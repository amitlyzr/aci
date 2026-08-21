from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from aci.common.db import crud
from aci.common.db.sql_models import App
from aci.common.enums import SecurityScheme
from aci.server import config


def _make_app_owned_by_api_key(db_session: Session, app: App, api_key: str) -> App:
    """Tie an existing (system) app to the given API key so it shows up as a
    "custom app" for that key, without going through the upsert-app file-path
    flow (which needs real app.json fixtures on disk)."""
    owner_api_key = crud.projects.get_api_key(db_session, api_key)
    assert owner_api_key is not None
    app.api_key_id = owner_api_key.id
    db_session.commit()
    db_session.refresh(app)
    return app


def test_list_my_custom_apps_redacts_oauth2_client_secret_without_admin_key(
    test_client: TestClient,
    dummy_api_key_1: str,
    dummy_app_google: App,
    db_session: Session,
) -> None:
    """ACI-11: my-custom-apps must not leak the raw, DB-decrypted OAuth2
    client_id/client_secret to a caller without the static admin key."""
    _make_app_owned_by_api_key(db_session, dummy_app_google, dummy_api_key_1)

    response = test_client.get(
        f"{config.ROUTER_PREFIX_TOOL_SEEDING}/my-custom-apps",
        headers={"x-api-key": dummy_api_key_1},
    )
    assert response.status_code == status.HTTP_200_OK

    apps = {app["name"]: app for app in response.json()}
    assert dummy_app_google.name in apps
    security_schemes = apps[dummy_app_google.name]["security_schemes"]
    assert "client_id" not in security_schemes["oauth2"]
    assert "client_secret" not in security_schemes["oauth2"]
    assert security_schemes["oauth2"]["scope"] == dummy_app_google.security_schemes[
        SecurityScheme.OAUTH2
    ]["scope"], "non-secret scheme fields should still be visible"


def test_list_my_custom_apps_returns_oauth2_client_secret_with_admin_key(
    test_client: TestClient,
    dummy_api_key_1: str,
    dummy_app_google: App,
    db_session: Session,
) -> None:
    """A caller holding the static admin key still gets the raw security_schemes
    (e.g. lyzr-agent/data-query, which need the real client credentials)."""
    assert config.STATIC_ADMIN_KEY, "test env must set SERVER_STATIC_ADMIN_KEY"
    _make_app_owned_by_api_key(db_session, dummy_app_google, dummy_api_key_1)

    response = test_client.get(
        f"{config.ROUTER_PREFIX_TOOL_SEEDING}/my-custom-apps",
        headers={
            "x-api-key": dummy_api_key_1,
            "Authorization": f"Bearer {config.STATIC_ADMIN_KEY}",
        },
    )
    assert response.status_code == status.HTTP_200_OK

    apps = {app["name"]: app for app in response.json()}
    security_schemes = apps[dummy_app_google.name]["security_schemes"]
    assert (
        security_schemes["oauth2"]["client_id"]
        == dummy_app_google.security_schemes[SecurityScheme.OAUTH2]["client_id"]
    )
    assert (
        security_schemes["oauth2"]["client_secret"]
        == dummy_app_google.security_schemes[SecurityScheme.OAUTH2]["client_secret"]
    )
