import time
from unittest.mock import patch

from fastapi import status
from fastapi.testclient import TestClient

from aci.common.db.sql_models import LinkedAccount
from aci.common.schemas.linked_accounts import LinkedAccountWithFullCredentials
from aci.server import config, security_credentials_manager

NON_EXISTENT_LINKED_ACCOUNT_ID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"


def test_get_linked_account_full_credentials(
    test_client: TestClient,
    dummy_api_key_1: str,
    dummy_api_key_2: str,
    dummy_linked_account_oauth2_google_project_1: LinkedAccount,
    dummy_linked_account_oauth2_google_project_2: LinkedAccount,
) -> None:
    ENDPOINT_1 = (
        f"{config.ROUTER_PREFIX_LINKED_ACCOUNTS}"
        f"/{dummy_linked_account_oauth2_google_project_1.id}/credentials"
    )
    ENDPOINT_2 = (
        f"{config.ROUTER_PREFIX_LINKED_ACCOUNTS}"
        f"/{dummy_linked_account_oauth2_google_project_2.id}/credentials"
    )

    response = test_client.get(ENDPOINT_1, headers={"x-api-key": dummy_api_key_1})
    assert response.status_code == status.HTTP_200_OK, response.json()
    assert (
        LinkedAccountWithFullCredentials.model_validate(response.json()).id
        == dummy_linked_account_oauth2_google_project_1.id
    )

    response = test_client.get(ENDPOINT_2, headers={"x-api-key": dummy_api_key_2})
    assert response.status_code == status.HTTP_200_OK, response.json()
    assert (
        LinkedAccountWithFullCredentials.model_validate(response.json()).id
        == dummy_linked_account_oauth2_google_project_2.id
    )


def test_get_linked_account_full_credentials_not_found(
    test_client: TestClient,
    dummy_api_key_1: str,
) -> None:
    ENDPOINT = (
        f"{config.ROUTER_PREFIX_LINKED_ACCOUNTS}/{NON_EXISTENT_LINKED_ACCOUNT_ID}/credentials"
    )

    response = test_client.get(ENDPOINT, headers={"x-api-key": dummy_api_key_1})
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_get_linked_account_full_credentials_not_belong_to_project(
    test_client: TestClient,
    dummy_api_key_1: str,
    dummy_linked_account_oauth2_google_project_1: LinkedAccount,
    dummy_linked_account_oauth2_google_project_2: LinkedAccount,
) -> None:
    ENDPOINT = (
        f"{config.ROUTER_PREFIX_LINKED_ACCOUNTS}"
        f"/{dummy_linked_account_oauth2_google_project_2.id}/credentials"
    )

    response = test_client.get(ENDPOINT, headers={"x-api-key": dummy_api_key_1})
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_get_linked_account_full_credentials_with_api_key_credentials(
    test_client: TestClient,
    dummy_api_key_1: str,
    dummy_linked_account_api_key_github_project_1: LinkedAccount,
) -> None:
    """Unlike GET /{id}, this endpoint must expose the raw api_key secret."""
    ENDPOINT = (
        f"{config.ROUTER_PREFIX_LINKED_ACCOUNTS}"
        f"/{dummy_linked_account_api_key_github_project_1.id}/credentials"
    )

    response = test_client.get(ENDPOINT, headers={"x-api-key": dummy_api_key_1})
    assert response.status_code == status.HTTP_200_OK

    linked_account = response.json()
    security_credentials = linked_account["security_credentials"]
    assert security_credentials["secret_key"], "api_key secret_key should be exposed here"


def test_get_linked_account_full_credentials_with_oauth2_credentials(
    test_client: TestClient,
    dummy_api_key_1: str,
    dummy_linked_account_oauth2_google_project_1: LinkedAccount,
) -> None:
    ENDPOINT = (
        f"{config.ROUTER_PREFIX_LINKED_ACCOUNTS}"
        f"/{dummy_linked_account_oauth2_google_project_1.id}/credentials"
    )

    response = test_client.get(ENDPOINT, headers={"x-api-key": dummy_api_key_1})
    assert response.status_code == status.HTTP_200_OK

    linked_account = response.json()
    security_credentials: dict[str, str] = linked_account["security_credentials"]
    assert security_credentials["access_token"], "OAuth2 credentials should contain access_token"
    assert security_credentials["expires_at"], "OAuth2 credentials should contain expires_at"
    assert security_credentials["refresh_token"], "OAuth2 credentials should contain refresh_token"


def test_get_linked_account_full_credentials_redacts_client_secret_without_admin_key(
    test_client: TestClient,
    dummy_api_key_1: str,
    dummy_linked_account_oauth2_google_project_1: LinkedAccount,
) -> None:
    """ACI-10: without the static admin key, client_id/client_secret must be
    redacted even on the full-credentials route, since they freeze whichever
    OAuth2 client (including ACI's shared platform apps) was used at link time."""
    ENDPOINT = (
        f"{config.ROUTER_PREFIX_LINKED_ACCOUNTS}"
        f"/{dummy_linked_account_oauth2_google_project_1.id}/credentials"
    )

    response = test_client.get(ENDPOINT, headers={"x-api-key": dummy_api_key_1})
    assert response.status_code == status.HTTP_200_OK

    security_credentials = response.json()["security_credentials"]
    assert security_credentials["client_id"] == "REDACTED"
    assert security_credentials["client_secret"] == "REDACTED"
    assert security_credentials["access_token"], "OAuth2 credentials should still contain access_token"


def test_get_linked_account_full_credentials_returns_client_secret_with_admin_key(
    test_client: TestClient,
    dummy_api_key_1: str,
    dummy_linked_account_oauth2_google_project_1: LinkedAccount,
) -> None:
    """A caller holding the static admin key still gets the real OAuth2 client
    credentials (e.g. lyzr-agent/data-query, which need them to mint tokens)."""
    assert config.STATIC_ADMIN_KEY, "test env must set SERVER_STATIC_ADMIN_KEY"
    ENDPOINT = (
        f"{config.ROUTER_PREFIX_LINKED_ACCOUNTS}"
        f"/{dummy_linked_account_oauth2_google_project_1.id}/credentials"
    )

    response = test_client.get(
        ENDPOINT,
        headers={
            "x-api-key": dummy_api_key_1,
            "Authorization": f"Bearer {config.STATIC_ADMIN_KEY}",
        },
    )
    assert response.status_code == status.HTTP_200_OK

    security_credentials = response.json()["security_credentials"]
    assert security_credentials["client_id"] == "dummy_linked_account_oauth2_credentials_client_id"
    assert (
        security_credentials["client_secret"]
        == "dummy_linked_account_oauth2_credentials_client_secret"
    )


def test_get_linked_account_full_credentials_with_expired_oauth2_credentials(
    test_client: TestClient,
    dummy_api_key_1: str,
    dummy_linked_account_oauth2_google_project_1: LinkedAccount,
) -> None:
    """Confirm the shared refresh helper still refreshes expired oauth2 tokens on this route."""
    ENDPOINT = (
        f"{config.ROUTER_PREFIX_LINKED_ACCOUNTS}"
        f"/{dummy_linked_account_oauth2_google_project_1.id}/credentials"
    )

    mock_refresh_response: dict[str, str | int] = {
        "access_token": "new_mock_access_token",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "new_mock_refresh_token",
    }

    mock_current_time = int(time.time()) + 7200  # 2 hours in the future

    with (
        patch.object(
            security_credentials_manager,
            "_refresh_oauth2_access_token",
            return_value=mock_refresh_response,
        ) as mock_refresh,
        patch("time.time", return_value=mock_current_time),
    ):
        response = test_client.get(ENDPOINT, headers={"x-api-key": dummy_api_key_1})
        assert response.status_code == status.HTTP_200_OK

        linked_account = response.json()
        security_credentials: dict[str, str] = linked_account["security_credentials"]
        assert security_credentials["access_token"] == mock_refresh_response["access_token"]
        assert int(security_credentials["expires_at"]) == (
            mock_current_time + int(mock_refresh_response["expires_in"])
        )
        assert security_credentials["refresh_token"] == mock_refresh_response["refresh_token"]
        mock_refresh.assert_called_once()
