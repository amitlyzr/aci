import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx
from fastapi import status
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from aci.common.db import crud
from aci.common.db.sql_models import Agent, AppConfiguration, Function, LinkedAccount
from aci.common.enums import SecurityScheme
from aci.common.schemas.function import FunctionExecute, FunctionExecutionResult
from aci.common.schemas.security_scheme import (
    OAuth2FlowType,
    OAuth2Scheme,
    OAuth2SchemeCredentials,
)
from aci.server import config
from aci.server.linked_account_events import LinkedAccountEventDeliveryError


@respx.mock
@pytest.mark.parametrize("use_custom_oauth2_app", [True, False])
def test_execute_oauth2_based_function_with_linked_account_credentials(
    db_session: Session,
    test_client: TestClient,
    dummy_agent_1_with_all_apps_allowed: Agent,
    dummy_function_aci_test__hello_world_with_args: Function,
    dummy_linked_account_oauth2_aci_test_project_1: LinkedAccount,
    use_custom_oauth2_app: bool,
) -> None:
    # update the linked account's credentials if use_custom_oauth2_app is True
    if use_custom_oauth2_app:
        dummy_linked_account_oauth2_aci_test_project_1.security_credentials["client_id"] = (
            "custom_client_id"
        )
        dummy_linked_account_oauth2_aci_test_project_1.security_credentials["client_secret"] = (
            "custom_client_secret"
        )
        crud.linked_accounts.update_linked_account_credentials(
            db_session,
            dummy_linked_account_oauth2_aci_test_project_1,
            security_credentials=OAuth2SchemeCredentials.model_validate(
                dummy_linked_account_oauth2_aci_test_project_1.security_credentials
            ),
        )
        db_session.commit()

    # Mock the HTTP endpoint and response
    mock_response_data = {
        "message": "Hello, test_execute_oauth2_based_function_with_linked_account_credentials!"
    }
    request = respx.post("https://api.mock.aci.com/v1/greet/John").mock(
        return_value=httpx.Response(
            200,
            json=mock_response_data,
        )
    )

    # execute the function
    function_execute = FunctionExecute(
        linked_account_owner_id=dummy_linked_account_oauth2_aci_test_project_1.linked_account_owner_id,
        function_input={
            "path": {"userId": "John"},
            "query": {"lang": "en"},
            "body": {"name": "John"},  # greeting is not visible so no input here
            "header": {"X-CUSTOM-HEADER": "header123"},
            # "cookie" property is not visible in our test schema so no input here
        },
    )
    response = test_client.post(
        f"{config.ROUTER_PREFIX_FUNCTIONS}/{dummy_function_aci_test__hello_world_with_args.name}/execute",
        json=function_execute.model_dump(mode="json"),
        headers={"x-api-key": dummy_agent_1_with_all_apps_allowed.api_keys[0].key},
    )

    # verify response is successful
    assert response.status_code == status.HTTP_200_OK
    assert "error" not in response.json()
    function_execution_response = FunctionExecutionResult.model_validate(response.json())
    assert function_execution_response.success
    assert function_execution_response.data == mock_response_data

    # Verify the request was made with correct inputs
    assert request.called
    assert request.calls.last.request.url == "https://api.mock.aci.com/v1/greet/John?lang=en"
    assert request.calls.last.request.headers["X-CUSTOM-HEADER"] == "header123"
    assert json.loads(request.calls.last.request.content) == json.loads(
        '{"name": "John","greeting": "default-greeting"}'
    )

    # verify request was made with the correct credentials
    # TODO: adding tests for scenarios where the access_token is placed in other location
    # (e.g., header, query, cookie). Might need to refactor the test cases and fixtures first to have a
    # more flexible and generic way of injecting different apps, functions, app_configurations, etc.
    app = dummy_function_aci_test__hello_world_with_args.app
    oauth2_scheme = OAuth2Scheme.model_validate(app.security_schemes[SecurityScheme.OAUTH2])
    linked_account_oauth2_credentials = OAuth2SchemeCredentials.model_validate(
        dummy_linked_account_oauth2_aci_test_project_1.security_credentials
    )
    assert (
        request.calls.last.request.headers["Authorization"]
        == f"{oauth2_scheme.prefix} {linked_account_oauth2_credentials.access_token}"
    )


@respx.mock
@pytest.mark.parametrize("use_custom_oauth2_app", [True, False])
def test_execute_oauth2_based_function_with_expired_linked_account_access_token(
    db_session: Session,
    test_client: TestClient,
    dummy_agent_1_with_all_apps_allowed: Agent,
    dummy_function_aci_test__hello_world_with_args: Function,
    dummy_linked_account_oauth2_aci_test_project_1: LinkedAccount,
    use_custom_oauth2_app: bool,
) -> None:
    # update the linked account's credentials if use_custom_oauth2_app is True
    if use_custom_oauth2_app:
        dummy_linked_account_oauth2_aci_test_project_1.security_credentials["client_id"] = (
            "custom_client_id"
        )
        dummy_linked_account_oauth2_aci_test_project_1.security_credentials["client_secret"] = (
            "custom_client_secret"
        )
        crud.linked_accounts.update_linked_account_credentials(
            db_session,
            dummy_linked_account_oauth2_aci_test_project_1,
            security_credentials=OAuth2SchemeCredentials.model_validate(
                dummy_linked_account_oauth2_aci_test_project_1.security_credentials
            ),
        )
        db_session.commit()

    # Mock the function's HTTP endpoint and response
    mock_response_data = {
        "message": "Hello, test_execute_oauth2_based_function_with_expired_linked_account_access_token!"
    }
    request = respx.post("https://api.mock.aci.com/v1/greet/John").mock(
        return_value=httpx.Response(
            200,
            json=mock_response_data,
        )
    )

    # mock the refresh token endpoint
    mock_refresh_token_response = {
        "access_token": "dummy_new_access_token",
        "expires_in": 3600,
    }
    respx.post("https://api.mock.aci.com/v1/oauth2/refresh").mock(
        return_value=httpx.Response(
            200,
            json=mock_refresh_token_response,
        )
    )

    # set the linked account's access token to expired
    linked_account_oauth2_credentials = OAuth2SchemeCredentials.model_validate(
        dummy_linked_account_oauth2_aci_test_project_1.security_credentials
    )
    old_access_token = linked_account_oauth2_credentials.access_token
    linked_account_oauth2_credentials.expires_at = 0
    crud.linked_accounts.update_linked_account_credentials(
        db_session,
        dummy_linked_account_oauth2_aci_test_project_1,
        security_credentials=linked_account_oauth2_credentials,
    )
    db_session.commit()

    # execute the function
    function_execute = FunctionExecute(
        linked_account_owner_id=dummy_linked_account_oauth2_aci_test_project_1.linked_account_owner_id,
        function_input={
            "path": {"userId": "John"},
            "query": {"lang": "en"},
            "body": {"name": "John"},  # greeting is not visible so no input here
            "header": {"X-CUSTOM-HEADER": "header123"},
            # "cookie" property is not visible in our test schema so no input here
        },
    )
    response = test_client.post(
        f"{config.ROUTER_PREFIX_FUNCTIONS}/{dummy_function_aci_test__hello_world_with_args.name}/execute",
        json=function_execute.model_dump(mode="json"),
        headers={"x-api-key": dummy_agent_1_with_all_apps_allowed.api_keys[0].key},
    )

    # verify response is successful
    assert response.status_code == status.HTTP_200_OK
    assert "error" not in response.json()
    function_execution_response = FunctionExecutionResult.model_validate(response.json())
    assert function_execution_response.success
    assert function_execution_response.data == mock_response_data

    # Verify the request was made with correct inputs
    assert request.called
    assert request.calls.last.request.url == "https://api.mock.aci.com/v1/greet/John?lang=en"
    assert request.calls.last.request.headers["X-CUSTOM-HEADER"] == "header123"
    assert json.loads(request.calls.last.request.content) == json.loads(
        '{"name": "John", "greeting": "default-greeting"}'
    )

    # verify request was made with the new access token
    app = dummy_function_aci_test__hello_world_with_args.app
    oauth2_scheme = OAuth2Scheme.model_validate(app.security_schemes[SecurityScheme.OAUTH2])
    assert (
        request.calls.last.request.headers["Authorization"]
        == f"{oauth2_scheme.prefix} {mock_refresh_token_response['access_token']}"
    )
    assert old_access_token != mock_refresh_token_response["access_token"]

    # verify the linked account's access token was updated
    db_session.refresh(dummy_linked_account_oauth2_aci_test_project_1)
    assert (
        dummy_linked_account_oauth2_aci_test_project_1.security_credentials["access_token"]
        == mock_refresh_token_response["access_token"]
    )


@respx.mock
def test_execute_oauth2_based_function_with_invalid_grant_disables_linked_account_and_notifies_once(
    db_session: Session,
    test_client: TestClient,
    dummy_agent_1_with_all_apps_allowed: Agent,
    dummy_function_aci_test__hello_world_with_args: Function,
    dummy_linked_account_oauth2_aci_test_project_1: LinkedAccount,
) -> None:
    """A terminal invalid_grant refresh failure emits exactly one expiry event,
    disables the linked account, and a subsequent call fails fast as disabled
    without another webhook delivery."""
    # expire the access token so a refresh is attempted
    linked_account_oauth2_credentials = OAuth2SchemeCredentials.model_validate(
        dummy_linked_account_oauth2_aci_test_project_1.security_credentials
    )
    linked_account_oauth2_credentials.expires_at = 0
    crud.linked_accounts.update_linked_account_credentials(
        db_session,
        dummy_linked_account_oauth2_aci_test_project_1,
        security_credentials=linked_account_oauth2_credentials,
    )
    db_session.commit()

    # provider rejects the refresh token as terminally invalid
    respx.post("https://api.mock.aci.com/v1/oauth2/refresh").mock(
        return_value=httpx.Response(400, json={"error": "invalid_grant"})
    )

    function_execute = FunctionExecute(
        linked_account_owner_id=dummy_linked_account_oauth2_aci_test_project_1.linked_account_owner_id,
        function_input={
            "path": {"userId": "John"},
            "query": {"lang": "en"},
            "body": {"name": "John"},
            "header": {"X-CUSTOM-HEADER": "header123"},
        },
    )

    with patch(
        "aci.server.security_credentials_manager.emit_linked_account_expired",
        new=AsyncMock(return_value=None),
    ) as mock_emit:
        response = test_client.post(
            f"{config.ROUTER_PREFIX_FUNCTIONS}/{dummy_function_aci_test__hello_world_with_args.name}/execute",
            json=function_execute.model_dump(mode="json"),
            headers={"x-api-key": dummy_agent_1_with_all_apps_allowed.api_keys[0].key},
        )

    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    mock_emit.assert_called_once()
    notified_error = mock_emit.call_args.args[2]
    assert notified_error.reason_code == "refresh_token_invalid"

    db_session.refresh(dummy_linked_account_oauth2_aci_test_project_1)
    assert dummy_linked_account_oauth2_aci_test_project_1.enabled is False

    # a second call must fail as disabled, and must not trigger another webhook
    with patch(
        "aci.server.security_credentials_manager.emit_linked_account_expired",
        new=AsyncMock(return_value=None),
    ) as mock_emit_second_call:
        second_response = test_client.post(
            f"{config.ROUTER_PREFIX_FUNCTIONS}/{dummy_function_aci_test__hello_world_with_args.name}/execute",
            json=function_execute.model_dump(mode="json"),
            headers={"x-api-key": dummy_agent_1_with_all_apps_allowed.api_keys[0].key},
        )
    assert second_response.status_code == status.HTTP_403_FORBIDDEN
    mock_emit_second_call.assert_not_called()


@respx.mock
def test_execute_oauth2_based_function_with_invalid_grant_and_delivery_failure_leaves_account_enabled(
    db_session: Session,
    test_client: TestClient,
    dummy_agent_1_with_all_apps_allowed: Agent,
    dummy_function_aci_test__hello_world_with_args: Function,
    dummy_linked_account_oauth2_aci_test_project_1: LinkedAccount,
) -> None:
    """When the expiry event cannot be delivered/acknowledged, the linked
    account must remain enabled so the next credential use retries."""
    linked_account_oauth2_credentials = OAuth2SchemeCredentials.model_validate(
        dummy_linked_account_oauth2_aci_test_project_1.security_credentials
    )
    linked_account_oauth2_credentials.expires_at = 0
    crud.linked_accounts.update_linked_account_credentials(
        db_session,
        dummy_linked_account_oauth2_aci_test_project_1,
        security_credentials=linked_account_oauth2_credentials,
    )
    db_session.commit()

    respx.post("https://api.mock.aci.com/v1/oauth2/refresh").mock(
        return_value=httpx.Response(400, json={"error": "invalid_grant"})
    )

    function_execute = FunctionExecute(
        linked_account_owner_id=dummy_linked_account_oauth2_aci_test_project_1.linked_account_owner_id,
        function_input={
            "path": {"userId": "John"},
            "query": {"lang": "en"},
            "body": {"name": "John"},
            "header": {"X-CUSTOM-HEADER": "header123"},
        },
    )

    with patch(
        "aci.server.security_credentials_manager.emit_linked_account_expired",
        new=AsyncMock(side_effect=LinkedAccountEventDeliveryError("webhook not configured")),
    ) as mock_emit:
        response = test_client.post(
            f"{config.ROUTER_PREFIX_FUNCTIONS}/{dummy_function_aci_test__hello_world_with_args.name}/execute",
            json=function_execute.model_dump(mode="json"),
            headers={"x-api-key": dummy_agent_1_with_all_apps_allowed.api_keys[0].key},
        )

    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    mock_emit.assert_called_once()

    db_session.refresh(dummy_linked_account_oauth2_aci_test_project_1)
    assert dummy_linked_account_oauth2_aci_test_project_1.enabled is True


@respx.mock
def test_execute_oauth2_based_function_with_generic_refresh_failure_does_not_emit_or_disable(
    db_session: Session,
    test_client: TestClient,
    dummy_agent_1_with_all_apps_allowed: Agent,
    dummy_function_aci_test__hello_world_with_args: Function,
    dummy_linked_account_oauth2_aci_test_project_1: LinkedAccount,
) -> None:
    """A provider 5xx during refresh is a generic, retryable OAuth2Error: it
    must not emit an expiry event or disable the linked account."""
    linked_account_oauth2_credentials = OAuth2SchemeCredentials.model_validate(
        dummy_linked_account_oauth2_aci_test_project_1.security_credentials
    )
    linked_account_oauth2_credentials.expires_at = 0
    crud.linked_accounts.update_linked_account_credentials(
        db_session,
        dummy_linked_account_oauth2_aci_test_project_1,
        security_credentials=linked_account_oauth2_credentials,
    )
    db_session.commit()

    respx.post("https://api.mock.aci.com/v1/oauth2/refresh").mock(
        return_value=httpx.Response(503, text="service unavailable")
    )

    function_execute = FunctionExecute(
        linked_account_owner_id=dummy_linked_account_oauth2_aci_test_project_1.linked_account_owner_id,
        function_input={
            "path": {"userId": "John"},
            "query": {"lang": "en"},
            "body": {"name": "John"},
            "header": {"X-CUSTOM-HEADER": "header123"},
        },
    )

    with patch(
        "aci.server.security_credentials_manager.emit_linked_account_expired",
        new=AsyncMock(return_value=None),
    ) as mock_emit:
        response = test_client.post(
            f"{config.ROUTER_PREFIX_FUNCTIONS}/{dummy_function_aci_test__hello_world_with_args.name}/execute",
            json=function_execute.model_dump(mode="json"),
            headers={"x-api-key": dummy_agent_1_with_all_apps_allowed.api_keys[0].key},
        )

    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    mock_emit.assert_not_called()

    db_session.refresh(dummy_linked_account_oauth2_aci_test_project_1)
    assert dummy_linked_account_oauth2_aci_test_project_1.enabled is True


@respx.mock
def test_execute_oauth2_based_function_with_client_credentials_failure_does_not_emit_or_disable(
    db_session: Session,
    test_client: TestClient,
    dummy_agent_1_with_all_apps_allowed: Agent,
    dummy_function_aci_test__hello_world_with_args: Function,
    dummy_app_configuration_oauth2_aci_test_project_1: AppConfiguration,
) -> None:
    """Client-credentials token re-fetch failures are operational, not a
    reauthentication signal: no linked account is user-authorized, so they
    must never emit an expiry event or disable anything."""
    client_credentials = OAuth2SchemeCredentials(
        client_id="dummy_client_credentials_client_id",
        client_secret="dummy_client_credentials_client_secret",
        scope="dummy_scope",
        access_token="dummy_client_credentials_access_token",
        token_type="Bearer",
        expires_at=0,  # force a refresh on every use
        oauth2_flow_type=OAuth2FlowType.CLIENT_CREDENTIALS,
        token_url="https://api.mock.aci.com/v1/oauth2/token",
    )
    linked_account = crud.linked_accounts.create_linked_account(
        db_session,
        dummy_app_configuration_oauth2_aci_test_project_1.project_id,
        dummy_app_configuration_oauth2_aci_test_project_1.app_name,
        "dummy_linked_account_client_credentials_aci_test_project_1",
        dummy_app_configuration_oauth2_aci_test_project_1.security_scheme,
        client_credentials,
        enabled=True,
    )
    db_session.commit()

    respx.post("https://api.mock.aci.com/v1/oauth2/token").mock(
        return_value=httpx.Response(503, text="service unavailable")
    )

    function_execute = FunctionExecute(
        linked_account_owner_id=linked_account.linked_account_owner_id,
        function_input={
            "path": {"userId": "John"},
            "query": {"lang": "en"},
            "body": {"name": "John"},
            "header": {"X-CUSTOM-HEADER": "header123"},
        },
    )

    with patch(
        "aci.server.security_credentials_manager.emit_linked_account_expired",
        new=AsyncMock(return_value=None),
    ) as mock_emit:
        response = test_client.post(
            f"{config.ROUTER_PREFIX_FUNCTIONS}/{dummy_function_aci_test__hello_world_with_args.name}/execute",
            json=function_execute.model_dump(mode="json"),
            headers={"x-api-key": dummy_agent_1_with_all_apps_allowed.api_keys[0].key},
        )

    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    mock_emit.assert_not_called()

    db_session.refresh(linked_account)
    assert linked_account.enabled is True
