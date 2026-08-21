from typing import Annotated
from uuid import UUID

from authlib.jose import jwt
from fastapi import APIRouter, Body, Depends, Query, Request, status
from sqlalchemy.orm import Session
from starlette.responses import RedirectResponse

from aci.common.db import crud
from aci.common.db.sql_models import LinkedAccount
from aci.common.enums import SecurityScheme
from aci.common.exceptions import (
    AppConfigurationNotFound,
    AppNotFound,
    AuthenticationError,
    LinkedAccountAlreadyExists,
    LinkedAccountNotFound,
    NoImplementationFound,
    OAuth2Error,
    ProjectNotFound,
)
from aci.common.logging_setup import get_logger
from aci.common.schemas.linked_accounts import (
    LinkedAccountAPIKeyCreate,
    LinkedAccountAPIKeyCreateByAppId,
    LinkedAccountDefaultCreate,
    LinkedAccountNoAuthCreate,
    LinkedAccountNoAuthCreateByAppId,
    LinkedAccountOAuth2ClientCredentialsCreate,
    LinkedAccountOAuth2Create,
    LinkedAccountOAuth2CreateByAppId,
    LinkedAccountOAuth2CreateState,
    LinkedAccountPublic,
    LinkedAccountsList,
    LinkedAccountUpdate,
    LinkedAccountWithCredentials,
    LinkedAccountWithFullCredentials,
)
from aci.common.schemas.security_scheme import (
    APIKeySchemeCredentials,
    NoAuthSchemeCredentials,
    OAuth2FlowType,
    OAuth2SchemeCredentials,
)
from aci.server import acl, config, quota_manager
from aci.server import dependencies as deps
from aci.server import security_credentials_manager as scm
from aci.server.oauth2_manager import OAuth2Manager

router = APIRouter()
logger = get_logger(__name__)

LINKED_ACCOUNTS_OAUTH2_CALLBACK_ROUTE_NAME = "linked_accounts_oauth2_callback"

"""
IMPORTANT NOTE:
The api endpoints (both URL design and implementation) for linked accounts are currently a bit hacky, especially for OAuth2 account type.
Will revisit and potentially refactor later once we have more time and more clarity on the requirements.
There are a few tricky parts:
- There are different types of linked accounts (OAuth2, API key, etc.) And the OAuth2 type linking flow
  is very different from the other types.
- For OAuth2 account linking, we want to support quite a few scenarios that might require different
  flows or setups. But for simplicity, we currently hack together an implementation that works for all,
  with some compromises on the security. (well, I'd say it's still secure enough for this stage but need to
  revisit and improve later.). These OAuth2 scenarios include:
  - Scenario 1: allow (our direct) client to link an OAuth2 account on developer portal.
  - Scenario 2: allow (client's) end user to link an OAuth2 account with the redirect url.
    - Scenario 2.1: Client generates the redirect url and sends it to the end user.
    - Scenario 2.2: Amid end user's conversation with the client's AI agent, the AI agent generates the
      redirect url for OAuth2 account linking. (If the App the end user needs access too is not yet authenticated)
  - Scenario 3: allow (our direct) client to generate a link to a webpage that we host for OAuth2 account linking.
    Different from Scenario 2.1, the link is not a redirect url but a link to a webpage that we host. And potentially
    can work for other types of accounting linking, e.g., allowend user to input API key.

- Also see: https://www.notion.so/Replace-authlib-to-support-both-browser-and-cli-authentication-16f8378d6a4780eda593ef149a205198
"""


@router.post("/default", response_model=LinkedAccountPublic, include_in_schema=False)
async def link_account_with_aci_default_credentials(
    context: Annotated[deps.RequestContext, Depends(deps.get_request_context)],
    body: Annotated[LinkedAccountDefaultCreate, Body()],
) -> LinkedAccount:
    """
    Create a linked account under an App using default credentials (e.g., API key, OAuth2, etc.)
    provided by ACI.
    If there is no default credentials provided by ACI for the specific App, the linked account will not be created,
    and an error will be returned.
    """
    logger.info(
        f"Linking account with ACI default credentials, "
        f"app_name={body.app_name}, "
        f"linked_account_owner_id={body.linked_account_owner_id}"
    )
    # TODO: some duplicate code with other linked account creation routes
    app_configuration = crud.app_configurations.get_app_configuration(
        context.db_session, context.project.id, body.app_name
    )
    if not app_configuration:
        logger.error(
            f"Failed to link account with ACI default credentials, app configuration not found, "
            f"app_name={body.app_name}"
        )
        raise AppConfigurationNotFound(
            f"configuration for app={body.app_name} not found, please configure the app first {config.DEV_PORTAL_URL}/apps/{body.app_name}"
        )

    # need to make sure the App actully has default credentials provided by ACI
    app_default_credentials = app_configuration.app.default_security_credentials_by_scheme.get(
        app_configuration.security_scheme
    )
    if not app_default_credentials:
        logger.error(
            f"Failed to link account with ACI default credentials, no default credentials provided by ACI, "
            f"app_name={body.app_name} "
            f"security_scheme={app_configuration.security_scheme}"
        )
        # TODO: consider choosing a different exception type?
        raise NoImplementationFound(
            f"No default credentials provided by ACI for app={body.app_name}, "
            f"security_scheme={app_configuration.security_scheme}"
        )

    linked_account = crud.linked_accounts.get_linked_account(
        context.db_session,
        context.project.id,
        body.app_name,
        body.linked_account_owner_id,
    )
    # TODO: same as OAuth2 linked account creation, we might want to separate the logic for updating and creating a linked account
    # or give warning to clients if the linked account already exists to avoid accidental overwriting the account
    if linked_account:
        # TODO: support updating any type of linked account to use ACI default credentials
        logger.error(
            f"Failed to link account with ACI default credentials, linked account already exists, "
            f"linked_account_owner_id={body.linked_account_owner_id} "
            f"app_name={body.app_name}"
        )
        raise LinkedAccountAlreadyExists(
            f"linked account with linked_account_owner_id={body.linked_account_owner_id} already exists for app={body.app_name}"
        )
    else:
        # Enforce linked accounts quota before creating new account
        quota_manager.enforce_linked_accounts_creation_quota(
            context.db_session, context.project.org_id, body.linked_account_owner_id
        )

        logger.info(
            f"Creating linked account with ACI default credentials, "
            f"linked_account_owner_id={body.linked_account_owner_id}, "
            f"app_name={body.app_name}"
        )
        linked_account = crud.linked_accounts.create_linked_account(
            context.db_session,
            context.project.id,
            body.app_name,
            body.linked_account_owner_id,
            app_configuration.security_scheme,
            enabled=True,
            api_key_id=context.api_key_id,
        )
    context.db_session.commit()

    return linked_account


@router.post("/no-auth", response_model=LinkedAccountPublic)
async def link_account_with_no_auth(
    context: Annotated[deps.RequestContext, Depends(deps.get_request_context)],
    body: LinkedAccountNoAuthCreate,
) -> LinkedAccount:
    """
    Create a linked account under an App that requires no authentication.
    """
    logger.info(
        f"Linking no_auth account, app_name={body.app_name}, "
        f"linked_account_owner_id={body.linked_account_owner_id}"
    )
    # TODO: duplicate code with other linked account creation routes, refactor later
    app_configuration = crud.app_configurations.get_app_configuration(
        context.db_session, context.project.id, body.app_name, context.api_key_id
    )
    if not app_configuration:
        logger.error(
            f"Failed to link no_auth account, app configuration not found, app_name={body.app_name}"
        )
        raise AppConfigurationNotFound(
            f"configuration for app={body.app_name} not found, please configure the app first {config.DEV_PORTAL_URL}/apps/{body.app_name}"
        )
    if app_configuration.security_scheme != SecurityScheme.NO_AUTH:
        logger.error(
            f"Failed to link no_auth account, app configuration security scheme is not no_auth, "
            f"app_name={body.app_name} security_scheme={app_configuration.security_scheme}"
        )
        raise NoImplementationFound(
            f"the security_scheme configured for app={body.app_name} is "
            f"{app_configuration.security_scheme}, not no_auth"
        )
    linked_account = crud.linked_accounts.get_linked_account(
        context.db_session,
        context.project.id,
        body.app_name,
        body.linked_account_owner_id,
    )
    if linked_account:
        logger.error(
            f"Failed to link no_auth account, linked account already exists, "
            f"linked_account_owner_id={body.linked_account_owner_id} app_name={body.app_name}"
        )
        raise LinkedAccountAlreadyExists(
            f"linked account with linked_account_owner_id={body.linked_account_owner_id} already exists for app={body.app_name}"
        )
    else:
        # Enforce linked accounts quota before creating new account
        quota_manager.enforce_linked_accounts_creation_quota(
            context.db_session, context.project.org_id, body.linked_account_owner_id
        )

        logger.info(
            f"Creating no_auth linked account, "
            f"linked_account_owner_id={body.linked_account_owner_id}, "
            f"app_name={body.app_name}"
        )
        linked_account = crud.linked_accounts.create_linked_account(
            context.db_session,
            context.project.id,
            body.app_name,
            body.linked_account_owner_id,
            SecurityScheme.NO_AUTH,
            NoAuthSchemeCredentials(),
            enabled=True,
            api_key_id=context.api_key_id,
        )

    context.db_session.commit()

    return linked_account


@router.post("/api-key", response_model=LinkedAccountPublic)
async def link_account_with_api_key(
    context: Annotated[deps.RequestContext, Depends(deps.get_request_context)],
    body: LinkedAccountAPIKeyCreate,
) -> LinkedAccount:
    """
    Create a linked account under an API key based App.
    """
    logger.info(
        f"Linking api_key account, app_name={body.app_name}, "
        f"linked_account_owner_id={body.linked_account_owner_id}"
    )
    app_configuration = crud.app_configurations.get_app_configuration(
        context.db_session, context.project.id, body.app_name
    )
    if not app_configuration:
        logger.error(
            f"Failed to link api_key account, app configuration not found, app_name={body.app_name}"
        )
        raise AppConfigurationNotFound(
            f"configuration for app={body.app_name} not found, please configure the app first {config.DEV_PORTAL_URL}/apps/{body.app_name}"
        )
    # TODO: for now we require the security_schema used for accounts under an App must be the same as the security_schema configured in the app
    # configuration. But in the future, we might lift this restriction and allow any security_schema as long as the App supports it.
    if app_configuration.security_scheme != SecurityScheme.API_KEY:
        logger.error(
            f"Failed to link api_key account, app configuration security scheme is, "
            f"{app_configuration.security_scheme} instead of api_key "
            f"app_name={body.app_name} security_scheme={app_configuration.security_scheme}"
        )
        # TODO: consider choosing a different exception type?
        raise NoImplementationFound(
            f"the security_scheme configured for app={body.app_name} is "
            f"{app_configuration.security_scheme}, not api_key"
        )
    linked_account = crud.linked_accounts.get_linked_account(
        context.db_session,
        context.project.id,
        body.app_name,
        body.linked_account_owner_id,
    )
    security_credentials = APIKeySchemeCredentials(
        secret_key=body.api_key,
    )
    # TODO: same as other linked account creation, we might want to separate the logic for updating and creating a linked account
    # or give warning to clients if the linked account already exists to avoid accidental overwriting the account
    if linked_account:
        # TODO: support updating api_key linked account
        logger.error(
            f"Failed to link api_key account, linked account already exists, "
            f"linked_account_owner_id={body.linked_account_owner_id} app_name={body.app_name}"
        )
        raise LinkedAccountAlreadyExists(
            f"linked account with linked_account_owner_id={body.linked_account_owner_id} already exists for app={body.app_name}"
        )
    else:
        # Enforce linked accounts quota before creating new account
        quota_manager.enforce_linked_accounts_creation_quota(
            context.db_session, context.project.org_id, body.linked_account_owner_id
        )

        logger.info(
            f"Creating api_key linked account, "
            f"linked_account_owner_id={body.linked_account_owner_id}, "
            f"app_name={body.app_name}"
        )
        linked_account = crud.linked_accounts.create_linked_account(
            context.db_session,
            context.project.id,
            body.app_name,
            body.linked_account_owner_id,
            SecurityScheme.API_KEY,
            security_credentials,
            enabled=True,
            api_key_id=context.api_key_id,
        )

    context.db_session.commit()

    return linked_account


@router.post("/by-app-id/no-auth", response_model=LinkedAccountPublic)
async def link_account_with_no_auth_by_app_id(
    context: Annotated[deps.RequestContext, Depends(deps.get_request_context)],
    body: LinkedAccountNoAuthCreateByAppId,
) -> LinkedAccount:
    """
    Create a linked account under an App that requires no authentication, using app_id.
    """
    logger.info(
        f"Linking no_auth account by app_id, app_id={body.app_id}, "
        f"linked_account_owner_id={body.linked_account_owner_id}"
    )
    app_configuration = crud.app_configurations.get_app_configuration_by_app_id(
        context.db_session, context.project.id, body.app_id
    )
    if not app_configuration:
        logger.error(
            f"Failed to link no_auth account, app configuration not found, app_id={body.app_id}"
        )
        raise AppConfigurationNotFound(
            f"configuration for app_id={body.app_id} not found, please configure the app first"
        )
    if app_configuration.security_scheme != SecurityScheme.NO_AUTH:
        logger.error(
            f"Failed to link no_auth account, app configuration security scheme is not no_auth, "
            f"app_id={body.app_id} security_scheme={app_configuration.security_scheme}"
        )
        raise NoImplementationFound(
            f"the security_scheme configured for app_id={body.app_id} is "
            f"{app_configuration.security_scheme}, not no_auth"
        )
    linked_account = crud.linked_accounts.get_linked_account_by_app_id(
        context.db_session,
        context.project.id,
        body.app_id,
        body.linked_account_owner_id,
    )
    if linked_account:
        logger.error(
            f"Failed to link no_auth account, linked account already exists, "
            f"linked_account_owner_id={body.linked_account_owner_id} app_id={body.app_id}"
        )
        raise LinkedAccountAlreadyExists(
            f"linked account with linked_account_owner_id={body.linked_account_owner_id} already exists for app_id={body.app_id}"
        )
    else:
        # Enforce linked accounts quota before creating new account
        quota_manager.enforce_linked_accounts_creation_quota(
            context.db_session, context.project.org_id, body.linked_account_owner_id
        )

        logger.info(
            f"Creating no_auth linked account, "
            f"linked_account_owner_id={body.linked_account_owner_id}, "
            f"app_id={body.app_id}"
        )
        linked_account = crud.linked_accounts.create_linked_account_by_app_id(
            context.db_session,
            context.project.id,
            body.app_id,
            body.linked_account_owner_id,
            SecurityScheme.NO_AUTH,
            NoAuthSchemeCredentials(),
            enabled=True,
        )

    context.db_session.commit()

    return linked_account


@router.post("/by-app-id/api-key", response_model=LinkedAccountPublic)
async def link_account_with_api_key_by_app_id(
    context: Annotated[deps.RequestContext, Depends(deps.get_request_context)],
    body: LinkedAccountAPIKeyCreateByAppId,
) -> LinkedAccount:
    """
    Create a linked account under an API key based App, using app_id.
    """
    logger.info(
        f"Linking api_key account by app_id, app_id={body.app_id}, "
        f"linked_account_owner_id={body.linked_account_owner_id}"
    )
    app_configuration = crud.app_configurations.get_app_configuration_by_app_id(
        context.db_session, context.project.id, body.app_id
    )
    if not app_configuration:
        logger.error(
            f"Failed to link api_key account, app configuration not found, app_id={body.app_id}"
        )
        raise AppConfigurationNotFound(
            f"configuration for app_id={body.app_id} not found, please configure the app first"
        )
    if app_configuration.security_scheme != SecurityScheme.API_KEY:
        logger.error(
            f"Failed to link api_key account, app configuration security scheme is, "
            f"{app_configuration.security_scheme} instead of api_key "
            f"app_id={body.app_id} security_scheme={app_configuration.security_scheme}"
        )
        raise NoImplementationFound(
            f"the security_scheme configured for app_id={body.app_id} is "
            f"{app_configuration.security_scheme}, not api_key"
        )
    linked_account = crud.linked_accounts.get_linked_account_by_app_id(
        context.db_session,
        context.project.id,
        body.app_id,
        body.linked_account_owner_id,
    )
    security_credentials = APIKeySchemeCredentials(
        secret_key=body.api_key,
    )
    if linked_account:
        logger.error(
            f"Failed to link api_key account, linked account already exists, "
            f"linked_account_owner_id={body.linked_account_owner_id} app_id={body.app_id}"
        )
        raise LinkedAccountAlreadyExists(
            f"linked account with linked_account_owner_id={body.linked_account_owner_id} already exists for app_id={body.app_id}"
        )
    else:
        # Enforce linked accounts quota before creating new account
        quota_manager.enforce_linked_accounts_creation_quota(
            context.db_session, context.project.org_id, body.linked_account_owner_id
        )

        logger.info(
            f"Creating api_key linked account, "
            f"linked_account_owner_id={body.linked_account_owner_id}, "
            f"app_id={body.app_id}"
        )
        linked_account = crud.linked_accounts.create_linked_account_by_app_id(
            context.db_session,
            context.project.id,
            body.app_id,
            body.linked_account_owner_id,
            SecurityScheme.API_KEY,
            security_credentials,
            enabled=True,
        )

    context.db_session.commit()

    return linked_account


@router.get("/by-app-id/oauth2")
async def link_oauth2_account_by_app_id(
    request: Request,
    context: Annotated[deps.RequestContext, Depends(deps.get_request_context)],
    query_params: Annotated[LinkedAccountOAuth2CreateByAppId, Query()],
) -> dict:
    """
    Start an OAuth2 account linking process using app_id.
    It will return a redirect url (as a string, instead of RedirectResponse) to the OAuth2 provider's authorization endpoint.
    """
    app_configuration = crud.app_configurations.get_app_configuration_by_app_id(
        context.db_session, context.project.id, query_params.app_id
    )
    if not app_configuration:
        logger.error(
            f"Failed to link OAuth2 account, app configuration not found, "
            f"app_id={query_params.app_id}"
        )
        raise AppConfigurationNotFound(
            f"configuration for app_id={query_params.app_id} not found, please configure the app first"
        )
    if app_configuration.security_scheme != SecurityScheme.OAUTH2:
        logger.error(
            f"Failed to link OAuth2 account, app configuration security scheme is not OAuth2, "
            f"app_id={query_params.app_id} security_scheme={app_configuration.security_scheme}"
        )
        raise NoImplementationFound(
            f"The security_scheme configured for app_id={query_params.app_id} is "
            f"{app_configuration.security_scheme}, not OAuth2"
        )

    # Enforce linked accounts quota before creating new account
    quota_manager.enforce_linked_accounts_creation_quota(
        context.db_session, context.project.org_id, query_params.linked_account_owner_id
    )

    oauth2_scheme = scm.get_app_configuration_oauth2_scheme(
        app_configuration.app, app_configuration
    )

    oauth2_manager = OAuth2Manager(
        app_name=app_configuration.app.name,
        client_id=oauth2_scheme.client_id,
        client_secret=oauth2_scheme.client_secret,
        scope=oauth2_scheme.scope,
        authorize_url=oauth2_scheme.authorize_url,
        access_token_url=oauth2_scheme.access_token_url,
        refresh_token_url=oauth2_scheme.refresh_token_url,
        token_endpoint_auth_method=oauth2_scheme.token_endpoint_auth_method,
        pkce_enabled=oauth2_scheme.pkce_enabled,
        scope_in_token_exchange=oauth2_scheme.scope_in_token_exchange,
        redirect_uri_in_token_exchange=oauth2_scheme.redirect_uri_in_token_exchange,
    )

    # create and encode the state payload.
    # NOTE: the state payload is jwt encoded (signed), but it's not encrypted, anyone can decode it
    # TODO: add expiration check to the state payload for extra security
    oauth2_state = LinkedAccountOAuth2CreateState(
        app_name=app_configuration.app.name,
        project_id=context.project.id,
        linked_account_owner_id=query_params.linked_account_owner_id,
        client_id=oauth2_scheme.client_id,
        code_verifier=OAuth2Manager.generate_code_verifier(),
        after_oauth2_link_redirect_url=query_params.after_oauth2_link_redirect_url,
        app_id=query_params.app_id,  # Include app_id for by-app-id flow
    )

    oauth2_state_jwt = jwt.encode(
        {"alg": config.JWT_ALGORITHM},
        oauth2_state.model_dump(mode="json", exclude_none=True),
        config.SIGNING_KEY,
    ).decode()  # decode() is needed to convert the bytes to a string (not decoding the jwt payload) for this jwt library.

    path = request.url_for(LINKED_ACCOUNTS_OAUTH2_CALLBACK_ROUTE_NAME).path
    redirect_uri = oauth2_scheme.redirect_url or f"{config.REDIRECT_URI_BASE}{path}"
    authorization_url = await oauth2_manager.create_authorization_url(
        redirect_uri=redirect_uri,
        state=oauth2_state_jwt,
        code_verifier=oauth2_state.code_verifier,
        prompt=oauth2_scheme.prompt or "consent",
    )

    # rewrite the authorization url for some apps that need special handling
    # TODO: this is hacky and need to refactor this in the future
    authorization_url = OAuth2Manager.rewrite_oauth2_authorization_url(
        app_configuration.app.name, authorization_url
    )

    logger.info(f"Linking oauth2 account by app_id with authorization_url={authorization_url}")
    return {"url": authorization_url}


@router.get("/oauth2")
async def link_oauth2_account(
    request: Request,
    context: Annotated[deps.RequestContext, Depends(deps.get_request_context)],
    query_params: Annotated[LinkedAccountOAuth2Create, Query()],
) -> dict:
    """
    Start an OAuth2 account linking process.
    It will return a redirect url (as a string, instead of RedirectResponse) to the OAuth2 provider's authorization endpoint.
    """
    app_configuration = crud.app_configurations.get_app_configuration(
        context.db_session, context.project.id, query_params.app_name
    )
    if not app_configuration:
        logger.error(
            f"Failed to link OAuth2 account, app configuration not found, "
            f"app_name={query_params.app_name}"
        )
        raise AppConfigurationNotFound(
            f"configuration for app={query_params.app_name} not found, please configure the app first {config.DEV_PORTAL_URL}/apps/{query_params.app_name}"
        )
    # TODO: for now we require the security_schema used for accounts under an App must be the same as the security_schema configured in the app
    # configuration. But in the future, we might lift this restriction and allow any security_schema as long the App supports it.
    if app_configuration.security_scheme != SecurityScheme.OAUTH2:
        logger.error(
            f"Failed to link OAuth2 account, app configuration security scheme is not OAuth2, "
            f"app_name={query_params.app_name} security_scheme={app_configuration.security_scheme}"
        )
        raise NoImplementationFound(
            f"The security_scheme configured in app={query_params.app_name} is "
            f"{app_configuration.security_scheme}, not OAuth2"
        )

    # Enforce linked accounts quota before creating new account
    quota_manager.enforce_linked_accounts_creation_quota(
        context.db_session, context.project.org_id, query_params.linked_account_owner_id
    )

    oauth2_scheme = scm.get_app_configuration_oauth2_scheme(
        app_configuration.app, app_configuration
    )

    oauth2_manager = OAuth2Manager(
        app_name=query_params.app_name,
        client_id=oauth2_scheme.client_id,
        client_secret=oauth2_scheme.client_secret,
        scope=oauth2_scheme.scope,
        authorize_url=oauth2_scheme.authorize_url,
        access_token_url=oauth2_scheme.access_token_url,
        refresh_token_url=oauth2_scheme.refresh_token_url,
        token_endpoint_auth_method=oauth2_scheme.token_endpoint_auth_method,
        pkce_enabled=oauth2_scheme.pkce_enabled,
        scope_in_token_exchange=oauth2_scheme.scope_in_token_exchange,
        redirect_uri_in_token_exchange=oauth2_scheme.redirect_uri_in_token_exchange,
    )

    # create and encode the state payload.
    # NOTE: the state payload is jwt encoded (signed), but it's not encrypted, anyone can decode it
    # TODO: add expiration check to the state payload for extra security
    oauth2_state = LinkedAccountOAuth2CreateState(
        app_name=query_params.app_name,
        project_id=context.project.id,
        linked_account_owner_id=query_params.linked_account_owner_id,
        client_id=oauth2_scheme.client_id,
        code_verifier=OAuth2Manager.generate_code_verifier(),
        after_oauth2_link_redirect_url=query_params.after_oauth2_link_redirect_url,
    )

    oauth2_state_jwt = jwt.encode(
        {"alg": config.JWT_ALGORITHM},
        oauth2_state.model_dump(mode="json", exclude_none=True),
        config.SIGNING_KEY,
    ).decode()  # decode() is needed to convert the bytes to a string (not decoding the jwt payload) for this jwt library.

    path = request.url_for(LINKED_ACCOUNTS_OAUTH2_CALLBACK_ROUTE_NAME).path
    redirect_uri = oauth2_scheme.redirect_url or f"{config.REDIRECT_URI_BASE}{path}"
    authorization_url = await oauth2_manager.create_authorization_url(
        redirect_uri=redirect_uri,
        state=oauth2_state_jwt,
        code_verifier=oauth2_state.code_verifier,
        prompt=oauth2_scheme.prompt or "consent",
    )

    # rewrite the authorization url for some apps that need special handling
    # TODO: this is hacky and need to refactor this in the future
    authorization_url = OAuth2Manager.rewrite_oauth2_authorization_url(
        query_params.app_name, authorization_url
    )

    logger.info(f"Linking oauth2 account with authorization_url={authorization_url}")
    return {"url": authorization_url}


@router.get(
    "/oauth2/callback",
    name=LINKED_ACCOUNTS_OAUTH2_CALLBACK_ROUTE_NAME,
    response_model=LinkedAccountWithCredentials,
    response_model_exclude_none=True,
)
async def linked_accounts_oauth2_callback(
    request: Request,
    db_session: Annotated[Session, Depends(deps.yield_db_session)],
    has_admin_key: Annotated[bool, Depends(acl.is_valid_static_admin_key)],
) -> LinkedAccount | RedirectResponse:
    """
    Callback endpoint for OAuth2 account linking.
    - A linked account (with necessary credentials from the OAuth2 provider) will be created in the database.
    """
    # check for errors
    error = request.query_params.get("error")
    error_description = request.query_params.get("error_description")
    if error:
        logger.error(
            f"OAuth2 account linking callback received, error={error}, "
            f"error_description={error_description}"
        )
        raise OAuth2Error(
            f"oauth2 account linking callback error: {error}, error_description: {error_description}"
        )

    # check for code
    code = request.query_params.get("code")
    if not code:
        logger.error("OAuth2 account linking callback received, missing code")
        raise OAuth2Error("missing code parameter during account linking")

    # check for state
    state_jwt = request.query_params.get("state")
    if not state_jwt:
        logger.error(
            "OAuth2 account linking callback received, missing state",
        )
        raise OAuth2Error("missing state parameter during account linking")

    # decode the state payload
    try:
        state = LinkedAccountOAuth2CreateState.model_validate(
            jwt.decode(state_jwt, config.SIGNING_KEY)
        )
        logger.info(
            f"OAuth2 account linking callback received, decoded state={state.model_dump(exclude_none=True)}",
        )
    except Exception as e:
        logger.exception(f"Failed to decode OAuth2 state, error={e}")
        raise AuthenticationError("invalid state parameter during account linking") from e

    # check if the app exists
    app = crud.apps.get_app(db_session, state.app_name, False, False)
    if not app:
        logger.error(
            f"Unable to continue with account linking, app not found app_name={state.app_name}"
        )
        raise AppNotFound(f"app={state.app_name} not found")

    # check app configuration
    # - exists
    # - configuration is OAuth2
    # - client_id matches the one used at the start of the OAuth2 flow
    app_configuration = crud.app_configurations.get_app_configuration(
        db_session, state.project_id, state.app_name
    )
    if not app_configuration:
        logger.error(
            f"Unable to continue with account linking, app configuration not found "
            f"app_name={state.app_name}"
        )
        raise AppConfigurationNotFound(f"app configuration for app={state.app_name} not found")
    if app_configuration.security_scheme != SecurityScheme.OAUTH2:
        logger.error(
            f"Unable to continue with account linking, app configuration is not OAuth2 "
            f"app_name={state.app_name}"
        )
        raise NoImplementationFound(f"app configuration for app={state.app_name} is not OAuth2")

    # create oauth2 manager
    oauth2_scheme = scm.get_app_configuration_oauth2_scheme(
        app_configuration.app, app_configuration
    )
    if oauth2_scheme.client_id != state.client_id:
        logger.error(
            f"Unable to continue with account linking, client_id of state doesn't match client_id of app configuration "
            f"app_name={state.app_name} "
            f"client_id={oauth2_scheme.client_id} "
            f"state_client_id={state.client_id}"
        )
        raise OAuth2Error("client_id mismatch during account linking")

    oauth2_manager = OAuth2Manager(
        app_name=state.app_name,
        client_id=oauth2_scheme.client_id,
        client_secret=oauth2_scheme.client_secret,
        scope=oauth2_scheme.scope,
        authorize_url=oauth2_scheme.authorize_url,
        access_token_url=oauth2_scheme.access_token_url,
        refresh_token_url=oauth2_scheme.refresh_token_url,
        token_endpoint_auth_method=oauth2_scheme.token_endpoint_auth_method,
        pkce_enabled=oauth2_scheme.pkce_enabled,
        scope_in_token_exchange=oauth2_scheme.scope_in_token_exchange,
        redirect_uri_in_token_exchange=oauth2_scheme.redirect_uri_in_token_exchange,
    )

    path = request.url_for(LINKED_ACCOUNTS_OAUTH2_CALLBACK_ROUTE_NAME).path
    redirect_uri = oauth2_scheme.redirect_url or f"{config.REDIRECT_URI_BASE}{path}"
    try:
        token_response = await oauth2_manager.fetch_token(
            redirect_uri=redirect_uri,
            code=code,
            code_verifier=state.code_verifier,
        )
    except OAuth2Error as e:
        logger.exception(
            f"Token exchange failed during OAuth2 callback, "
            f"app_name={state.app_name}, "
            f"app_id={state.app_id}, "
            f"project_id={state.project_id}, "
            f"linked_account_owner_id={state.linked_account_owner_id}, "
            f"access_token_url={oauth2_scheme.access_token_url}, "
            f"redirect_uri={redirect_uri}"
        )
        raise

    try:
        security_credentials = oauth2_manager.parse_fetch_token_response(token_response)
    except OAuth2Error as e:
        logger.exception(
            f"Failed to parse token response during OAuth2 callback, "
            f"app_name={state.app_name}, "
            f"app_id={state.app_id}, "
            f"project_id={state.project_id}, "
            f"linked_account_owner_id={state.linked_account_owner_id}"
        )
        raise

    # if the linked account already exists, update it, otherwise create a new one
    # TODO: consider separating the logic for updating and creating a linked account or give warning to clients
    # if the linked account already exists to avoid accidental overwriting the account
    # TODO: try/except, retry?

    # Check if state contains app_id (from by-app-id flow) or app_name (from by-app-name flow)
    if state.app_id:
        # Use app_id-based CRUD functions
        linked_account = crud.linked_accounts.get_linked_account_by_app_id(
            db_session,
            state.project_id,
            state.app_id,
            state.linked_account_owner_id,
        )
    else:
        # Use app_name-based CRUD functions
        linked_account = crud.linked_accounts.get_linked_account(
            db_session,
            state.project_id,
            state.app_name,
            state.linked_account_owner_id,
        )

    if linked_account:
        logger.info(
            f"Updating oauth2 credentials for linked account, linked_account_id={linked_account.id}"
        )
        linked_account = crud.linked_accounts.update_linked_account_credentials(
            db_session, linked_account, security_credentials
        )
    else:
        # Get the organization ID from the project
        project = crud.projects.get_project(db_session, state.project_id)
        if not project:
            logger.error(
                f"project not found when creating linked account project_id={state.project_id}"
            )
            raise ProjectNotFound(f"Project with ID {state.project_id} not found")
        org_id = project.org_id
        # Enforce linked accounts quota before creating new account
        quota_manager.enforce_linked_accounts_creation_quota(
            db_session, org_id, state.linked_account_owner_id
        )

        if state.app_id:
            # Use app_id-based create function
            logger.info(
                f"Creating oauth2 linked account by app_id, "
                f"app_id={state.app_id}, "
                f"linked_account_owner_id={state.linked_account_owner_id}"
            )
            linked_account = crud.linked_accounts.create_linked_account_by_app_id(
                db_session,
                project_id=state.project_id,
                app_id=state.app_id,
                linked_account_owner_id=state.linked_account_owner_id,
                security_scheme=SecurityScheme.OAUTH2,
                security_credentials=security_credentials,
                enabled=True,
            )
        else:
            # Use app_name-based create function
            logger.info(
                f"Creating oauth2 linked account, "
                f"app_name={state.app_name}, "
                f"linked_account_owner_id={state.linked_account_owner_id}"
            )
            linked_account = crud.linked_accounts.create_linked_account(
                db_session,
                project_id=state.project_id,
                app_name=state.app_name,
                linked_account_owner_id=state.linked_account_owner_id,
                security_scheme=SecurityScheme.OAUTH2,
                security_credentials=security_credentials,
                enabled=True,
                api_key_id=None,  # OAuth2 callback doesn't have access to request context
            )
    db_session.commit()

    if state.after_oauth2_link_redirect_url:
        return RedirectResponse(
            url=state.after_oauth2_link_redirect_url, status_code=status.HTTP_302_FOUND
        )

    if not has_admin_key:
        linked_account.security_credentials = acl.strip_oauth2_client_credentials(
            linked_account.security_credentials
        )

    return linked_account


@router.post("/oauth2/client-credentials", response_model=LinkedAccountPublic)
async def link_oauth2_client_credentials_account(
    context: Annotated[deps.RequestContext, Depends(deps.get_request_context)],
    body: Annotated[LinkedAccountOAuth2ClientCredentialsCreate, Body()],
) -> LinkedAccount:
    """
    Create a linked account using OAuth2 client_credentials grant.
    This flow directly exchanges client_id + client_secret for an access token
    (no user browser interaction), suitable for server-to-server/daemon scenarios.
    """
    app_configuration = crud.app_configurations.get_app_configuration(
        context.db_session, context.project.id, body.app_name
    )
    if not app_configuration:
        raise AppConfigurationNotFound(
            f"configuration for app={body.app_name} not found, please configure the app first"
        )
    if app_configuration.security_scheme != SecurityScheme.OAUTH2:
        raise NoImplementationFound(
            f"The security_scheme configured for app={body.app_name} is "
            f"{app_configuration.security_scheme}, not OAuth2"
        )

    # Check for existing linked account
    existing = crud.linked_accounts.get_linked_account(
        context.db_session,
        context.project.id,
        body.app_name,
        body.linked_account_owner_id,
    )
    if existing:
        raise LinkedAccountAlreadyExists(
            f"linked account already exists for app={body.app_name}, "
            f"owner={body.linked_account_owner_id}"
        )

    # Enforce quota
    quota_manager.enforce_linked_accounts_creation_quota(
        context.db_session, context.project.org_id, body.linked_account_owner_id
    )

    # Get OAuth2 scheme (with overrides applied)
    oauth2_scheme = scm.get_app_configuration_oauth2_scheme(
        app_configuration.app, app_configuration
    )

    # Determine effective values
    client_id = body.client_id or oauth2_scheme.client_id
    client_secret = body.client_secret or oauth2_scheme.client_secret
    scope = body.scope or oauth2_scheme.scope

    # Build token_url from tenant_id if not directly provided
    if body.token_url:
        token_url = body.token_url
    else:
        token_url = f"https://login.microsoftonline.com/{body.tenant_id}/oauth2/v2.0/token"

    logger.info(
        f"[client_credentials] app={body.app_name}, "
        f"token_url={token_url}, "
        f"token_endpoint_auth_method={oauth2_scheme.token_endpoint_auth_method}, "
        f"scope={scope}, "
        f"client_id_source={'body' if body.client_id else 'scheme'}"
    )

    # Fetch token using client_credentials grant
    token_response = await OAuth2Manager.fetch_client_credentials_token(
        token_url=token_url,
        client_id=client_id,
        client_secret=client_secret,
        scope=scope,
        token_endpoint_auth_method=oauth2_scheme.token_endpoint_auth_method,
    )

    expires_at = scm.resolve_oauth2_expires_at(
        token_response,
        OAuth2FlowType.CLIENT_CREDENTIALS,
    )

    if not token_response.get("access_token"):
        raise OAuth2Error("Failed to obtain access token via client_credentials grant")

    # Build credentials
    credentials = OAuth2SchemeCredentials(
        client_id=client_id,
        client_secret=client_secret,
        scope=scope,
        access_token=token_response["access_token"],
        token_type=token_response.get("token_type"),
        expires_at=expires_at,
        refresh_token=None,
        raw_token_response=token_response,
        oauth2_flow_type=OAuth2FlowType.CLIENT_CREDENTIALS,
        token_url=token_url,
    )

    # Create linked account
    linked_account = crud.linked_accounts.create_linked_account(
        context.db_session,
        project_id=context.project.id,
        app_name=body.app_name,
        linked_account_owner_id=body.linked_account_owner_id,
        security_scheme=SecurityScheme.OAUTH2,
        security_credentials=credentials,
    )

    context.db_session.commit()
    logger.info(
        f"Created linked account via client_credentials, "
        f"app={body.app_name}, linked_account_id={linked_account.id}"
    )

    return linked_account


# TODO: add pagination
@router.get("", response_model=list[LinkedAccountPublic])
async def list_linked_accounts(
    context: Annotated[deps.RequestContext, Depends(deps.get_request_context)],
    query_params: Annotated[LinkedAccountsList, Query()],
) -> list[LinkedAccount]:
    """
    List all linked accounts.
    - Optionally filter by app_name and linked_account_owner_id.
    - app_name + linked_account_owner_id can uniquely identify a linked account.
    - This can be an alternatively way to GET /linked-accounts/{linked_account_id} for getting a specific linked account.
    """

    linked_accounts = crud.linked_accounts.get_linked_accounts(
        context.db_session,
        context.project.id,
        query_params.app_name,
        query_params.linked_account_owner_id,
    )

    return linked_accounts


@router.get(
    "/{linked_account_id}",
    response_model=LinkedAccountWithCredentials,
    response_model_exclude_none=True,
)
async def get_linked_account(
    context: Annotated[deps.RequestContext, Depends(deps.get_request_context)],
    has_admin_key: Annotated[bool, Depends(acl.is_valid_static_admin_key)],
    linked_account_id: UUID,
) -> LinkedAccount:
    """
    Get a linked account by its id.
    - linked_account_id uniquely identifies a linked account across the platform.
    """
    logger.info(f"Get linked account, linked_account_id={linked_account_id}")
    # validations
    linked_account = crud.linked_accounts.get_linked_account_by_id_under_project(
        context.db_session, linked_account_id, context.project.id
    )
    if not linked_account:
        logger.error(f"Linked account not found, linked_account_id={linked_account_id}")
        raise LinkedAccountNotFound(f"linked account={linked_account_id} not found")

    # Get the app configuration to check and refresh credentials if needed
    app_configuration = crud.app_configurations.get_app_configuration(
        context.db_session, context.project.id, linked_account.app.name
    )
    if not app_configuration:
        logger.error(
            "app configuration not found",
        )
        raise AppConfigurationNotFound(
            f"app configuration for app={linked_account.app.name} not found"
        )

    security_credentials_response = await scm.get_security_credentials(
        linked_account.app, app_configuration, linked_account
    )
    scm.update_security_credentials(
        context.db_session, linked_account.app, linked_account, security_credentials_response
    )
    logger.info(
        f"Fetched security credentials for linked account, linked_account_id={linked_account.id}, "
        f"is_updated={security_credentials_response.is_updated}"
    )
    context.db_session.commit()

    if not has_admin_key:
        linked_account.security_credentials = acl.strip_oauth2_client_credentials(
            linked_account.security_credentials
        )

    return linked_account


@router.get(
    "/{linked_account_id}/credentials",
    response_model=LinkedAccountWithFullCredentials,
    response_model_exclude_none=True,
)
async def get_linked_account_full_credentials(
    context: Annotated[deps.RequestContext, Depends(deps.get_request_context)],
    has_admin_key: Annotated[bool, Depends(acl.is_valid_static_admin_key)],
    linked_account_id: UUID,
) -> LinkedAccount:
    """
    Get a linked account's full, unredacted credentials by its id.
    Unlike GET /{linked_account_id}, this also returns the raw secret_key for
    api_key-based linked accounts, not just oauth2 access/refresh tokens.
    """
    logger.info(f"Get linked account full credentials, linked_account_id={linked_account_id}")
    # validations
    linked_account = crud.linked_accounts.get_linked_account_by_id_under_project(
        context.db_session, linked_account_id, context.project.id
    )
    if not linked_account:
        logger.error(f"Linked account not found, linked_account_id={linked_account_id}")
        raise LinkedAccountNotFound(f"linked account={linked_account_id} not found")

    # Get the app configuration to check and refresh credentials if needed
    app_configuration = crud.app_configurations.get_app_configuration(
        context.db_session, context.project.id, linked_account.app.name
    )
    if not app_configuration:
        logger.error(
            "app configuration not found",
        )
        raise AppConfigurationNotFound(
            f"app configuration for app={linked_account.app.name} not found"
        )

    security_credentials_response = await scm.get_security_credentials(
        linked_account.app, app_configuration, linked_account
    )
    scm.update_security_credentials(
        context.db_session, linked_account.app, linked_account, security_credentials_response
    )
    logger.info(
        f"Fetched security credentials for linked account, linked_account_id={linked_account.id}, "
        f"is_updated={security_credentials_response.is_updated}"
    )
    context.db_session.commit()

    if not has_admin_key:
        linked_account.security_credentials = acl.strip_oauth2_client_credentials(
            linked_account.security_credentials, redact_value="REDACTED"
        )

    return linked_account


@router.delete("/{linked_account_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_linked_account(
    context: Annotated[deps.RequestContext, Depends(deps.get_request_context)],
    linked_account_id: UUID,
) -> None:
    """
    Delete a linked account by its id.
    """
    logger.info(f"Delete linked account, linked_account_id={linked_account_id}")
    linked_account = crud.linked_accounts.get_linked_account_by_id_under_project(
        context.db_session, linked_account_id, context.project.id
    )
    if not linked_account:
        logger.error(f"Linked account not found, linked_account_id={linked_account_id}")
        raise LinkedAccountNotFound(f"linked account={linked_account_id} not found")

    crud.linked_accounts.delete_linked_account(context.db_session, linked_account)

    context.db_session.commit()


@router.patch("/{linked_account_id}", response_model=LinkedAccountPublic)
async def update_linked_account(
    context: Annotated[deps.RequestContext, Depends(deps.get_request_context)],
    linked_account_id: UUID,
    body: LinkedAccountUpdate,
) -> LinkedAccount:
    """
    Update a linked account.
    """
    logger.info(f"Update linked account, linked_account_id={linked_account_id}")
    linked_account = crud.linked_accounts.get_linked_account_by_id_under_project(
        context.db_session, linked_account_id, context.project.id
    )
    if not linked_account:
        logger.error(f"Linked account not found, linked_account_id={linked_account_id}")
        raise LinkedAccountNotFound(f"Linked account={linked_account_id} not found")

    linked_account = crud.linked_accounts.update_linked_account(
        context.db_session, linked_account, body
    )
    context.db_session.commit()

    return linked_account
