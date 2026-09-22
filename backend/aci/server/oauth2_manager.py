import random
import string
import time
from typing import Any, cast

import httpx
from authlib.integrations.httpx_client import AsyncOAuth2Client

from aci.common.exceptions import OAuth2Error, OAuth2ReauthenticationRequired
from aci.common.logging_setup import get_logger
from aci.common.schemas.security_scheme import OAuth2SchemeCredentials

UNICODE_ASCII_CHARACTER_SET = string.ascii_letters + string.digits
logger = get_logger(__name__)


class OAuth2Manager:
    def __init__(
        self,
        app_name: str,
        client_id: str,
        client_secret: str,
        scope: str,
        authorize_url: str,
        access_token_url: str,
        refresh_token_url: str,
        token_endpoint_auth_method: str | None = None,
        pkce_enabled: bool = True,
        scope_in_token_exchange: bool = True,
        redirect_uri_in_token_exchange: bool = True,
    ):
        """
        Initialize the OAuth2Manager

        Args:
            app_name: The name of the ACI.dev App
            client_id: The client ID of the OAuth2 client
            client_secret: The client secret of the OAuth2 client
            scope: The scope of the OAuth2 client
            authorize_url: The URL of the OAuth2 authorization server
            access_token_url: The URL of the OAuth2 access token server
            refresh_token_url: The URL of the OAuth2 refresh token server
            token_endpoint_auth_method:
                client_secret_basic (default) | client_secret_post | none
                Additional options can be achieved by registering a custom auth method
            pkce_enabled: Set to False for providers that do not support PKCE (e.g., Oracle IDCS).
                Defaults to True so all existing apps continue using PKCE unchanged.
            scope_in_token_exchange: Set to False for providers that reject scope in the
                authorization_code token exchange (e.g., Oracle IDCS). Defaults to True.
            redirect_uri_in_token_exchange: Set to False for providers whose confidential/trusted
                clients reject redirect_uri in the authorization_code token exchange
                (e.g., Oracle IDCS — redirect_uri is only expected there for public clients).
                Defaults to True.
        """

        self.app_name = app_name
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.authorize_url = authorize_url
        self.access_token_url = access_token_url
        self.refresh_token_url = refresh_token_url
        self.token_endpoint_auth_method = token_endpoint_auth_method
        self.pkce_enabled = pkce_enabled
        self.scope_in_token_exchange = scope_in_token_exchange
        self.redirect_uri_in_token_exchange = redirect_uri_in_token_exchange

        # TODO: need to close the client after use
        # Add an aclose() helper (or implement __aenter__/__aexit__) and make callers invoke it during shutdown.
        # NOTE: don't pass in scope here, otherwise it will be sent during refresh token request which is not needed
        self.oauth2_client = AsyncOAuth2Client(
            client_id=client_id,
            client_secret=client_secret,
            token_endpoint_auth_method=token_endpoint_auth_method,
            code_challenge_method="S256" if pkce_enabled else None,
            # TODO: use update_token callback to save tokens to the database
            update_token=None,
        )

    # TODO: some app may not support "code_verifier"?
    async def create_authorization_url(
        self,
        redirect_uri: str,
        state: str,
        code_verifier: str,
        access_type: str = "offline",
        prompt: str = "consent",
    ) -> str:
        """
        Create authorization URL for user to authorize your application

        Args:
            redirect_uri: The redirect URI of the OAuth2 client
            state: state parameter for CSRF protection, also used to store required data for the callback
            code_verifier: The code verifier used to for the authorization url
            access_type: The access type of the OAuth2 client
            prompt: The prompt of the OAuth2 client

        Returns:
            authorization_url: The authorization URL for the user to authorize the app
        """

        # TODO: some oauth2 apps may have unconventional params, temporarily handle them here
        app_specific_params = {}
        if self.app_name == "REDDIT":
            app_specific_params = {
                "duration": "permanent",
            }
            logger.info(
                f"Adding app specific params, app_name={self.app_name}, "
                f"params={app_specific_params}"
            )
        # NOTE:
        # - "scope" can be specified here
        # - "response_type" can be specified here (default is "code")
        # - and additional options can be specified here (like access_type, prompt, etc.)
        # When PKCE is disabled (e.g. Oracle IDCS), code_verifier is intentionally
        # dropped here. The caller still generates one but it is harmlessly discarded.
        authorization_url, _ = self.oauth2_client.create_authorization_url(
            url=self.authorize_url,
            redirect_uri=redirect_uri,
            state=state,
            code_verifier=code_verifier if self.pkce_enabled else None,
            access_type=access_type,
            prompt=prompt,
            scope=self.scope,
            **app_specific_params,
        )

        return str(authorization_url)

    # TODO: some app may not support "code_verifier"?
    async def fetch_token(
        self,
        redirect_uri: str,
        code: str,
        code_verifier: str,
    ) -> dict[str, Any]:
        """
        Exchange authorization code for access token

        Args:
            redirect_uri: The redirect URI of the OAuth2 client
            code: The authorization code returned from OAuth2 provider
            code_verifier: The code verifier used to for the authorization url

        Returns:
            Token response dictionary
        """
        effective_redirect_uri = redirect_uri if self.redirect_uri_in_token_exchange else None
        effective_code_verifier = code_verifier if self.pkce_enabled else None
        effective_scope = self.scope if self.scope_in_token_exchange else None

        logger.info(
            f"[fetch_token] attempting authorization_code token exchange, "
            f"app_name={self.app_name}, access_token_url={self.access_token_url}, "
            f"token_endpoint_auth_method={self.token_endpoint_auth_method}, "
            f"pkce_enabled={self.pkce_enabled}, "
            f"scope_in_token_exchange={self.scope_in_token_exchange}, "
            f"redirect_uri_in_token_exchange={self.redirect_uri_in_token_exchange}, "
            f"redirect_uri_sent={effective_redirect_uri}, "
            f"scope_sent={effective_scope}, "
            f"code_verifier_sent={effective_code_verifier is not None}, "
            # NOTE: this is the single-use, short-lived authorization code (not an access/refresh
            # token), and only its first 8 chars are logged, purely to correlate log lines with a
            # specific exchange attempt without exposing the full code.
            f"code_prefix={code[:8]}..."
        )

        try:
            token = cast(
                dict[str, Any],
                await self.oauth2_client.fetch_token(
                    self.access_token_url,
                    redirect_uri=effective_redirect_uri,
                    code=code,
                    code_verifier=effective_code_verifier,
                    scope=effective_scope,
                ),
            )
            logger.info(
                f"[fetch_token] token exchange succeeded, app_name={self.app_name}, "
                f"token_type={token.get('token_type')}, has_refresh_token={'refresh_token' in token}"
            )
            return token
        except Exception as e:
            # authlib's OAuth2Error subclasses (e.g. InvalidRequestError) carry the parsed
            # error/description/status_code from the provider's token endpoint response.
            provider_error = getattr(e, "error", None)
            provider_description = getattr(e, "description", None)
            provider_status_code = getattr(e, "status_code", None)
            logger.error(
                f"[fetch_token] token exchange failed, app_name={self.app_name}, "
                f"access_token_url={self.access_token_url}, "
                f"token_endpoint_auth_method={self.token_endpoint_auth_method}, "
                f"pkce_enabled={self.pkce_enabled}, "
                f"scope_in_token_exchange={self.scope_in_token_exchange}, "
                f"redirect_uri_in_token_exchange={self.redirect_uri_in_token_exchange}, "
                f"redirect_uri_sent={effective_redirect_uri}, "
                f"scope_sent={effective_scope}, "
                f"provider_error={provider_error}, provider_description={provider_description}, "
                f"provider_status_code={provider_status_code}, "
                f"exception_type={type(e).__name__}, error={e}"
            )
            raise OAuth2Error("failed to fetch access token") from e

    async def refresh_token(
        self,
        refresh_token: str,
    ) -> dict[str, Any]:
        try:
            token = cast(
                dict[str, Any],
                await self.oauth2_client.refresh_token(
                    self.refresh_token_url, refresh_token=refresh_token
                ),
            )
            return token
        except Exception as e:
            # Authlib sets `.error` to the provider's raw OAuth2 error code (e.g.
            # "invalid_grant") when the token endpoint responds with a structured
            # error body. Only these exact terminal codes mean the refresh token
            # itself is dead and the user must re-authenticate; everything else
            # (timeouts, connection failures, provider 5xx, malformed responses,
            # unrecognized codes) is a generic, retryable OAuth2Error.
            provider_error = getattr(e, "error", None)
            if provider_error in ("invalid_grant", "invalid_token", "interaction_required"):
                logger.error(
                    "Refresh token rejected by provider as terminal, "
                    f"app_name={self.app_name}, provider_error={provider_error}, error={e}"
                )
                raise OAuth2ReauthenticationRequired(
                    reason_code="refresh_token_invalid",
                    provider_error=provider_error,
                    message="Failed to refresh access token",
                ) from e
            logger.error(f"Failed to refresh access token, app_name={self.app_name}, error={e}")
            raise OAuth2Error("Failed to refresh access token") from e

    def parse_fetch_token_response(self, token: dict) -> OAuth2SchemeCredentials:
        """
        Parse OAuth2SchemeCredentials from token response with app-specific handling.

        Args:
            token: OAuth2 token response from provider

        Returns:
            OAuth2SchemeCredentials with appropriate fields set
        """
        data = token

        # handle Slack's special case
        if self.app_name == "SLACK":
            if "authed_user" in data:
                data = cast(dict, data["authed_user"])
            else:
                logger.error(f"Missing authed_user in Slack OAuth response, app={self.app_name}")
                raise OAuth2Error("Missing access_token in Slack OAuth response")

        if "access_token" not in data:
            logger.error(f"Missing access_token in OAuth response, app={self.app_name}")
            raise OAuth2Error("Missing access_token in OAuth response")

        # some apps have long live access token so expiration time may not be present
        expires_at: int | None = None
        if "expires_at" in data:
            expires_at = int(data["expires_at"])
        elif "expires_in" in data:
            expires_at = int(time.time()) + int(data["expires_in"])

        # TODO: if scope is present, check if it matches the scope in the App Configuration

        return OAuth2SchemeCredentials(
            client_id=self.client_id,
            client_secret=self.client_secret,
            scope=self.scope,
            access_token=data["access_token"],
            token_type=data.get("token_type"),
            expires_at=expires_at,
            refresh_token=data.get("refresh_token"),
            raw_token_response=token,
        )

    @staticmethod
    async def fetch_client_credentials_token(
        token_url: str,
        client_id: str,
        client_secret: str,
        scope: str,
        token_endpoint_auth_method: str | None = None,
    ) -> dict[str, Any]:
        """Exchange client_id + client_secret for an access token using client_credentials grant.

        token_endpoint_auth_method:
          - "client_secret_basic": credentials sent as HTTP Basic Auth header (e.g. Commercetools)
          - None / anything else: credentials sent in the request body (default, backward-compatible)
        """
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=300.0)) as client:
                data: dict[str, str] = {"grant_type": "client_credentials"}
                httpx_auth = None

                if token_endpoint_auth_method == "client_secret_basic":
                    # Credentials go in Authorization: Basic header, not the body
                    httpx_auth = (client_id, client_secret)
                    logger.info(
                        f"[fetch_client_credentials_token] using client_secret_basic (HTTP Basic Auth), "
                        f"token_url={token_url}, scope={scope}"
                    )
                else:
                    # Default (client_secret_post): credentials in request body
                    data["client_id"] = client_id
                    data["client_secret"] = client_secret
                    logger.info(
                        f"[fetch_client_credentials_token] using client_secret_post (body), "
                        f"token_url={token_url}, scope={scope}"
                    )

                if scope:
                    data["scope"] = scope

                response = await client.post(token_url, data=data, auth=httpx_auth)
                logger.info(
                    f"[fetch_client_credentials_token] response status={response.status_code}, "
                    f"token_url={token_url}"
                )
                if not response.is_success:
                    logger.error(
                        f"[fetch_client_credentials_token] token request failed, "
                        f"token_url={token_url}, status={response.status_code}, "
                        f"response_body={response.text}"
                    )
                    response.raise_for_status()
                return response.json()
        except OAuth2Error:
            raise
        except Exception as e:
            logger.error(
                f"[fetch_client_credentials_token] exception, token_url={token_url}, error={e}"
            )
            raise OAuth2Error("Failed to fetch client_credentials token") from e

    @staticmethod
    def generate_code_verifier(length: int = 48) -> str:
        """
        Generate a random code verifier for OAuth2
        """
        rand = random.SystemRandom()
        return "".join(rand.choice(UNICODE_ASCII_CHARACTER_SET) for _ in range(length))

    # TODO: consider adding this inside create_authorization_url function instead of
    # calling it separately
    @staticmethod
    def rewrite_oauth2_authorization_url(app_name: str, authorization_url: str) -> str:
        """
        Rewrite OAuth2 authorization URL for specific apps that need special handling.
        Currently handles Slack's special case where user scopes and scopes need to be replaced.
        TODO: this approach is hacky and need to refactor this in the future

        Args:
            app_name: Name of the OAuth2 app (e.g., 'slack')
            authorization_url: The original authorization URL

        Returns:
            The rewritten authorization URL if needed, otherwise the original URL
        """
        if app_name == "SLACK":
            # Slack requires user scopes to be prefixed with 'user_'
            # Replace 'scope=' with 'user_scope=' and add 'scope=' with the null value
            if "scope=" in authorization_url:
                # Extract the original scope value
                scope_start = authorization_url.find("scope=") + 6
                scope_end = authorization_url.find("&", scope_start)
                if scope_end == -1:
                    scope_end = len(authorization_url)
                original_scope = authorization_url[scope_start:scope_end]

                # Replace the original scope with user_scope and add scope
                new_url = authorization_url.replace(
                    f"scope={original_scope}", f"user_scope={original_scope}&scope="
                )
                return new_url

        return authorization_url
