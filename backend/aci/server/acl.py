import logging
from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from propelauth_fastapi import FastAPIAuth, User, init_auth
from sqlalchemy.orm import Session

from aci.common.db import crud
from aci.common.db.sql_models import Project
from aci.common.enums import OrganizationRole
from aci.common.exceptions import ProjectNotFound
from aci.server import config

logger = logging.getLogger(__name__)

_static_key_bearer = HTTPBearer(auto_error=False)

_auth = init_auth(config.PROPELAUTH_AUTH_URL, config.PROPELAUTH_API_KEY)


def get_propelauth() -> FastAPIAuth:
    return _auth


def validate_user_access_to_org(user: User, org_id: str) -> None:
    # TODO: Change to require_org_member_with_minimum_role and require_org_member once projects have been refactored to use
    # TODO: org_id in the header. Currently they we have project_id so this function and validate_user_access_to_project are still useful.
    # Use PropelAuth's built-in method to validate organization role
    get_propelauth().require_org_member(user, org_id)


def validate_user_access_to_project(db_session: Session, user: User, project_id: UUID) -> None:
    # TODO: refactor to use PropelAuth built-in methods
    # TODO: we can introduce project level ACLs later
    project = crud.projects.get_project(db_session, project_id)
    if not project:
        raise ProjectNotFound(f"project={project_id} not found")

    validate_user_access_to_org(user, project.org_id)


def require_org_member(user: User, org_id: str) -> None:
    get_propelauth().require_org_member(user, org_id)


def require_org_member_with_minimum_role(
    user: User, org_id: str, minimum_role: OrganizationRole
) -> None:
    get_propelauth().require_org_member_with_minimum_role(user, org_id, minimum_role)


def require_static_key(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_static_key_bearer)] = None,
) -> None:
    """Stopgap auth for /v1/projects and /v1/tool-seeding while PropelAuth isn't
    fully wired up: validates a single shared secret (SERVER_STATIC_ADMIN_KEY)
    sent as `Authorization: Bearer <key>`.

    There is no per-user/org-membership model behind this key — any request
    bearing the correct key is trusted as a full admin; org_id/project_id
    supplied by the caller are used as-is and are not checked against org
    membership (unlike PropelAuth's require_org_member).
    """
    if not config.STATIC_ADMIN_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Static admin key is not configured: set SERVER_STATIC_ADMIN_KEY.",
        )
    if credentials is None or credentials.credentials != config.STATIC_ADMIN_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing admin key",
        )


def is_valid_static_admin_key(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_static_key_bearer)] = None,
) -> bool:
    """Non-throwing check for the shared static admin key (see require_static_key
    above). Unlike require_static_key, this never raises: routes that are already
    gated by per-project API-key auth (or a signed OAuth2 state token) use it to
    conditionally unlock admin-only response fields — e.g. the platform's OAuth2
    client_id/client_secret — rather than to gate the route itself.
    """
    return bool(
        config.STATIC_ADMIN_KEY
        and credentials is not None
        and credentials.credentials == config.STATIC_ADMIN_KEY
    )


def strip_oauth2_client_credentials(
    security_credentials: dict[str, object], *, redact_value: str | None = None
) -> dict[str, object]:
    """Redact client_id/client_secret from a linked account's (or app's) stored
    OAuth2 credentials/security-scheme dict, e.g. before returning it to a caller
    that doesn't hold the static admin key.

    These freeze whichever OAuth2 client was used at link/seed time — including
    ACI's own shared platform apps (e.g. AIPOLABS_GMAIL_CLIENT_SECRET) when no
    tenant override exists — so any tenant that can read one back would obtain a
    credential trusted across every tenant.

    No-op if the dict has neither key (api_key/no_auth schemes). `redact_value`
    defaults to None (drop to null) for schemas where the fields are optional;
    pass a placeholder string for schemas where they're required.
    """
    if "client_id" not in security_credentials and "client_secret" not in security_credentials:
        return security_credentials
    stripped = dict(security_credentials)
    stripped["client_id"] = redact_value
    stripped["client_secret"] = redact_value
    return stripped


def validate_project_exists(db_session: Session, project_id: UUID) -> Project:
    project = crud.projects.get_project(db_session, project_id)
    if not project:
        raise ProjectNotFound(f"project={project_id} not found")
    return project
