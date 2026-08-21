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


def validate_project_exists(db_session: Session, project_id: UUID) -> Project:
    project = crud.projects.get_project(db_session, project_id)
    if not project:
        raise ProjectNotFound(f"project={project_id} not found")
    return project
