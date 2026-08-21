from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, status
from sqlalchemy.orm import Session

from aci.common.db import crud
from aci.common.db.sql_models import Agent, Project
from aci.common.exceptions import (
    AgentNotFound,
    ProjectIsLastInOrgError,
    ProjectNotFound,
)
from aci.common.logging_setup import get_logger
from aci.common.schemas.agent import AgentCreate, AgentPublic, AgentUpdate
from aci.common.schemas.project import ProjectCreate, ProjectPublic, ProjectUpdate
from aci.server import acl, config, quota_manager
from aci.server import dependencies as deps

# Create router instance
router = APIRouter()
logger = get_logger(__name__)


@router.post("", response_model=ProjectPublic, include_in_schema=True)
async def create_project(
    body: ProjectCreate,
    _admin: Annotated[None, Depends(acl.require_static_key)],
    db_session: Annotated[Session, Depends(deps.yield_db_session)],
) -> Project:
    logger.info(f"Create project, org_id={body.org_id}")

    quota_manager.enforce_project_creation_quota(db_session, body.org_id)

    project = crud.projects.create_project(db_session, body.org_id, body.name)

    # Create a default Agent for the project
    agent = crud.projects.create_agent(
        db_session,
        project.id,
        name="Default Agent",
        description="Default Agent",
        allowed_apps=[],
        custom_instructions={},
    )
    db_session.commit()
    
    logger.info(f"Created project, project_id={project.id}, org_id={body.org_id}")
    
    # Convert to ProjectPublic model to avoid DetachedInstanceError
    from aci.common.schemas.project import ProjectPublic
    from aci.common.schemas.agent import AgentPublic
    from aci.common.schemas.apikey import APIKeyPublic
    
    # Load the agent that was created
    agents = crud.projects.get_agents_by_project(db_session, project.id)
    
    # Convert agents to AgentPublic models
    agent_publics = []
    for agent in agents:
        # Load API key for this agent - with error handling for Unicode issues
        api_key_publics = []
        try:
            api_key = crud.projects.get_api_key_by_agent_id(db_session, agent.id)
            if api_key:
                api_key_public = APIKeyPublic(
                    id=api_key.id,
                    key=api_key.key,  # Include the decrypted API key
                    agent_id=api_key.agent_id,
                    status=api_key.status,
                    created_at=api_key.created_at,
                    updated_at=api_key.updated_at,
                )
                api_key_publics.append(api_key_public)
        except Exception as e:
            logger.error(f"Error loading API key for agent {agent.id}: {e}")
            # Continue without API key - this allows the project creation to succeed
        
        # Create AgentPublic model
        agent_public = AgentPublic(
            id=agent.id,
            project_id=agent.project_id,
            name=agent.name,
            description=agent.description,
            allowed_apps=agent.allowed_apps,
            custom_instructions=agent.custom_instructions,
            created_at=agent.created_at,
            updated_at=agent.updated_at,
            api_keys=api_key_publics,
        )
        agent_publics.append(agent_public)
    
    # Create ProjectPublic model
    project_public = ProjectPublic(
        id=project.id,
        org_id=project.org_id,
        name=project.name,
        visibility_access=project.visibility_access,
        daily_quota_used=project.daily_quota_used,
        daily_quota_reset_at=project.daily_quota_reset_at,
        api_quota_monthly_used=project.api_quota_monthly_used,
        api_quota_last_reset=project.api_quota_last_reset,
        total_quota_used=project.total_quota_used,
        created_at=project.created_at,
        updated_at=project.updated_at,
        agents=agent_publics,
    )
    
    return project_public


@router.get("", include_in_schema=True)
async def get_projects(
    _admin: Annotated[None, Depends(acl.require_static_key)],
    org_id: Annotated[str, Header(alias=config.ACI_ORG_ID_HEADER)],
    db_session: Annotated[Session, Depends(deps.yield_db_session)],
) -> list[dict]:
    """
    Get all projects for the organization.
    """
    # logger.info(f"Get projects, org_id={org_id}")

    try:
        projects = crud.projects.get_projects_by_org(db_session, org_id)
        
        # Return a response with agents but handle Unicode errors gracefully
        simplified_projects = []
        for project in projects:
            # Load agents for this project
            agents = crud.projects.get_agents_by_project(db_session, project.id)
            
            # Convert agents to simple dict format with error handling for API keys
            agent_list = []
            for agent in agents:
                # Try to load API keys with error handling
                api_keys_list = []
                try:
                    api_key = crud.projects.get_api_key_by_agent_id(db_session, agent.id)
                    if api_key:
                        api_key_dict = {
                            "id": str(api_key.id),
                            "key": api_key.key,  # Include the decrypted API key
                            "agent_id": str(api_key.agent_id),
                            "status": api_key.status.value,
                            "created_at": api_key.created_at.isoformat() if api_key.created_at else None,
                            "updated_at": api_key.updated_at.isoformat() if api_key.updated_at else None,
                        }
                        
                        api_keys_list.append(api_key_dict)
                except Exception as e:
                    logger.error(f"Error loading API key for agent {agent.id}: {e}")
                    # Continue without API key - this allows the project to load
                
                agent_dict = {
                    "id": str(agent.id),
                    "project_id": str(agent.project_id),
                    "name": agent.name,
                    "description": agent.description,
                    "allowed_apps": agent.allowed_apps,
                    "custom_instructions": agent.custom_instructions,
                    "created_at": agent.created_at.isoformat() if agent.created_at else None,
                    "updated_at": agent.updated_at.isoformat() if agent.updated_at else None,
                    "api_keys": api_keys_list
                }
                agent_list.append(agent_dict)
            
            simplified_project = {
                "id": str(project.id),
                "org_id": project.org_id,
                "name": project.name,
                "visibility_access": project.visibility_access.value,
                "daily_quota_used": project.daily_quota_used,
                "daily_quota_reset_at": project.daily_quota_reset_at.isoformat() if project.daily_quota_reset_at else None,
                "api_quota_monthly_used": project.api_quota_monthly_used,
                "api_quota_last_reset": project.api_quota_last_reset.isoformat() if project.api_quota_last_reset else None,
                "total_quota_used": project.total_quota_used,
                "created_at": project.created_at.isoformat() if project.created_at else None,
                "updated_at": project.updated_at.isoformat() if project.updated_at else None,
                "agents": agent_list
            }
            simplified_projects.append(simplified_project)
        
        return simplified_projects
        
    except Exception as e:
        logger.error(f"Error getting projects: {e}")
        # Return empty list if there's an error, so frontend can still load
        return []


@router.delete("/{project_id}", status_code=status.HTTP_204_NO_CONTENT, include_in_schema=True)
async def delete_project(
    project_id: UUID,
    _admin: Annotated[None, Depends(acl.require_static_key)],
    db_session: Annotated[Session, Depends(deps.yield_db_session)],
) -> None:
    """
    Delete a project by project id.

    This operation will cascade delete all related data:
    - Agents and their API keys
    - App configurations
    - Linked accounts

    All associations to the project will be removed from the database.
    """
    logger.info(f"Delete project, project_id={project_id}")

    acl.validate_project_exists(db_session, project_id)

    # Get the project to check its organization
    project = crud.projects.get_project(db_session, project_id)
    if not project:
        logger.error(f"Project not found, project_id={project_id}")
        raise ProjectNotFound(f"project={project_id} not found")

    # Check if this is the last project in the organization
    org_projects = crud.projects.get_projects_by_org(db_session, project.org_id)
    if len(org_projects) <= 1:
        logger.error(
            f"Cannot delete last project, project_id={project_id}, org_id={project.org_id}"
        )
        raise ProjectIsLastInOrgError()

    crud.projects.delete_project(db_session, project_id)
    db_session.commit()


@router.patch("/{project_id}", response_model=ProjectPublic, include_in_schema=True)
async def update_project(
    project_id: UUID,
    body: ProjectUpdate,
    _admin: Annotated[None, Depends(acl.require_static_key)],
    db_session: Annotated[Session, Depends(deps.yield_db_session)],
) -> Project:
    """
    Update a project by project id.
    Currently supports updating the project name.
    """
    logger.info(f"Update project, project_id={project_id}")

    acl.validate_project_exists(db_session, project_id)

    project = crud.projects.get_project(db_session, project_id)
    if not project:
        logger.error(f"Project not found, project_id={project_id}")
        raise ProjectNotFound(f"project={project_id} not found")

    updated_project = crud.projects.update_project(db_session, project, body)
    db_session.commit()

    return updated_project


@router.post("/{project_id}/agents", response_model=AgentPublic, include_in_schema=True)
async def create_agent(
    project_id: UUID,
    body: AgentCreate,
    _admin: Annotated[None, Depends(acl.require_static_key)],
    db_session: Annotated[Session, Depends(deps.yield_db_session)],
) -> Agent:
    logger.info(f"Create agent, project_id={project_id}")

    acl.validate_project_exists(db_session, project_id)
    quota_manager.enforce_agent_creation_quota(db_session, project_id)

    agent = crud.projects.create_agent(
        db_session,
        project_id,
        body.name,
        body.description,
        body.allowed_apps,
        body.custom_instructions,
    )
    db_session.commit()
    logger.info(f"Created agent, agent_id={agent.id}")
    return agent


@router.patch(
    "/{project_id}/agents/{agent_id}",
    response_model=AgentPublic,
    include_in_schema=True,
)
async def update_agent(
    project_id: UUID,
    agent_id: UUID,
    body: AgentUpdate,
    _admin: Annotated[None, Depends(acl.require_static_key)],
    db_session: Annotated[Session, Depends(deps.yield_db_session)],
) -> Agent:
    logger.info(f"Update agent, agent_id={agent_id}, project_id={project_id}")

    acl.validate_project_exists(db_session, project_id)

    agent = crud.projects.get_agent_by_id(db_session, agent_id)
    if not agent:
        logger.error(f"Agent not found, agent_id={agent_id}, project_id={project_id}")
        raise AgentNotFound(f"agent={agent_id} not found in project={project_id}")
    # TODO: get project direct from agent through relationship
    project = crud.projects.get_project(db_session, project_id)
    if not project:
        logger.error(f"Project not found, project_id={project_id}")
        raise ProjectNotFound(f"project={project_id} not found")

    if agent.project_id != project_id:
        logger.error(
            f"Agent with project_id={agent.project_id} does not belong to project with project_id={project_id}"
        )
        raise AgentNotFound(f"Agent={agent_id} not found in project={project_id}")

    crud.projects.update_agent(db_session, agent, body)
    db_session.commit()

    return agent


@router.delete("/{project_id}/agents/{agent_id}", include_in_schema=True)
async def delete_agent(
    project_id: UUID,
    agent_id: UUID,
    _admin: Annotated[None, Depends(acl.require_static_key)],
    db_session: Annotated[Session, Depends(deps.yield_db_session)],
) -> dict[str, str]:
    """
    Delete an agent by agent id
    """
    logger.info(f"Delete agent, agent_id={agent_id}, project_id={project_id}")

    acl.validate_project_exists(db_session, project_id)

    agent = crud.projects.get_agent_by_id(db_session, agent_id)
    if not agent:
        logger.error(f"Agent not found, agent_id={agent_id}, project_id={project_id}")
        raise AgentNotFound(f"Agent={agent_id} not found")

    if agent.project_id != project_id:
        logger.error(
            f"Agent does not belong to project, agent_id={agent_id}, project_id={project_id}"
        )
        # raise 404 instead of 403 to avoid leaking information about the existence of the agent
        raise AgentNotFound(f"Agent={agent_id} not found")

    crud.projects.delete_agent(db_session, agent)
    db_session.commit()

    return {"message": f"Agent={agent.name} deleted successfully"}
