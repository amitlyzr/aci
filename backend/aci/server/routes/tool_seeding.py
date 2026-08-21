"""
Tool seeding routes for managing apps and functions via API
Matches the Docker exec commands from README.md
"""

import asyncio
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Annotated, Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, ValidationError
from sqlalchemy.orm import Session

from aci.cli.commands import upsert_app, upsert_functions
from aci.common.db import crud
from aci.common.db.sql_models import App, Function
from aci.server import acl, config, dependencies as deps
from aci.common.logging_setup import get_logger
from aci.common.schemas.app import AppDetails
from aci.common.schemas.security_scheme import SecuritySchemesPublic
from aci.common.schemas.function import FunctionDetails

logger = get_logger(__name__)
router = APIRouter()


class AppUpsertRequest(BaseModel):
    """Request model for upserting an app - matches CLI command"""
    app_path: str  # Path to app.json file (e.g., "./apps/gmail/app.json")
    secrets_path: Optional[str] = None  # Path to secrets file (e.g., "./apps/gmail/.app.secrets.json")
    secrets: Optional[Dict[str, str]] = None  # JSON secrets object for OAuth2 credentials
    skip_dry_run: bool = True


class FunctionsUpsertRequest(BaseModel):
    """Request model for upserting functions - matches CLI command"""
    functions_path: str  # Path to functions.json file (e.g., "./apps/gmail/functions.json")
    skip_dry_run: bool = True


class SeedingRequest(BaseModel):
    """Request model for seeding tools - matches frontend interface"""
    app_path: str
    functions_path: Optional[str] = None
    secrets: Optional[Dict[str, str]] = None
    skip_dry_run: bool = True


class ToolSeedingResponse(BaseModel):
    """Response model for tool seeding operations"""
    success: bool
    message: str
    app_id: Optional[UUID] = None
    function_names: Optional[List[str]] = None
    functions: Optional[List[Dict[str, Any]]] = None


class AppJsonRequest(BaseModel):
    """Request model for creating app from JSON content"""
    app_json: Dict[str, Any]  # The app.json content as a dictionary
    secrets: Optional[Dict[str, str]] = None  # Optional secrets
    skip_dry_run: bool = True


class FunctionsJsonRequest(BaseModel):
    """Request model for creating functions from JSON content"""
    functions_json: List[Dict[str, Any]]  # The functions.json content as a list
    skip_dry_run: bool = True


class ToolJsonRequest(BaseModel):
    """Request model for creating a complete tool from JSON content"""
    app_json: Dict[str, Any]  # The app.json content
    functions_json: Optional[List[Dict[str, Any]]] = None  # Optional functions.json content
    secrets: Optional[Dict[str, str]] = None  # Optional secrets
    skip_dry_run: bool = True


@router.post("/upsert-app", response_model=ToolSeedingResponse)
async def upsert_app_via_api(
    _admin: Annotated[None, Depends(acl.require_static_key)],
    org_id: Annotated[str, Header(alias=config.ACI_ORG_ID_HEADER)],
    db_session: Annotated[Session, Depends(deps.yield_db_session)],
    request: AppUpsertRequest,
) -> ToolSeedingResponse:
    """
    Upsert an app via API, equivalent to:
    docker compose exec runner python -m aci.cli upsert-app --app-file ./apps/gmail/app.json --secrets-file ./apps/gmail/.app.secrets.json

    This allows adding new tools/apps with their JSON configurations and credentials.
    """
    logger.info(f"Upsert app, org_id={org_id}")
    try:
        # Convert relative path to absolute path
        app_file_path = Path(request.app_path)
        if not app_file_path.is_absolute():
            # Assume it's relative to the backend directory
            app_file_path = Path("/workdir") / app_file_path

        if not app_file_path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"App file not found at path: {app_file_path}"
            )

        LYZR_API_KEY_ID_DB = UUID(os.getenv("LYZR_API_KEY_ID_DB"))

        # Handle secrets - either from file or from request
        secrets_file_path = None
        if request.secrets_path:
            secrets_file_path = Path(request.secrets_path)
            if not secrets_file_path.is_absolute():
                secrets_file_path = Path("/workdir") / secrets_file_path

            if not secrets_file_path.exists():
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Secrets file not found at path: {secrets_file_path}"
                )
        elif request.secrets:
            # Create temporary secrets file from request data
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(request.secrets, f)
                secrets_file_path = Path(f.name)

        # Use the CLI helper function
        app_id = upsert_app.upsert_app_helper(
            db_session=db_session,
            app_file=app_file_path,
            secrets_file=secrets_file_path,
            skip_dry_run=request.skip_dry_run,
            api_key_id=LYZR_API_KEY_ID_DB
        )

        # Clean up temporary secrets file if created
        if request.secrets and secrets_file_path and secrets_file_path.exists():
            secrets_file_path.unlink()

        return ToolSeedingResponse(
            success=True,
            message=f"Successfully upserted app from path '{request.app_path}'",
            app_id=app_id
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error upserting app from path {request.app_path}: {str(e)}")
        return ToolSeedingResponse(
            success=False,
            message=f"Failed to upsert app from path '{request.app_path}': {str(e)}"
        )


@router.post("/upsert-functions", response_model=ToolSeedingResponse)
async def upsert_functions_via_api(
    _admin: Annotated[None, Depends(acl.require_static_key)],
    org_id: Annotated[str, Header(alias=config.ACI_ORG_ID_HEADER)],
    db_session: Annotated[Session, Depends(deps.yield_db_session)],
    request: FunctionsUpsertRequest,
) -> ToolSeedingResponse:
    """
    Upsert functions via API, equivalent to:
    docker compose exec runner python -m aci.cli upsert-functions --functions-file ./apps/gmail/functions.json

    This allows adding new functions for existing apps.
    """
    logger.info(f"Upsert functions, org_id={org_id}")
    try:
        # Convert relative path to absolute path
        functions_file_path = Path(request.functions_path)
        if not functions_file_path.is_absolute():
            # Assume it's relative to the backend directory
            functions_file_path = Path("/workdir") / functions_file_path

        if not functions_file_path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Functions file not found at path: {functions_file_path}"
            )

        LYZR_API_KEY_ID_DB = UUID(os.getenv("LYZR_API_KEY_ID_DB"))

        # Initialize CLI config DB_FULL_URL if not set
        if upsert_functions.config.DB_FULL_URL is None:
            upsert_functions.config.DB_FULL_URL = upsert_functions.config.get_db_full_url_sync()

        # Use the CLI helper function
        logger.info(f"Calling upsert_functions_helper with functions_file={functions_file_path}, skip_dry_run={request.skip_dry_run}")
        function_names = upsert_functions.upsert_functions_helper(
            functions_file_path,  # Use positional argument
            request.skip_dry_run,
            api_key_id=LYZR_API_KEY_ID_DB
        )

        return ToolSeedingResponse(
        success=True,
            message=f"Successfully upserted {len(function_names)} functions from path '{request.functions_path}'",
            function_names=function_names
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error upserting functions from path {request.functions_path}: {str(e)}")
        return ToolSeedingResponse(
            success=False,
            message=f"Failed to upsert functions from path '{request.functions_path}': {str(e)}"
        )


@router.post("/seed-tool", response_model=ToolSeedingResponse)
async def seed_tool(
    _admin: Annotated[None, Depends(acl.require_static_key)],
    org_id: Annotated[str, Header(alias=config.ACI_ORG_ID_HEADER)],
    db_session: Annotated[Session, Depends(deps.yield_db_session)],
    request: SeedingRequest,
) -> ToolSeedingResponse:
    """
    Seed a tool (app + functions) via API - matches frontend interface.
    This is the main endpoint that the frontend tool-seeding page uses.
    """
    logger.info(f"Seed tool, org_id={org_id}")
    try:
        results = []

        # 1. Upsert the app first
        app_request = AppUpsertRequest(
            app_path=request.app_path,
            secrets=request.secrets,
            skip_dry_run=request.skip_dry_run
        )

        app_response = await upsert_app_via_api(_admin, org_id, db_session, app_request)
        results.append(f"App: {app_response.message}")

        if not app_response.success:
            return ToolSeedingResponse(
                success=False,
                message=f"Failed to seed tool - App upsert failed: {app_response.message}"
            )

        # 2. Upsert functions if functions_path is provided
        if request.functions_path:
            functions_request = FunctionsUpsertRequest(
                functions_path=request.functions_path,
                skip_dry_run=request.skip_dry_run
            )

            functions_response = await upsert_functions_via_api(_admin, org_id, db_session, functions_request)
            results.append(f"Functions: {functions_response.message}")

            if not functions_response.success:
                return ToolSeedingResponse(
                    success=False,
                    message=f"Partially failed to seed tool - Functions upsert failed: {functions_response.message}"
                )

        return ToolSeedingResponse(
            success=True,
            message=f"Successfully seeded tool. {' | '.join(results)}",
            app_id=app_response.app_id,
            function_names=functions_response.function_names if request.functions_path else None
        )

    except Exception as e:
        logger.error(f"Error seeding tool: {str(e)}")
        return ToolSeedingResponse(
            success=False,
            message=f"Failed to seed tool: {str(e)}"
        )


@router.get("/available-apps", response_model=List[Dict[str, Any]])
async def get_available_apps(
    _admin: Annotated[None, Depends(acl.require_static_key)],
    org_id: Annotated[str, Header(alias=config.ACI_ORG_ID_HEADER)],
    db_session: Annotated[Session, Depends(deps.yield_db_session)],
) -> List[Dict[str, Any]]:
    """
    Get list of available apps that can be seeded.
    This scans the apps directory for available app configurations.
    """
    try:
        # Scan the apps directory for available apps
        apps_dir = Path("/workdir/apps")
        available_apps = []

        if apps_dir.exists():
            for app_dir in apps_dir.iterdir():
                if app_dir.is_dir():
                    app_json_path = app_dir / "app.json"
                    functions_json_path = app_dir / "functions.json"
                    secrets_json_path = app_dir / ".app.secrets.json"

                    if app_json_path.exists():
                        try:
                            # Read app.json to get app details
                            with open(app_json_path) as f:
                                app_data = json.load(f)

                            available_apps.append({
                                "name": app_data.get("name", app_dir.name),
                                "display_name": app_data.get("display_name", app_data.get("name", app_dir.name)),
                                "description": app_data.get("description", ""),
                                "app_path": f"./apps/{app_dir.name}/app.json",
                                "functions_path": f"./apps/{app_dir.name}/functions.json" if functions_json_path.exists() else None,
                                "requires_secrets": secrets_json_path.exists() or "oauth2" in app_data.get("security_schemes", {}),
                                "security_schemes": list(app_data.get("security_schemes", {}).keys())
                            })
                        except Exception as e:
                            logger.warning(f"Could not read app.json for {app_dir.name}: {e}")
                            continue

        return available_apps

    except Exception as e:
        logger.error(f"Error getting available apps: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get available apps: {str(e)}"
        )


@router.get("/seeded-apps", response_model=List[AppDetails])
async def get_seeded_apps(
    _admin: Annotated[None, Depends(acl.require_static_key)],
    org_id: Annotated[str, Header(alias=config.ACI_ORG_ID_HEADER)],
    db_session: Annotated[Session, Depends(deps.yield_db_session)],
) -> List[AppDetails]:
    """
    Get list of apps that have been seeded (exist in the database).
    """
    try:
        LYZR_API_KEY_ID_DB = UUID(os.getenv("LYZR_API_KEY_ID_DB"))
        # Get all apps from the database
        apps = crud.apps.get_apps(
            db_session,
            public_only=False,  # Include all apps for admin purposes
            active_only=False,  # Include inactive apps
            app_names=None,
            limit=None,
            offset=0,
            api_key_id=LYZR_API_KEY_ID_DB
        )

        # Convert to AppDetails format
        app_details = []
        for app in apps:
            app_detail = AppDetails(
                id=app.id,
                name=app.name,
                display_name=app.display_name,
                provider=app.provider,
                version=app.version,
                description=app.description,
                logo=app.logo,
                categories=app.categories,
                visibility=app.visibility,
                active=app.active,
                security_schemes=list(app.security_schemes.keys()),
                supported_security_schemes=app.security_schemes,
                functions=[FunctionDetails.model_validate(func) for func in app.functions],
                created_at=app.created_at,
                updated_at=app.updated_at,
                custom_app=app.api_key_id != LYZR_API_KEY_ID_DB,
            )
            app_details.append(app_detail)

        return app_details

    except Exception as e:
        logger.error(f"Error getting seeded apps: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get seeded apps: {str(e)}"
        )


@router.get("/seeding-status", response_model=Dict[str, Any])
async def get_seeding_status(
    _admin: Annotated[None, Depends(acl.require_static_key)],
    org_id: Annotated[str, Header(alias=config.ACI_ORG_ID_HEADER)],
    db_session: Annotated[Session, Depends(deps.yield_db_session)],
) -> Dict[str, Any]:
    """
    Get the current seeding status.
    This is used by the frontend to show seeding progress.
    """
    try:
        # For now, return a simple status
        # You can enhance this to track actual seeding operations
        return {
            "is_seeded": True,
            "is_running": False,
            "last_seeded_at": None,
            "seeding_version": "1.0",
            "environment": "development"
        }

    except Exception as e:
        logger.error(f"Error getting seeding status: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get seeding status: {str(e)}"
        )


@router.post("/run-seed-script", response_model=ToolSeedingResponse)
async def run_seed_script(
    _admin: Annotated[None, Depends(acl.require_static_key)],
    org_id: Annotated[str, Header(alias=config.ACI_ORG_ID_HEADER)],
    db_session: Annotated[Session, Depends(deps.yield_db_session)],
    script_path: str = "./scripts/seed_db.sh",
    args: List[str] = None,
) -> ToolSeedingResponse:
    """
    Run a seeding script via API, equivalent to:
    docker compose exec runner ./scripts/seed_db.sh --all --mock

    This allows running the full database seeding process.

    Restricted to scripts under the repository ``/workdir/scripts`` directory.
    """
    logger.info(f"Run seed script, org_id={org_id}")
    try:
        if args is None:
            args = []

        # Restrict script execution to the seeding scripts directory to prevent
        # arbitrary-file execution (the endpoint previously executed any path).
        allowed_base = Path("/workdir/scripts").resolve()
        script_file_path = Path(script_path)
        if not script_file_path.is_absolute():
            script_file_path = Path("/workdir") / script_file_path
        script_file_path = script_file_path.resolve()

        if not script_file_path.is_relative_to(allowed_base):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Script path must be under {allowed_base}: {script_path}",
            )

        if not script_file_path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Script file not found at path: {script_file_path}"
            )

        # Make script executable
        script_file_path.chmod(0o755)

        # Run the script without blocking the event loop
        cmd = [str(script_file_path)] + list(args)

        def _run() -> subprocess.CompletedProcess[str]:
            return subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd="/workdir"
            )

        result = await asyncio.to_thread(_run)

        if result.returncode == 0:
            return ToolSeedingResponse(
                success=True,
                message=f"Successfully ran seeding script: {result.stdout}",
            )
        else:
            return ToolSeedingResponse(
                success=False,
                message=f"Seeding script failed: {result.stderr}",
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error running seeding script {script_path}: {str(e)}")
        return ToolSeedingResponse(
            success=False,
            message=f"Failed to run seeding script '{script_path}': {str(e)}"
        )


# NEW JSON-BASED ENDPOINTS

@router.post("/upsert-app-json", response_model=ToolSeedingResponse)
async def upsert_app_from_json(
    context: Annotated[deps.RequestContext, Depends(deps.get_request_context)],
    request: AppJsonRequest,
) -> ToolSeedingResponse:
    """
    Create/update an app from JSON content pasted by the user.
    This allows users to paste app.json content directly instead of requiring file paths.
    """
    try:
        # Create temporary file with the app JSON content
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(request.app_json, f, indent=2)
            app_file_path = Path(f.name)

        # Create temporary secrets file if provided
        secrets_file_path = None
        if request.secrets:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                json.dump(request.secrets, f, indent=2)
                secrets_file_path = Path(f.name)

        try:
            # Use the existing CLI helper function
            app_id = upsert_app.upsert_app_helper(
                db_session=context.db_session,
                app_file=app_file_path,
                secrets_file=secrets_file_path,
                skip_dry_run=request.skip_dry_run,
                api_key_id=context.api_key_id
            )

            return ToolSeedingResponse(
                success=True,
                message=f"Successfully upserted app '{request.app_json.get('name', 'Unknown')}' from JSON content",
                app_id=app_id
            )

        finally:
            # Clean up temporary files
            if app_file_path.exists():
                app_file_path.unlink()
            if secrets_file_path and secrets_file_path.exists():
                secrets_file_path.unlink()

    except ValidationError as e:
        lines = []
        for err in e.errors():
            loc = err["loc"]
            field = " → ".join(str(l) for l in loc) if loc else "(root)"
            lines.append(f"App JSON · {field}: {err['msg']}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="\n".join(lines),
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error upserting app from JSON content: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"{str(e)}"
        )


@router.post("/upsert-functions-json", response_model=ToolSeedingResponse)
async def upsert_functions_from_json(
    context: Annotated[deps.RequestContext, Depends(deps.get_request_context)],
    request: FunctionsJsonRequest,
) -> ToolSeedingResponse:
    """
    Create/update functions from JSON content pasted by the user.
    This allows users to paste functions.json content directly instead of requiring file paths.
    """
    try:
        # Create temporary file with the functions JSON content
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(request.functions_json, f, indent=2)
            functions_file_path = Path(f.name)

        try:
            # Initialize CLI config DB_FULL_URL if not set
            if upsert_functions.config.DB_FULL_URL is None:
                upsert_functions.config.DB_FULL_URL = upsert_functions.config.get_db_full_url_sync()

            # Use the existing CLI helper function
            function_names = upsert_functions.upsert_functions_helper(
                functions_file_path,
                request.skip_dry_run,
                context.api_key_id
            )

            # Get the function IDs for the upserted functions
            functions = []
            for name in function_names:
                function = crud.functions.get_function_by_name_and_api_key_id(context.db_session, name, context.api_key_id)
                if function:
                    functions.append({
                        "id": str(function.id),
                        "name": function.name
                    })

            return ToolSeedingResponse(
                success=True,
                message=f"Successfully upserted {len(function_names)} functions from JSON content",
                function_names=function_names,
                functions=functions
            )

        finally:
            # Clean up temporary file
            if functions_file_path.exists():
                functions_file_path.unlink()

    except ValidationError as e:
        lines = []
        for err in e.errors():
            loc = err["loc"]
            if loc and isinstance(loc[0], int):
                item_label = f"item #{loc[0] + 1}"
                field = " → ".join(str(l) for l in loc[1:]) if len(loc) > 1 else "(root)"
                lines.append(f"Function JSON · {item_label} · {field}: {err['msg']}")
            else:
                field = " → ".join(str(l) for l in loc) if loc else "(root)"
                lines.append(f"Function JSON · {field}: {err['msg']}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="\n".join(lines),
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error upserting functions from JSON content: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upsert functions from JSON content: {str(e)}"
        )


@router.post("/seed-tool-json", response_model=ToolSeedingResponse)
async def seed_tool_from_json(
    context: Annotated[deps.RequestContext, Depends(deps.get_request_context)],
    request: ToolJsonRequest,
) -> ToolSeedingResponse:
    """
    Create/update a complete tool (app + functions) from JSON content pasted by the user.
    This is the main endpoint for users to paste their custom tool configurations.
    """
    try:
        results = []

        # 1. Create app from JSON content
        app_request = AppJsonRequest(
            app_json=request.app_json,
            secrets=request.secrets,
            skip_dry_run=request.skip_dry_run
        )

        app_response = await upsert_app_from_json(context, app_request)
        results.append(f"App: {app_response.message}")

        # 2. Create functions from JSON content if provided
        functions_response = None
        if request.functions_json:
            functions_request = FunctionsJsonRequest(
                functions_json=request.functions_json,
                skip_dry_run=request.skip_dry_run
            )

            functions_response = await upsert_functions_from_json(context, functions_request)
            results.append(f"Functions: {functions_response.message}")

        return ToolSeedingResponse(
            success=True,
            message=f"Successfully seeded tool from JSON content. {' | '.join(results)}",
            app_id=app_response.app_id,
            function_names=functions_response.function_names if functions_response else None
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error seeding tool from JSON content: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to seed tool from JSON content: {str(e)}"
        )


# CUSTOM TOOLS MANAGEMENT ENDPOINTS

@router.get("/my-custom-apps", response_model=list[dict])
async def list_my_custom_apps(
    context: Annotated[deps.RequestContext, Depends(deps.get_request_context)],
    has_admin_key: Annotated[bool, Depends(acl.is_valid_static_admin_key)],
) -> list[dict]:
    """
    List all custom apps created by the current API key holder.
    Returns only apps that were created using the JSON seeding APIs.
    """
    try:
        apps = crud.apps.get_apps_by_api_key_id(context.db_session, context.api_key_id)

        return [
            {
                "id": str(app.id),
                "name": app.name,
                "display_name": app.display_name,
                "provider": app.provider,
                "version": app.version,
                "description": app.description,
                "categories": app.categories,
                "active": app.active,
                "security_schemes": (
                    app.security_schemes
                    if has_admin_key
                    else SecuritySchemesPublic.model_validate(app.security_schemes).model_dump(
                        exclude_none=True
                    )
                ),
                "created_at": app.created_at.isoformat(),
                "updated_at": app.updated_at.isoformat(),
            }
            for app in apps
        ]
    except Exception as e:
        logger.error(f"Error listing custom apps: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list custom apps: {str(e)}"
        )


@router.get("/my-custom-functions", response_model=list[dict])
async def list_my_custom_functions(
    context: Annotated[deps.RequestContext, Depends(deps.get_request_context)],
) -> list[dict]:
    """
    List all custom functions created by the current API key holder.
    Returns only functions that were created using the JSON seeding APIs.
    """
    try:
        functions = crud.functions.get_functions_by_api_key_id(context.db_session, context.api_key_id)

        return [
            {
                "id": str(function.id),
                "name": function.name,
                "description": function.description,
                "tags": function.tags,
                "active": function.active,
                "protocol": function.protocol.value,
                "app_name": function.app_name,
                "created_at": function.created_at.isoformat(),
                "updated_at": function.updated_at.isoformat(),
            }
            for function in functions
        ]
    except Exception as e:
        logger.error(f"Error listing custom functions: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list custom functions: {str(e)}"
        )


@router.delete("/my-custom-apps/{app_id}")
async def delete_my_custom_app_by_id(
    context: Annotated[deps.RequestContext, Depends(deps.get_request_context)],
    app_id: UUID,
) -> dict:
    """
    Delete a custom app by ID if it was created by the current API key holder.
    This will also delete all functions associated with the app.
    """
    try:
        # Get the app by ID first to check if it exists and belongs to this API key
        app = crud.apps.get_app_by_id(context.db_session, app_id)

        if not app or app.api_key_id != context.api_key_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"App with ID '{app_id}' not found"
            )

        # Delete the app
        deleted = crud.apps.delete_app_by_id(context.db_session, app.id, context.api_key_id)

        if deleted:
            context.db_session.commit()
            return {
                "success": True,
                "message": f"Successfully deleted app '{app.name}'"
            }
        else:
            # Should not reach here if check above passed, but for safety
             raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"App with ID '{app_id}' not found"
            )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting custom app {app_id}: {str(e)}", exc_info=True)
        context.db_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error deleting custom app {app_id}: {str(e)}"
        )


@router.delete("/my-custom-functions/{function_name}")
async def delete_my_custom_function(
    context: Annotated[deps.RequestContext, Depends(deps.get_request_context)],
    function_name: str,
) -> dict:
    """
    Delete a custom function if it was created by the current API key holder.
    """
    try:
        # Get the function by name first to check if it exists and belongs to this API key
        function = crud.functions.get_function_by_name_and_api_key_id(context.db_session, function_name, context.api_key_id)

        if not function:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Function '{function_name}' not found"
            )

        # Delete the function
        deleted = crud.functions.delete_function_by_id(context.db_session, function.id, context.api_key_id)

        if deleted:
            context.db_session.commit()
            return {
                "success": True,
                "message": f"Successfully deleted function '{function_name}'"
            }
    except Exception as e:
        logger.error(f"Error deleting custom function {function_name}: {str(e)}")
        context.db_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete function: {str(e)}"
        )


@router.delete("/delete-all-functions/{app_name}")
async def delete_all_functions_for_app(
    context: Annotated[deps.RequestContext, Depends(deps.get_request_context)],
    app_name: str,
) -> dict:
    """
    Delete all functions for a given custom app name.
    Only works with custom apps (apps created by API keys), not system apps.
    Only deletes functions created by the current API key holder.
    """
    try:
        # Check if the app exists
        app = crud.apps.get_app_by_name_and_api_key_id(context.db_session, app_name, context.api_key_id)
        if not app:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"App '{app_name}' not found"
            )

        # Only allow deletion of custom apps (apps created by API keys)
        if app.api_key_id != context.api_key_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"App '{app_name}' is a system app and cannot be deleted via this API"
            )

        # Delete all functions for the app that were created by this API key
        deleted_count = crud.functions.delete_functions_by_app_name(
            context.db_session,
            app_name,
            context.api_key_id
        )

        context.db_session.commit()

        return {
            "success": True,
            "message": f"Successfully deleted {deleted_count} functions for custom app '{app_name}'",
            "deleted_count": deleted_count
        }

    except Exception as e:
        logger.error(f"Error deleting functions for app '{app_name}': {str(e)}")
        context.db_session.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete functions for app '{app_name}': {str(e)}"
        )
