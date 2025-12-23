from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from .error import ClientError, ServerError
import logging

logger = logging.getLogger(__name__)


async def handle_client_error(request: Request, exc: ClientError):
    error_dict = {"code": exc.base_error.code, "message": exc.base_error.message}
    logger.warning(f"Client error: {error_dict}")
    return JSONResponse(status_code=exc.status_code, content={"error": error_dict})


async def handle_server_error(request: Request, exc: ServerError):
    error_dict = {"code": exc.base_error.code, "message": "Internal server error"}
    logger.error(f"Server error: {exc.base_error.code}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content={"error": error_dict}
    )


def create_app(ApplicationConfig) -> FastAPI:
    app = FastAPI(title="API", version="0.1.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=ApplicationConfig.CORS_ORIGINS,
        allow_credentials=ApplicationConfig.CORS_ALLOW_CREDENTIALS,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    from src.api.routes import admin, audit, auth, health_check, invitation, sessions, tenant, user

    app.include_router(health_check.router, tags=["Health"])
    app.include_router(auth.router, tags=["Authentication"])
    app.include_router(user.router, tags=["User"])
    app.include_router(tenant.router, tags=["Tenant"])
    app.include_router(invitation.router, tags=["Invitations"])
    app.include_router(sessions.router, tags=["Sessions"])
    app.include_router(audit.router, tags=["Audit"])
    app.include_router(admin.router, tags=["Admin"])

    app.add_exception_handler(ClientError, handle_client_error)
    app.add_exception_handler(ServerError, handle_server_error)

    return app
