"""
FastAPI Main Application Entrypoint for ShieldX SOC
"""
from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import api_router
from app.config import settings
from app.db.init_db import init_db
from app.websocket import websocket_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("shieldx")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler for startup table verification & shutdown."""
    logger.info("Starting ShieldX SOC Enclave Backend...")
    init_db()
    logger.info("Enclave database tables verified and initialized.")
    yield
    logger.info("Shutting down ShieldX SOC Enclave Backend.")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=settings.app_description,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# ─── Strict CORS Configuration (Config-driven, NO wildcard ["*"]) ───
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# ─── Route Registration ───
app.include_router(api_router)
app.include_router(websocket_router)


# ─── Root & Health Alias Endpoints ───
@app.get("/", tags=["Root"])
def root_info():
    """Service status and OpenAPI documentation link."""
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "status": "OPERATIONAL",
        "docs": "/docs",
        "api_prefix": "/api",
    }


# ─── Global Error Handler ───
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error processing {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "INTERNAL_SERVER_ERROR",
            "message": "An unexpected error occurred in the enclave service.",
            "path": request.url.path,
        },
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.host, port=settings.port, reload=True)
