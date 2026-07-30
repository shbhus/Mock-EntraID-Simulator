"""
app.py

Mock Microsoft Entra ID Simulator
---------------------------------
Main entry point for the application.

Run:
    uvicorn app:app --host 0.0.0.0 --port 8080 --reload

Swagger:
    http://localhost:8080/docs

"""

import logging
from contextlib import asynccontextmanager
from routes.discovery import router as discovery_router
from fastapi import FastAPI
from fastapi.responses import JSONResponse

from app_config import settings
from routes.token import router as token_router
from routes.jwks import router as jwks_router
from security.rsa_keys import initialize_keys

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("MockEntra")


# -----------------------------------------------------------------------------
# Application Lifecycle
# -----------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Called once when application starts.
    """

    logger.info("=" * 60)
    logger.info("Starting Mock Microsoft Entra Simulator")
    logger.info("=" * 60)

    # Generate RSA keys if not present
    initialize_keys()

    logger.info("RSA Keys Ready")
    logger.info("Application Started")

    yield

    logger.info("Application Stopped")


# -----------------------------------------------------------------------------
# FastAPI
# -----------------------------------------------------------------------------

app = FastAPI(
    title="Mock Microsoft Entra ID Simulator",
    description="""
A lightweight simulator that generates RS256 JWT access tokens
for local development and automation testing.

Phase-1 Features

✔ JWT Generation
✔ JWKS Endpoint
✔ Health Endpoint
✔ Swagger UI
✔ Automatic RSA Key Generation
""",
    version="1.0.0",
    lifespan=lifespan
)

# -----------------------------------------------------------------------------
# Register Routers
# -----------------------------------------------------------------------------


app.include_router(
    token_router,
    tags=["Token"]
)

app.include_router(
    jwks_router,
    tags=["JWKS"]
)

app.include_router(
    discovery_router,
    tags=["Discovery"]
)
# -----------------------------------------------------------------------------
# Root Endpoint
# -----------------------------------------------------------------------------

@app.get("/", summary="Application Information")
async def root():

    return {
        "application": settings.APP_NAME,
        "version": settings.VERSION,
        "issuer": settings.ISSUER,
        "status": "Running",
        "swagger": "/docs",
        "jwks": "/.well-known/jwks.json",
        "health": "/health",
        "generate_token": "/generate-token"
    }


# -----------------------------------------------------------------------------
# Global Exception Handler
# -----------------------------------------------------------------------------

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):

    logger.exception(str(exc))

    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": str(exc)
        }
    )


# -----------------------------------------------------------------------------
# Local Execution
# -----------------------------------------------------------------------------

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "app:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=True
    )