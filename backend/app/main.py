"""
CloudGuard — Cloud Security & Network Troubleshooting Intelligence Platform.
Main application entry point.
"""
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

from app.core.config import settings
from app.core.database import engine, Base
from app.core.logging_config import logger
from app.api.router import api_router

# Initialize database schema
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=(
        "Production-style educational platform for investigating network connectivity problems, "
        "inspecting HTTP/HTTPS responses, analyzing DNS resolution, reviewing TLS certificate validity, "
        "and evaluating AWS cloud security group least-privilege configurations."
    ),
    openapi_url=f"{settings.API_V1_PREFIX}/openapi.json",
    docs_url=f"{settings.API_V1_PREFIX}/docs",
    redoc_url=f"{settings.API_V1_PREFIX}/redoc",
)

# CORS middleware for React frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def log_requests_middleware(request: Request, call_next):
    """Sanitized access log middleware."""
    logger.info(f"Incoming {request.method} {request.url.path}")
    try:
        response = await call_next(request)
        logger.info(f"Completed {request.method} {request.url.path} with status {response.status_code}")
        return response
    except Exception as exc:
        logger.error(f"Unhandled exception processing {request.method} {request.url.path}: {str(exc)}")
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal Server Error",
                "message": "An unexpected error occurred while processing the diagnostic request."
            }
        )


# Global exception handler to prevent leaking stack traces
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global unhandled error: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected internal error occurred."
        }
    )


# Mount API routes
app.include_router(api_router, prefix=settings.API_V1_PREFIX)


@app.get("/")
def root():
    return {
        "platform": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "docs": f"{settings.API_V1_PREFIX}/docs",
        "health": f"{settings.API_V1_PREFIX}/health",
        "notice": "Educational and diagnostic platform designed for security engineering operations."
    }


if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
