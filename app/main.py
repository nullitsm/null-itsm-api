"""NULL ITSM API — FastAPI application entrypoint (modular monolith).

Versioned API under /api/v1. OpenAPI docs at /docs and /openapi.json.
"""

from __future__ import annotations

import logging
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.config import get_settings
from app.rate_limit import limiter
from app.routers import agents as agents_router
from app.routers import assets as assets_router
from app.routers import audit as audit_router
from app.routers import auth as auth_router
from app.routers import catalog as catalog_router
from app.routers import changes as changes_router
from app.routers import cmdb as cmdb_router
from app.routers import email as email_router
from app.routers import endpoints as endpoints_router
from app.routers import exports as exports_router
from app.routers import health as health_router
from app.routers import identity as identity_router
from app.routers import imports as imports_router
from app.routers import knowledge as knowledge_router
from app.routers import network as network_router
from app.routers import notifications as notifications_router
from app.routers import organizations as org_router
from app.routers import patching as patching_router
from app.routers import platform as platform_router
from app.routers import portal as portal_router
from app.routers import problems as problems_router
from app.routers import requests as requests_router
from app.routers import roles as roles_router
from app.routers import sla as sla_router
from app.routers import tickets as tickets_router
from app.routers import users as users_router
from app.routers import vulnerabilities as vulnerabilities_router

settings = get_settings()

logging.basicConfig(
    level=logging.DEBUG if settings.debug else logging.INFO,
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "logger": "%(name)s", "message": "%(message)s"}',
)
logger = logging.getLogger("null.api")

app = FastAPI(
    title="NULL ITSM API",
    version="0.1.0",
    description=(
        "Multi-tenant enterprise ITSM platform API. "
        "All tenant-owned data is isolated by organization_id and PostgreSQL "
        "Row-Level Security; the API never trusts a client-supplied org id."
    ),
    openapi_url="/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS: development origins only by default. Production sets
# NULL_CORS_ORIGINS explicitly (the GitHub Pages frontend origin).
_cors_origins = (
    ["http://localhost:5173", "http://localhost:8000", "http://127.0.0.1:8000"] if settings.env == "development" else []
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Organization-Id", "X-Request-Id"],
)


@app.middleware("http")
async def request_id_and_logging(request: Request, call_next):
    request_id = request.headers.get("X-Request-Id") or str(uuid.uuid4())
    start = time.monotonic()
    response = await call_next(request)
    elapsed_ms = int((time.monotonic() - start) * 1000)
    response.headers["X-Request-Id"] = request_id
    logger.info(
        "%s %s -> %s (%dms) request_id=%s",
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
        request_id,
    )
    return response


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"detail": "Validation error", "errors": exc.errors()},
    )


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


app.include_router(health_router.router)
app.include_router(auth_router.router)
app.include_router(org_router.router)
app.include_router(users_router.router)
app.include_router(roles_router.router)
app.include_router(audit_router.router)
app.include_router(tickets_router.router)
app.include_router(platform_router.router)
# Phase 2 routers (stubs until each workstream lands its endpoints).
app.include_router(requests_router.router)
app.include_router(catalog_router.router)
app.include_router(knowledge_router.router)
app.include_router(changes_router.router)
app.include_router(problems_router.router)
app.include_router(notifications_router.router)
app.include_router(sla_router.router)
app.include_router(email_router.router)
app.include_router(portal_router.router)
app.include_router(imports_router.router)
app.include_router(exports_router.router)
app.include_router(identity_router.router)
app.include_router(assets_router.router)
# Phase 3 routers (agent/endpoints, patching, vulnerabilities, CMDB, network).
app.include_router(agents_router.router)
app.include_router(endpoints_router.router)
app.include_router(patching_router.router)
app.include_router(vulnerabilities_router.router)
app.include_router(cmdb_router.router)
app.include_router(network_router.router)


@app.get("/", include_in_schema=False)
def root():
    return {"service": "null-itsm-api", "version": "0.1.0", "docs": "/docs"}
