"""
Main Application Entrypoint — TrustVault
Secure document sharing platform with cryptographic tamper-evident audit trails.
"""
import time
import os, sys
# Ensure the "app" package inside the backend directory is importable
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict

from fastapi import FastAPI, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import JSONResponse

from app.config import CORS_ORIGINS, BASE_DIR
from app.database import init_db, async_session_factory
from app.seed import seed_database
from app.routers import auth, documents, permissions, audit, users, ai

# Rate limiting storage: IP -> list of timestamps
_rate_limits: Dict[str, list[float]] = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup & shutdown events."""
    # Initialize DB schema
    await init_db()
    # Seed default data if empty
    async with async_session_factory() as session:
        await seed_database(session)
    yield


app = FastAPI(
    title="TrustVault API",
    description="High-Assurance Secure Document Sharing with Real-Time Cryptographic Audit Trails",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS if CORS_ORIGINS != ["*"] else ["*"],
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers_and_rate_limit_middleware(request: Request, call_next):
    """
    Apply defensive HTTP security headers and enforce brute-force rate limits on authentication.
    """
    client_ip = request.client.host if request.client else "unknown"
    path = request.url.path

    # Rate limiting on auth endpoints: max 5 requests per 60 seconds per IP
    if path in ("/api/auth/login", "/api/auth/signup", "/api/auth/reset-password") and request.method == "POST":
        now = time.time()
        timestamps = _rate_limits.setdefault(client_ip, [])
        # Prune older than 60s
        timestamps = [t for t in timestamps if now - t < 60]
        _rate_limits[client_ip] = timestamps

        if len(timestamps) >= 5:
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Too many failed login attempts. Please wait 60 seconds before trying again."},
                headers={"Retry-After": "60"}
            )
        timestamps.append(now)

    response: Response = await call_next(request)

    # Security Headers (OWASP Top 10 defenses)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' blob:; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: blob:; "
        "connect-src 'self' http://localhost:* http://127.0.0.1:* ws: wss: blob:"
    )

    return response


# Register Routers
app.include_router(auth.router)
app.include_router(documents.router)
app.include_router(permissions.router)
app.include_router(audit.router)
app.include_router(users.router)
app.include_router(ai.router)


@app.get("/api/health")
async def health_check():
    """System health check endpoint."""
    return {
        "status": "healthy",
        "service": "TrustVault",
        "cryptographic_hash_engine": "SHA-256 Chained",
        "encryption_algorithm": "AES-256-GCM",
        "auth_engine": "Argon2id + JWT + TokenGenerationInvalidator",
    }


# Mount Static Frontend
FRONTEND_DIR = BASE_DIR.parent / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
