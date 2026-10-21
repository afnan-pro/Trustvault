"""
TrustVault Configuration
All settings loaded from environment variables with secure defaults.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Base paths
BASE_DIR = Path(__file__).resolve().parent.parent
UPLOAD_DIR = BASE_DIR.parent / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

# Database — defaults to local SQLite for instant zero-dependency execution, or PostgreSQL via env
DEFAULT_DB_FILE = (BASE_DIR / "trustvault.db").as_posix()
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"sqlite+aiosqlite:///{DEFAULT_DB_FILE}"
)

# Synchronous URL for migrations / admin tools
DATABASE_URL_SYNC = os.getenv(
    "DATABASE_URL_SYNC",
    f"sqlite:///{DEFAULT_DB_FILE}"
)

# JWT Settings
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "CHANGE-ME-IN-PRODUCTION-" + os.urandom(16).hex())
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Argon2 Settings (deliberately high for security)
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_PARALLELISM = 4

# File Upload Settings
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
ALLOWED_MIME_TYPES = {
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.ms-powerpoint",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "text/plain",
    "text/csv",
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "application/zip",
}

# Encryption
FILE_ENCRYPTION_KEY = os.getenv("FILE_ENCRYPTION_KEY", os.urandom(32).hex())

# Rate Limiting
RATE_LIMIT_LOGIN = "5/minute"
RATE_LIMIT_GENERAL = "100/minute"

# CORS
DEFAULT_CORS_ORIGINS = (
    "http://localhost:8000,http://127.0.0.1:8000,"
    "http://localhost:8080,http://127.0.0.1:8080,"
    "http://localhost:5500,http://127.0.0.1:5500,"
    "http://localhost:3000,http://127.0.0.1:3000,"
    "http://localhost:5173,http://127.0.0.1:5173"
)
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv("CORS_ORIGINS", DEFAULT_CORS_ORIGINS).split(",")
    if origin.strip()
]

# Server
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))
DEBUG = os.getenv("DEBUG", "false").lower() == "true"
