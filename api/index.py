"""
Vercel Serverless Function entrypoint for TrustVault FastAPI application.
"""
import sys
import os

# Add backend directory to sys.path so app modules can be resolved
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "..", "backend"))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.main import app
