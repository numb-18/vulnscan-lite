import os
from pathlib import Path

# Base directories
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
STATIC_DIR = BASE_DIR / "static"
REPORTS_DIR = BASE_DIR / "reports"

# Ensure runtime directories exist
DATA_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

# SQLite Database
DATABASE_URL = f"sqlite:///{DATA_DIR / 'vulnscan.db'}"
DB_PATH = DATA_DIR / "vulnscan.db"

# Server Configuration
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", 8000))
DEBUG = os.getenv("DEBUG", "true").lower() == "true"

# Redis & Celery Configuration (Optional, falls back to async background worker)
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
USE_CELERY = os.getenv("USE_CELERY", "false").lower() == "true"

# Scanner Engine Limits
SCAN_TIMEOUT_SECONDS = int(os.getenv("SCAN_TIMEOUT_SECONDS", 15))
USER_AGENT = "VulnScanLite/1.0 (Passive Web Security Posture Auditor; +https://github.com/vulnscan-lite)"
MAX_CONCURRENT_SCANS = 5
