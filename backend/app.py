"""Entry point.   uvicorn app:app --host 0.0.0.0 --port 8000

Settings come from the environment (a `.env` file next to this file is loaded if present):
DATABASE_URL, DB_SCHEMA, ADMIN_TOKEN, COLLECT_API_KEY, ML_MODE, TRUST_PROXY, MAX_BODY_KB, STORE.
See docs/USAGE.md. API docs: /docs
"""
import logging
from pathlib import Path

from dotenv import load_dotenv

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
load_dotenv(Path(__file__).resolve().parent / ".env")

from trustpoc.api import create_app  # noqa: E402  (after load_dotenv so settings see the .env)

app = create_app()
