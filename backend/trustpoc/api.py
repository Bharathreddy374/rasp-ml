"""HTTP layer. Five endpoints, nothing else.

  GET  /health               liveness + database + model status                (open)
  POST /v1/collect           receive a rasp_collect_v2 payload, run the pipeline,
                             store everything, return the decision             (COLLECT_API_KEY if set)
  GET  /v1/sessions/{id}     one stored session: payload, retrievals, result   (admin)
  GET  /v1/sessions          list sessions, filter by install_id / min_level   (admin)
  GET  /v1/model             model card: features, thresholds, evaluation      (admin)

Admin endpoints return 403 until ADMIN_TOKEN is set; send it as `X-Admin-Token`.
The pipeline itself is in trustpoc/pipeline.py; this module only does I/O, limits and auth.
"""
import hmac
import json
import logging
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import ValidationError

from .pipeline import Pipeline
from .geo import GeoIP
from .retrieval import PROXY_HEADERS, Request as RequestFacts
from .schema import CollectPayload
from .scoring import ModelService
from .store import MemoryStore, PostgresStore, Store, StoreError

log = logging.getLogger("trustpoc")
BASE = Path(__file__).resolve().parent.parent
DEFAULT_CONFIG = {"expected_cert_sha256": [], "release_manifests": []}


@dataclass
class Settings:
    store: str = "postgres"                 # postgres | memory
    database_url: str = ""
    db_schema: str = "public"
    admin_token: str = ""
    collect_api_key: str = ""
    ml_mode: str = "enforce"                # enforce | shadow
    trust_proxy: bool = False
    max_body_kb: int = 256
    data_dir: Path = BASE / "data"
    config_path: Path = BASE / "config.json"

    @staticmethod
    def from_env() -> "Settings":
        e = os.environ.get
        return Settings(
            store=e("STORE", "postgres"), database_url=e("DATABASE_URL", ""), db_schema=e("DB_SCHEMA", "public"),
            admin_token=e("ADMIN_TOKEN", ""), collect_api_key=e("COLLECT_API_KEY", ""),
            ml_mode=e("ML_MODE", "enforce"), trust_proxy=e("TRUST_PROXY", "0") == "1",
            max_body_kb=int(e("MAX_BODY_KB", "256")),
        )


def load_config(path: Path) -> dict:
    return {**DEFAULT_CONFIG, **json.loads(path.read_text())} if path.exists() else dict(DEFAULT_CONFIG)


def build_store(s: Settings) -> Store:
    if s.store == "memory":
        log.warning("STORE=memory: results are lost on restart. Development and tests only.")
        return MemoryStore()
    if not s.database_url:
        raise RuntimeError("DATABASE_URL is not set. Set it, or set STORE=memory for a throwaway run.")
    return PostgresStore(s.database_url, s.db_schema)


def create_app(settings: Settings | None = None, store: Store | None = None,
               model: ModelService | None = None) -> FastAPI:
    s = settings or Settings.from_env()
    store = store or build_store(s)
    model = model or ModelService(s.data_dir, s.ml_mode)
    geo = GeoIP(s.data_dir / "geo")
    pipeline = Pipeline(store, model, load_config(s.config_path), geo)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        await run_in_threadpool(store.migrate)  # fail fast: the service must not start without its tables
        log.info("ready: store=%s model=%s mode=%s", s.store, "loaded" if model.models else "missing", model.mode)
        yield

    app = FastAPI(title="Device trust collector", version="3.0", lifespan=lifespan,
                  description="Receives rasp_collect_v2 payloads, scores them with rules and an ML model, "
                              "and stores the session and the result.")

    def require_admin(token: str | None) -> None:
        if not s.admin_token:
            raise HTTPException(403, "admin endpoints are disabled: set ADMIN_TOKEN")
        if not token or not hmac.compare_digest(token, s.admin_token):
            raise HTTPException(401, "invalid admin token")

    def client_ip(request: Request) -> str | None:
        if s.trust_proxy:
            # The trusted proxy APPENDS the address it saw, so take the last entry. Earlier entries
            # come from the client and can be forged.
            forwarded = request.headers.get("x-forwarded-for", "")
            if forwarded.strip():
                return forwarded.split(",")[-1].strip()
        return request.client.host if request.client else None

    @app.get("/health")
    def health():
        db = store.ping()
        body = {"status": "ok" if db else "degraded", "database": "ok" if db else "unreachable",
                "model": "loaded" if model.models else "missing", "ml_mode": model.mode, "geo_data": geo.available}
        if not db:
            raise HTTPException(503, body)
        return body

    @app.post("/v1/collect")
    async def collect(request: Request, x_api_key: str | None = Header(default=None)):
        if s.collect_api_key and not (x_api_key and hmac.compare_digest(x_api_key, s.collect_api_key)):
            raise HTTPException(401, "invalid or missing X-Api-Key")
        raw = await request.body()
        if len(raw) > s.max_body_kb * 1024:
            raise HTTPException(413, f"payload larger than {s.max_body_kb} KB")
        try:
            payload = CollectPayload.model_validate_json(raw)
        except ValidationError as exc:
            raise HTTPException(422, [{"field": ".".join(str(p) for p in e["loc"]), "problem": e["msg"]}
                                      for e in exc.errors(include_url=False, include_context=False, include_input=False)]) from exc
        names = [k.decode("latin-1").lower() for k, _ in request.headers.raw]
        added_by_proxy = set(PROXY_HEADERS) | {"x-ja3-hash"} if s.trust_proxy else set()
        facts = RequestFacts(
            client_ip=client_ip(request), user_agent=request.headers.get("user-agent"), payload_bytes=len(raw),
            header_names=[n for n in names if n not in added_by_proxy],
            # behind a trusted proxy its own headers are expected; otherwise they mean the client used a proxy
            proxy_headers=[] if s.trust_proxy else [n for n in PROXY_HEADERS if n in names],
            ja3=(request.headers.get("x-ja3-hash") or None) if s.trust_proxy else None)
        try:
            result = await run_in_threadpool(pipeline.run, payload, facts)
        except StoreError as exc:
            log.error("storage failed: %s", exc)
            # Nothing was stored, so the client may retry the same session_id safely.
            raise HTTPException(503, "storage unavailable; retry the same session_id") from exc
        d = result["decision"]
        log.info("session %s install=%s level=%s (rules %s, ml %s) outcome=%s duplicate=%s",
                 result["id"], result["install_id"], d["level"], d["rules_level"], d["ml_level"],
                 d["outcome"], result["duplicate"])
        return result

    @app.get("/v1/sessions/{pk}")
    def get_session(pk: str, x_admin_token: str | None = Header(default=None)):
        require_admin(x_admin_token)
        record = store.get(pk)
        if record is None:
            raise HTTPException(404, "no such session")
        return record

    @app.get("/v1/sessions")
    def list_sessions(install_id: str | None = None, min_level: int | None = Query(default=None, ge=1, le=5),
                      limit: int = Query(default=50, ge=1, le=500), x_admin_token: str | None = Header(default=None)):
        require_admin(x_admin_token)
        return {"sessions": store.list_sessions(install_id, min_level, limit)}

    @app.get("/v1/model")
    def model_card(x_admin_token: str | None = Header(default=None)):
        require_admin(x_admin_token)
        return model.info()

    return app
