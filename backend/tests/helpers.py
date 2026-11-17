"""Shared test helpers: a real phone payload, a small model, and a dependency-free ASGI caller."""
import asyncio
import copy
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "genuine_phone.json").read_text(encoding="utf-8"))

_MODEL_DIR: Path | None = None


def phone(session_id: str = "s1", install_id: str | None = None, signals: dict | None = None,
          device: dict | None = None, app: dict | None = None, unknown: list | None = None,
          failed_groups: list | None = None, action: str | None = None, timestamp: str | None = None) -> dict:
    """The real phone payload with changes applied. Signals given here replace the phone's own."""
    p = copy.deepcopy(FIXTURE)
    p["context_keys"]["session_id"] = session_id
    if install_id:
        p["context_keys"]["install_id"] = install_id
    p["signals"].update(signals or {})
    for k in (signals or {}):
        if k in p["unknown"]:
            p["unknown"].remove(k)
    p["device"].update(device or {})
    p["app"].update(app or {})
    if unknown is not None:
        p["unknown"] = unknown
        for k in unknown:           # a signal is either measured or unknown, never both
            p["signals"].pop(k, None)
    if failed_groups is not None:
        p["failed_groups"] = failed_groups
    if action:
        p["action"] = action
    # The fixture's own scan time is old; default to "now" so tests do not trip the clock-skew rule.
    p["device"]["scan_timestamp"] = timestamp or datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")
    return p


def small_model_dir() -> Path:
    """A quickly trained model on synthetic data, built once per test run."""
    global _MODEL_DIR
    if _MODEL_DIR is None:
        import numpy as np
        from trustpoc.features import extract
        from trustpoc.ml import ShadowModels
        from trustpoc.synth import FAMILIES, generate
        sessions = generate(n_genuine=400, n_per_family=60, seed=1)
        X = np.array([extract(p) for p, _, _ in sessions], dtype=float)
        Y = {f: np.array([lab[f] for _, lab, _ in sessions]) for f in FAMILIES}
        genuine = np.array([v == "genuine" for _, _, v in sessions])
        _MODEL_DIR = Path(tempfile.mkdtemp())
        ShadowModels().fit(X, Y, genuine, {"version": "test-model", "data": "synthetic"}).save(_MODEL_DIR / "shadow_model.pkl")
    return _MODEL_DIR


def call(app, method: str, path: str, body: bytes | dict | None = None, headers: dict | None = None,
         client=("203.0.113.9", 5555)) -> tuple[int, dict]:
    """Call an ASGI app in-process. Returns (status, parsed JSON body)."""
    if isinstance(body, dict):
        body = json.dumps(body).encode()
    body = body or b""
    hdrs = {"content-type": "application/json", "user-agent": "Dalvik/2.1.0 (Linux; U; Android 16; I2221 Build/BP2A)"}
    hdrs.update({k.lower(): v for k, v in (headers or {}).items()})
    path, _, query = path.partition("?")
    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": method, "path": path,
             "raw_path": path.encode(), "query_string": query.encode(), "root_path": "", "scheme": "http",
             "headers": [(k.encode(), v.encode()) for k, v in hdrs.items()], "client": client, "server": ("test", 80)}
    sent, out = False, {"status": 0, "body": b""}

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(msg):
        if msg["type"] == "http.response.start":
            out["status"] = msg["status"]
        elif msg["type"] == "http.response.body":
            out["body"] += msg.get("body", b"")

    asyncio.run(app(scope, receive, send))
    try:
        return out["status"], json.loads(out["body"])
    except ValueError:
        return out["status"], {"raw": out["body"].decode(errors="replace")}
