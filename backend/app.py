"""Device Trust POC: scoring API and live dashboard.

Run:  uvicorn app:app --host 0.0.0.0 --port 8000
Docs: http://localhost:8000/docs     Dashboard: http://localhost:8000/
"""
import hashlib
import hmac
import json
import logging
import os
import re
import ssl
import zlib
from urllib.parse import parse_qs, unquote, urlsplit
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field
import pg8000.dbapi as pg8000
from dotenv import load_dotenv

from trustpoc.engine import Engine

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

BASE = Path(__file__).resolve().parent
load_dotenv(BASE / ".env")
CONFIG_PATH = BASE / "config.json"
DEFAULT_CONFIG = {"expected_package": ["com.example.demo"], "expected_cert_sha256": []}


def load_config() -> dict:
    if CONFIG_PATH.exists():
        return {**DEFAULT_CONFIG, **json.loads(CONFIG_PATH.read_text())}
    CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2))
    return dict(DEFAULT_CONFIG)


engine = Engine(BASE / "data", BASE / "roots", load_config())
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
DATABASE_URL = os.environ.get("DATABASE_URL", "")


def database_connection():
    """Create a PostgreSQL connection using the Neon DATABASE_URL."""
    parsed = urlsplit(DATABASE_URL)
    if parsed.scheme not in {"postgres", "postgresql"} or not parsed.hostname:
        raise ValueError("DATABASE_URL must be a PostgreSQL connection string")

    query = parse_qs(parsed.query)
    return pg8000.connect(
        user=unquote(parsed.username or ""),
        password=unquote(parsed.password or ""),
        host=parsed.hostname,
        port=parsed.port or 5432,
        database=parsed.path.lstrip("/"),
        ssl_context=ssl.create_default_context() if query.get("sslmode") else None,
    )

# Demo mode: the web app can run simulated devices server-side, so a cloud demo needs no
# terminal. It makes the simulator's test root a TRUSTED attestation root, so anyone holding
# data/sim/root_key.pem can forge "hardware attestation". Off by default; set DEMO_MODE=1
# only on a demo server that never sees real devices.
DEMO = os.environ.get("DEMO_MODE", "0") == "1"
if DEMO:
    from cryptography.hazmat.primitives import serialization
    from simulate import GENUINE_CERT, PKG as SIM_PKG, SCENARIOS, SimDevice, sim_root
    _demo = SimDevice("", "i_web_demo")
    engine.trust.root_keys.append(_demo.root.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
    engine.config["expected_cert_sha256"] = list(
        {*engine.config["expected_cert_sha256"], hashlib.sha256(GENUINE_CERT).hexdigest()})
    pkgs = engine.config.get("expected_package") or []
    pkgs = [pkgs] if isinstance(pkgs, str) else list(pkgs)
    engine.config["expected_package"] = sorted({*pkgs, SIM_PKG})
    logging.warning("DEMO_MODE=1: simulator attestation root is trusted. Never use with real devices.")

# The unsigned /v1/features report is kept only for old app builds; it lets anyone write to
# the database, so it is off unless explicitly enabled.
ALLOW_UNSIGNED = os.environ.get("ALLOW_UNSIGNED_REPORTS", "0") == "1"
# Behind a reverse proxy (Render, nginx) the client IP is in X-Forwarded-For; trust it only then.
TRUST_PROXY = os.environ.get("TRUST_PROXY", "0") == "1"
MAX_BODY = 512 * 1024          # compressed request body
MAX_INFLATED = 2 * 1024 * 1024  # after gzip, to stop decompression bombs
app = FastAPI(title="Device Trust POC", version="0.1",
              description="Attestation + rules + 5-level trust decisions. ML runs in shadow only.")


def check_database_connection() -> bool:
    """Log whether PostgreSQL is reachable when the server starts."""
    if not DATABASE_URL:
        logging.error("DATABASE_URL is not configured; database is unavailable")
        return False

    try:
        with database_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT 1")
                cursor.fetchone()
            finally:
                cursor.close()
        logging.info("Database connection successful")
        return True
    except Exception:
        logging.exception("Database connection failed")
        return False


@app.on_event("startup")
def startup_database_check():
    check_database_connection()


class NonceRequest(BaseModel):
    install_id: str = Field(max_length=64)
    action: str = Field(max_length=32)


class AssessRequest(BaseModel):
    payload: str = Field(description="base64 of the exact JSON bytes the device signed")
    signature: str = Field(description="base64 DER ECDSA signature over payload bytes")
    chain: list[str] = Field(default_factory=list, description="base64 DER certs, leaf first")


class BankCheck(BaseModel):
    decision_jws: str
    action: str


class PredictRequest(BaseModel):
    probes: dict = Field(description="probe name -> value, as the SDK reports them")
    slowdown: float = 1.0
    failed: int = 0


class TrustDigest(BaseModel):
    cert_sha256: str = Field(min_length=64, max_length=64)


def validate_feature_report(report: object) -> dict:
    """Validate the shape of the front-end device feature report."""
    if not isinstance(report, dict):
        raise HTTPException(422, "features must be a JSON object")

    required_counts = (
        "total_signals",
        "safe_count",
        "info_count",
        "suspicious_count",
        "alert_count",
    )
    missing = [key for key in required_counts if key not in report]
    if missing:
        raise HTTPException(422, f"missing feature fields: {', '.join(missing)}")

    signals = report.get("signals")
    if not isinstance(signals, list):
        raise HTTPException(422, "signals must be an array")
    if len(signals) > 10_000:
        raise HTTPException(413, "too many signals")

    return report


def sanitize_json(value):
    """Remove characters PostgreSQL JSONB cannot store, such as NUL."""
    if isinstance(value, str):
        return value.replace("\x00", "\ufffd")
    if isinstance(value, list):
        return [sanitize_json(item) for item in value]
    if isinstance(value, dict):
        return {key: sanitize_json(item) for key, item in value.items()}
    return value


def feature_report_to_probes(report: dict) -> tuple[dict, int]:
    """Adapt the front-end signal report to the model's trained probe schema."""
    signals = {
        signal.get("name"): signal
        for signal in report.get("signals", [])
        if isinstance(signal, dict) and signal.get("name")
    }

    def signal(name: str):
        return signals.get(name, {})

    def value(name: str, default=None):
        return signal(name).get("value", default)

    def text(name: str) -> str:
        return str(value(name, "")).lower()

    def positive(name: str) -> bool:
        item = signal(name)
        raw = str(item.get("value", "")).lower()
        risk = str(item.get("risk_level", "")).upper()
        if risk in {"SUSPICIOUS", "ALERT", "CRITICAL"}:
            return True
        return any(token in raw for token in (
            "true", "detected", "present", "failed", "mismatch", "unlocked",
            "permissive", "unexpected", "frida", "xposed", "magisk", "root",
        )) and not any(token in raw for token in ("not detected", "none", "false", "no "))

    def number(name: str, default=None):
        match = re.search(r"-?\d+(?:\.\d+)?", str(value(name, "")))
        return float(match.group()) if match else default

    probes = {
        "selinux_mode": value("selinux_mode"),
        "sensor_count": number("sensor_count"),
        "rt_tracer_pid": number("tracer_pid", 0),
        "rt_debugger_connected": positive("debug_connected") or positive("jdwp_active"),
        "rt_frida_maps": any(positive(name) for name in (
            "frida_agent_in_maps", "frida_gadget_in_maps", "frida_memfd_mappings",
        )),
        "rt_frida_threads": [name for name in (
            "gum_js_loop_thread", "gmain_thread", "gdbus_thread",
        ) if positive(name)],
        "rt_frida_port": positive("frida_default_port_open") or positive("frida_port_scan_any"),
        "rt_xposed": any(positive(name) for name in (
            "xposed_bridge_class", "xposed_stack_frames", "lsposed_manager_present",
        )),
        "root_su_paths": [name for name in (
            "su_path_java", "su_path_libc", "su_path_syscall",
        ) if positive(name)],
        "root_su_which": positive("su_in_PATH"),
        "root_manager_packages": [name for name in (
            "magisk_pkg_present", "kernelsu_manager_present", "apatch_manager_present",
        ) if positive(name)],
        "root_magisk_mounts": positive("magisk_mount_names") or positive("magisk_files_data_adb"),
        "root_system_rw": positive("rw_system_mount") or positive("rw_vendor_mount"),
        "root_dangerous_props": positive("ro_debuggable") or positive("boot_flash_locked_prop"),
        "props_test_keys": positive("build_tags_test_keys") or positive("test_keys_ota_certs"),
        "emu_fingerprint": any(token in text("fingerprint_soc_consistent") for token in ("ranchu", "goldfish", "emulator")),
        "emu_hardware": positive("community_emulator_share"),
        "emu_qemu_props": any(token in text(name) for name in ("fingerprint_soc_consistent", "fingerprint_model_consistent") for token in ("qemu", "goldfish")),
        "app_data_dir_ok": not positive("apk_in_unusual_dir"),
        "ctx_developer_options": positive("developer_options_on"),
        "ctx_adb_enabled": positive("usb_debugging_on") or positive("adb_wifi_on"),
        "ctx_accessibility_services": [value("accessibility_unknown_pkg")] if positive("accessibility_unknown_pkg") else [],
        "ctx_vpn": positive("vpn_active") or positive("vpn_proxy_flag"),
    }
    probes = {name: probe for name, probe in probes.items() if probe is not None}
    failed = sum(
        1 for item in report.get("signals", [])
        if isinstance(item, dict) and str(item.get("value", "")).lower() in {"error", "failed", "unavailable"}
    )
    return probes, failed


def score_feature_report(report: dict) -> tuple[dict, int]:
    """Run the existing rules + shadow ML model against a feature report."""
    probes, failed = feature_report_to_probes(report)
    logging.info(
        "model scoring started: signals=%d mapped_probes=%d failed_signals=%d",
        len(report.get("signals", [])), len(probes), failed,
    )
    try:
        result = engine.predict(probes, failed=failed)
        logging.info(
            "model scoring completed: level=%s label=%s rules_level=%s ml_level=%s",
            result.get("level"), result.get("label"),
            result.get("rules_level"), result.get("ml_level"),
        )
    except Exception:
        logging.exception("could not score feature report")
        result = {"error": "model scoring failed"}
    return result, len(probes)


def store_model_result(report_id: int, result: dict, mapped_probe_count: int) -> int:
    """Persist a model result linked to its source feature report."""
    logging.info(
        "storing model result: feature_report_id=%s mapped_probes=%d",
        report_id, mapped_probe_count,
    )
    with database_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS feature_model_results (
                    id BIGSERIAL PRIMARY KEY,
                    feature_report_id BIGINT NOT NULL REFERENCES feature_reports(id) ON DELETE CASCADE,
                    scored_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                    mapped_probe_count INTEGER NOT NULL,
                    result JSONB NOT NULL
                )
            """)
            cursor.execute(
                """
                INSERT INTO feature_model_results
                    (feature_report_id, mapped_probe_count, result)
                VALUES (%s, %s, %s)
                RETURNING id
                """,
                (report_id, mapped_probe_count, json.dumps(result, default=str)),
            )
            result_id = cursor.fetchone()[0]
            conn.commit()
            logging.info(
                "model result stored: model_result_id=%s feature_report_id=%s",
                result_id, report_id,
            )
            return result_id
        finally:
            cursor.close()


@app.post("/v1/nonce")
def nonce(req: NonceRequest):
    return engine.issue_nonce(req.install_id, req.action)


@app.post("/v1/assess")
def assess(req: AssessRequest):
    if len(req.payload) > 200_000 or len(req.chain) > 10:
        raise HTTPException(413, "payload too large")
    res = engine.assess(req.payload, req.signature, req.chain)
    if "error" in res:
        raise HTTPException(400, res["error"])
    return res


@app.get("/v1/decisions")
def decisions(limit: int = 30):
    return {"decisions": list(engine.decisions)[:max(1, min(limit, 200))],
            "config": engine.config}


@app.get("/v1/public-key", response_class=PlainTextResponse)
def public_key():
    """The bank backend verifies decision JWS with this key (ES256)."""
    return engine.signer.public_pem()


@app.post("/v1/bank/check")
def bank_check(req: BankCheck):
    """What the bank backend does before moving money (design doc 14.1)."""
    return engine.bank_check(req.decision_jws, req.action)


def check_admin(token: str, header_token: str | None = None):
    """Admin endpoints are closed unless ADMIN_TOKEN is set. Prefer the X-Admin-Token header;
    the query parameter remains for the dashboard."""
    if not ADMIN_TOKEN:
        raise HTTPException(403, "admin endpoints are disabled: set ADMIN_TOKEN")
    supplied = header_token or token
    if not supplied or not hmac.compare_digest(supplied, ADMIN_TOKEN):
        raise HTTPException(401, "admin token required")


class AssessV2Request(BaseModel):
    payload: str = Field(max_length=MAX_INFLATED, description="exact JSON text the device signed (schema 2)")
    signature: str = Field(default="", max_length=512, description="base64 DER ECDSA signature over the payload's UTF-8 bytes")
    chain: list[str] = Field(default_factory=list, max_length=10, description="base64 DER certs, leaf first")


async def read_json_body(request: Request) -> dict:
    """Read a JSON body that may be gzip-compressed, with hard size limits."""
    raw = await request.body()
    if len(raw) > MAX_BODY:
        raise HTTPException(413, "request too large")
    if request.headers.get("content-encoding", "").lower() == "gzip":
        try:
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            raw = d.decompress(raw, MAX_INFLATED)
            if d.unconsumed_tail:
                raise HTTPException(413, "decompressed request too large")
        except zlib.error as exc:
            raise HTTPException(400, "invalid gzip body") from exc
    try:
        body = json.loads(raw)
    except ValueError as exc:
        raise HTTPException(400, "body is not JSON") from exc
    if not isinstance(body, dict):
        raise HTTPException(400, "body must be a JSON object")
    return body


def client_ip_of(request: Request) -> str | None:
    if TRUST_PROXY:
        fwd = request.headers.get("x-forwarded-for", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


def store_assessment(payload_text: str, result: dict) -> None:
    """Keep every signed assessment for audit and model training. A database outage must not
    block the decision, so failures are logged, not raised."""
    if not DATABASE_URL:
        return
    try:
        with database_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS device_assessments (
                        id BIGSERIAL PRIMARY KEY,
                        received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        decision_id TEXT NOT NULL,
                        trust_level INTEGER NOT NULL,
                        payload JSONB NOT NULL,
                        result JSONB NOT NULL
                    )
                """)
                stored = {k: v for k, v in result.items() if k != "decision_jws"}
                cursor.execute(
                    "INSERT INTO device_assessments (decision_id, trust_level, payload, result) "
                    "VALUES (%s, %s, %s, %s)",
                    (result["decision_id"], result["trust_level"],
                     json.dumps(sanitize_json(json.loads(payload_text))),
                     json.dumps(sanitize_json(stored), default=str)),
                )
                conn.commit()
            finally:
                cursor.close()
    except Exception:
        logging.exception("could not store assessment %s", result.get("decision_id"))


@app.post("/v2/assess")
async def assess_v2(request: Request):
    """Signed, attested schema-2 assessment from the Android app (gzip body accepted).

    Steps: verify nonce, attestation chain, payload signature and counter; map catalogue
    signals to rules/ML probes; compute server-side signals; return a signed decision.
    """
    req = AssessV2Request.model_validate(await read_json_body(request))
    res = engine.assess_v2(req.payload, req.signature, req.chain,
                           client_ip=client_ip_of(request),
                           user_agent=request.headers.get("user-agent"))
    if "error" in res:
        raise HTTPException(400, res["error"])
    logging.info("assessment %s: level=%s rules=%s ml=%s device_signals=%s unknown=%s",
                 res["decision_id"], res["trust_level"], res["rules_level"], res["ml_level"],
                 res["coverage"]["device_signals"], res["coverage"]["unknown"])
    store_assessment(req.payload, res)
    return res


@app.post("/v1/predict")
def predict(req: PredictRequest):
    """Rules + ML on raw probe values, no attestation. Powers the "Try it" page."""
    if len(req.probes) > 100:
        raise HTTPException(413, "too many probes")
    return engine.predict(req.probes, req.slowdown, req.failed)


@app.post("/v1/features")
def receive_features(report: dict):
    """Legacy: unsigned feature report from old app builds. Disabled unless ALLOW_UNSIGNED_REPORTS=1."""
    if not ALLOW_UNSIGNED:
        raise HTTPException(410, "unsigned reports are disabled; update the app (it now uses /v2/assess)")
    logging.info(
        "feature report received: total_signals=%s signal_items=%d safe=%s info=%s suspicious=%s alert=%s",
        report.get("total_signals") if isinstance(report, dict) else None,
        len(report.get("signals", [])) if isinstance(report, dict) and isinstance(report.get("signals"), list) else 0,
        report.get("safe_count") if isinstance(report, dict) else None,
        report.get("info_count") if isinstance(report, dict) else None,
        report.get("suspicious_count") if isinstance(report, dict) else None,
        report.get("alert_count") if isinstance(report, dict) else None,
    )
    report = validate_feature_report(sanitize_json(report))
    logging.info("feature report validated successfully")
    if not DATABASE_URL:
        raise HTTPException(503, "DATABASE_URL is not configured")

    try:
        with database_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS feature_reports (
                        id BIGSERIAL PRIMARY KEY,
                        received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        report JSONB NOT NULL
                    )
                """)
                cursor.execute(
                    "INSERT INTO feature_reports (report) VALUES (%s) RETURNING id, received_at",
                    (json.dumps(report),),
                )
                row = cursor.fetchone()
                conn.commit()
                logging.info(
                    "feature report stored: feature_report_id=%s received_at=%s",
                    row[0], row[1],
                )
            finally:
                cursor.close()
    except Exception as exc:
        logging.exception("could not store feature report")
        raise HTTPException(503, "could not store feature report") from exc

    model_result, mapped_probe_count = score_feature_report(report)
    try:
        model_result_id = store_model_result(row[0], model_result, mapped_probe_count)
    except Exception as exc:
        logging.exception("could not store model result")
        raise HTTPException(503, "could not store model result") from exc

    return {
        "ok": True,
        "received": True,
        "report_id": row[0],
        "received_at": row[1],
        "model_result_id": model_result_id,
        "result": model_result,
        "model": model_result,
        "mapped_probe_count": mapped_probe_count,
    }


@app.get("/v1/features")
def get_features(token: str = "", x_admin_token: str | None = Header(default=None)):
    """Legacy: latest unsigned feature report. Contains device data, so admin only."""
    check_admin(token, x_admin_token)
    logging.info("fetching latest feature report and model result")
    if not DATABASE_URL:
        raise HTTPException(503, "DATABASE_URL is not configured")

    try:
        with database_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS feature_reports (
                        id BIGSERIAL PRIMARY KEY,
                        received_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        report JSONB NOT NULL
                    )
                """)
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS feature_model_results (
                        id BIGSERIAL PRIMARY KEY,
                        feature_report_id BIGINT NOT NULL REFERENCES feature_reports(id) ON DELETE CASCADE,
                        scored_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                        mapped_probe_count INTEGER NOT NULL,
                        result JSONB NOT NULL
                    )
                """)
                cursor.execute("""
                    SELECT fr.id, fr.received_at, fr.report,
                           mr.id, mr.scored_at, mr.result, mr.mapped_probe_count
                    FROM feature_reports AS fr
                    LEFT JOIN feature_model_results AS mr
                        ON mr.feature_report_id = fr.id
                    ORDER BY fr.id DESC, mr.id DESC
                    LIMIT 1
                """)
                row = cursor.fetchone()
            finally:
                cursor.close()
    except Exception as exc:
        logging.exception("could not read feature reports")
        raise HTTPException(503, "could not read feature reports") from exc

    model_result = row[5] if row else None
    mapped_probe_count = row[6] if row else 0
    logging.info(
        "latest feature lookup complete: feature_report_id=%s model_result_id=%s mapped_probes=%s",
        row[0] if row else None, row[3] if row else None, mapped_probe_count,
    )

    return {
        "ok": True,
        "received": row is not None,
        "report_id": row[0] if row else None,
        "received_at": row[1] if row else None,
        "features": row[2] if row else None,
        "model_result_id": row[3] if row else None,
        "scored_at": row[4] if row else None,
        "result": model_result,
        "model": model_result,
        "mapped_probe_count": mapped_probe_count,
    }


@app.post("/v1/demo/{scenario}")
def demo(scenario: str):
    """Run one simulated device end to end (nonce, attestation, signature, decision)."""
    if not DEMO:
        raise HTTPException(404, "demo mode is off")
    if scenario not in SCENARIOS:
        raise HTTPException(404, f"unknown scenario; one of {list(SCENARIOS)}")
    sc = SCENARIOS[scenario]
    body = _demo.build(sc, engine.issue_nonce(_demo.install_id, sc["action"])["nonce"])
    res = engine.assess(body["payload"], body["signature"], body["chain"])
    if sc.get("replay"):  # send the exact same signed request again
        res = engine.assess(body["payload"], body["signature"], body["chain"])
    return {**res, "scenario": sc["title"]}


@app.get("/v1/demo")
def demo_list():
    return {"enabled": DEMO, "scenarios": {k: v["title"] for k, v in SCENARIOS.items()} if DEMO else {}}


@app.post("/v1/admin/trust-digest")
def trust_digest(req: TrustDigest, token: str = "", x_admin_token: str | None = Header(default=None)):
    """Mark a genuine build's signing-certificate digest as expected (admin only)."""
    check_admin(token, x_admin_token)
    d = req.cert_sha256.lower()
    if any(c not in "0123456789abcdef" for c in d):
        raise HTTPException(400, "not a hex sha256")
    cfg = engine.config
    if d not in cfg["expected_cert_sha256"]:
        cfg["expected_cert_sha256"].append(d)
        CONFIG_PATH.write_text(json.dumps(cfg, indent=2))
    return cfg


@app.post("/v1/admin/reset")
def reset(token: str = "", x_admin_token: str | None = Header(default=None)):
    check_admin(token, x_admin_token)
    engine.decisions.clear()
    engine.counters.clear()
    return {"ok": True}


@app.get("/v1/ml/report")
def ml_report():
    """Shadow-model evaluation (synthetic data unless real sessions were added)."""
    return {"loaded": engine.shadow is not None, "report": engine.ml_report,
            "thresholds": engine.shadow.thresholds if engine.shadow else None}


@app.get("/", response_class=HTMLResponse)
def dashboard():
    return (BASE / "dashboard.html").read_text(encoding="utf-8")


@app.get("/app", response_class=HTMLResponse)
@app.get("/app/", response_class=HTMLResponse)
def web_bank_app():
    """Browser version of the Android demo banking screen.

    Browsers cannot provide Android Key Attestation, so this client deliberately
    uses the reduced-assurance probe endpoint instead of claiming native trust.
    """
    return (BASE / "web" / "index.html").read_text(encoding="utf-8")
