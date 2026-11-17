"""Nonce store, payload verification, scoring and signed decisions.

Framework-free so it can be unit-tested and reused from any web framework.
"""
import base64
import json
import logging
import os
import secrets
import threading
import time
import uuid
from collections import deque
from pathlib import Path

import jwt
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from cryptography import x509

from . import attestation, rules, server_signals, signals

NONCE_TTL_S = 60
DECISION_TTL_S = 300


def _intermediate_serial(chain_b64: list[str]) -> str | None:
    """Serial of the first certificate above the leaf: shared keyboxes show up as one serial on many installs."""
    if len(chain_b64 or []) < 2:
        return None
    try:
        return format(x509.load_der_x509_certificate(base64.b64decode(chain_b64[1])).serial_number, "x")
    except Exception:  # noqa: BLE001
        return None


class NonceStore:
    """Single-use nonces bound to install_id and action (design doc 14.1)."""

    def __init__(self, ttl: int = NONCE_TTL_S):
        self.ttl = ttl
        self._lock = threading.Lock()
        self._items: dict[str, tuple[str, str, float]] = {}

    def issue(self, install_id: str, action: str) -> str:
        nonce = base64.b64encode(secrets.token_bytes(32)).decode()
        with self._lock:
            now = time.time()
            self._items = {k: v for k, v in self._items.items() if v[2] > now}
            self._items[nonce] = (install_id, action, now + self.ttl)
        return nonce

    def consume(self, nonce: str) -> tuple[str, str] | None:
        with self._lock:
            item = self._items.pop(nonce, None)  # deleted on first use
        if item is None or item[2] < time.time():
            return None
        return item[0], item[1]


class Signer:
    """ES256 key for signing decisions. Persisted so the bank demo keeps working."""

    def __init__(self, key_path: Path):
        if key_path.exists():
            self.key = serialization.load_pem_private_key(key_path.read_bytes(), None)
        else:
            self.key = ec.generate_private_key(ec.SECP256R1())
            key_path.parent.mkdir(parents=True, exist_ok=True)
            key_path.write_bytes(self.key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption()))
            os.chmod(key_path, 0o600)
        self.kid = attestation.sha256_hex(self.public_pem().encode())[:16]

    def public_pem(self) -> str:
        return self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()

    def sign(self, claims: dict) -> str:
        return jwt.encode(claims, self.key, algorithm="ES256", headers={"kid": self.kid})

    def verify(self, token: str) -> dict:
        return jwt.decode(token, self.key.public_key(), algorithms=["ES256"])


class Engine:
    def __init__(self, data_dir: Path, roots_dir: Path, config: dict, fetch_revocations: bool = True):
        self.config = config
        self.nonces = NonceStore()
        self.signer = Signer(data_dir / "decision_key.pem")
        self.trust = attestation.TrustStore(roots_dir, fetch_revocations=fetch_revocations)
        self.decisions: deque[dict] = deque(maxlen=200)
        self.data_dir = data_dir
        self.shadow = None
        self.ml_report = None
        try:  # ML is optional: the service runs rules-only without scikit-learn or a model
            from .ml import ShadowModels
            self.shadow = ShadowModels.load(data_dir / "shadow_model.pkl")
            rep = data_dir / "ml_report.json"
            self.ml_report = json.loads(rep.read_text()) if rep.exists() else None
        except Exception as e:  # noqa: BLE001
            logging.getLogger(__name__).warning("ML shadow disabled: %s", e)
        self.counters: dict[str, int] = {}
        self.history = server_signals.HistoryStore()
        self._lock = threading.Lock()

    # ---- request handling ----
    def issue_nonce(self, install_id: str, action: str) -> dict:
        return {"nonce": self.nonces.issue(install_id, action), "ttl_s": NONCE_TTL_S}

    def assess(self, payload_b64: str, signature_b64: str, chain_b64: list[str]) -> dict:
        """Schema-1 entry point (simulator, web demo): payload is base64 of the signed JSON."""
        try:
            payload_bytes = base64.b64decode(payload_b64)
            payload = json.loads(payload_bytes)
        except Exception:  # noqa: BLE001
            return {"error": "payload is not base64 JSON"}
        if not isinstance(payload, dict):
            return {"error": "payload must be a JSON object"}
        record, token = self._decide(payload_bytes, payload, signature_b64, chain_b64)
        return {
            "decision_jws": token,
            "trust_level": record["trust_level"],
            "outcome": record["outcome"],
            "decision_id": record["decision_id"],
            "server_ms": record["server_ms"],
        }

    def assess_v2(self, payload_text: str, signature_b64: str, chain_b64: list[str],
                  client_ip: str | None = None, user_agent: str | None = None) -> dict:
        """Schema-2 entry point (Android app): payload is the exact JSON text that was signed.

        Device signals arrive as catalogue IDs with the probe's own verdict; they are mapped to
        the rules/ML probes here. Server-side signals are computed from the request and history.
        """
        payload_bytes = payload_text.encode("utf-8")
        try:
            payload = json.loads(payload_text)
        except Exception:  # noqa: BLE001
            return {"error": "payload is not JSON"}
        if not isinstance(payload, dict):
            return {"error": "payload must be a JSON object"}
        if payload.get("schema") != 2:
            return {"error": "expected payload schema 2"}
        record, token = self._decide(payload_bytes, payload, signature_b64, chain_b64,
                                     client_ip=client_ip, user_agent=user_agent)
        return {
            "decision_jws": token,
            "decision_id": record["decision_id"],
            "trust_level": record["trust_level"],
            "label": record["label"],
            "outcome": record["outcome"],
            "rules_level": record["rules_level"],
            "ml_level": record["ml_level"],
            "reasons": record["reasons_detail"] + (
                [{"code": "ML_RISK", "tier": "ML", "text": rules.REASONS["ML_RISK"]}]
                if "ML_RISK" in record["reasons"] else []),
            "reduced_assurance": record["reduced_assurance"],
            "attestation": record["attestation"],
            "server_signals": record["server_signals"],
            "unmapped_alerts": record["unmapped_alerts"],
            "coverage": record["coverage"],
            "server_ms": record["server_ms"],
        }

    def _decide(self, payload_bytes: bytes, payload: dict, signature_b64: str, chain_b64: list[str],
                client_ip: str | None = None, user_agent: str | None = None) -> tuple[dict, str]:
        started = time.perf_counter()
        ev = rules.Evidence()
        converted = None
        if payload.get("schema") == 2:
            converted = signals.to_probes(payload)
            payload = {**payload, "probes": converted.probes}  # signature still covers payload_bytes
            if converted.unmapped_alerts:
                ev.add("C", "DV_UNMAPPED_ALERTS")

        install_id = str(payload.get("install_id", ""))[:64]
        action = str(payload.get("action", ""))[:32]

        # 1. Nonce: single use, bound to install and action
        bound = self.nonces.consume(str(payload.get("nonce", "")))
        if bound is None:
            ev.add("A", "AT_NONCE_INVALID")
        elif bound != (install_id, action):
            ev.add("A", "AT_NONCE_BINDING")

        # 2. Attestation chain + challenge
        att = attestation.verify_chain(chain_b64, self.trust) if chain_b64 else None
        if att is not None and att.chain_valid:
            try:
                expected_challenge = base64.b64decode(payload.get("nonce", ""))
            except Exception:  # noqa: BLE001
                expected_challenge = b""
            if att.challenge != expected_challenge:
                ev.add("A", "AT_CHALLENGE_MISMATCH")

        # 3. Payload signature with the attested key (proves origin, not truth)
        if att is not None and att.leaf_public_key is not None:
            try:
                att.leaf_public_key.verify(base64.b64decode(signature_b64), payload_bytes,
                                           ec.ECDSA(hashes.SHA256()))
            except (InvalidSignature, ValueError, TypeError):
                ev.add("A", "AT_PAYLOAD_SIGNATURE_INVALID")

        # 4. Counter must strictly increase per install
        counter = payload.get("counter")
        with self._lock:
            last = self.counters.get(install_id, -1)
            if isinstance(counter, int) and counter > last:
                self.counters[install_id] = counter
            elif isinstance(counter, int):
                ev.add("C", "AT_COUNTER_REGRESSED")

        rules.evaluate_attestation(att, payload, self.config, ev)
        rules.evaluate_probes(payload, ev)
        if os.environ.get("STRICT_HARDENING", "0") == "1" and action in {
                "login", "add_payee", "transfer", "high_value_transfer"}:
            if att is None or not att.trustworthy or not att.hardware_backed:
                ev.add("A", "AT_HARDWARE_REQUIRED")

        apk_match = props_mismatch = None
        if converted is not None:
            apk_match = signals.apk_matches_release(payload, self.config.get("release_manifests") or [])
            if apk_match is False:
                ev.add("B", "AP_CODE_MISMATCH")
            props_mismatch = signals.props_vs_attestation(payload, att)
            if props_mismatch:
                ev.add("C", "DV_PROPS_VS_ATTESTATION")

        # Server-side signals: what this server observes and remembers, never what the phone says.
        inter_serial = _intermediate_serial(chain_b64)
        server = self.history.compute(payload, att, client_ip, user_agent, inter_serial)
        if props_mismatch is not None:
            server["F025"] = props_mismatch
        if apk_match is not None:
            server["F088"] = not apk_match  # code / native libs differ from every configured release
        for fid, code in server_signals.HISTORY_REASONS.items():
            if server.get(fid) is True:
                ev.add("C", code)
        rules_level = rules.decide_level(ev)

        # ML decides, rules guard: final = max(rules, ML). A model can raise risk but never
        # override hard evidence. If the model fails, the rules level stands (flagged degraded).
        ml = None
        if self.shadow is not None:
            try:
                ml = self.shadow.score_payload(payload, rules_level)
            except Exception as e:  # noqa: BLE001  model failure must not break scoring
                ml = {"error": type(e).__name__}
        ml_level = ml.get("ml_level") if ml and "error" not in ml else None
        level = max(rules_level, ml_level or 1)
        self._log_session(payload, rules_level, ev)

        now = int(time.time())
        claims = {
            "decision_id": "d_" + uuid.uuid4().hex[:16],
            "install_id": install_id,
            "action": action,
            "nonce": payload.get("nonce"),
            "trust_level": level,
            "label": rules.LABELS[level],
            "reasons": [r["code"] for r in rules.reasons(ev)] + (["ML_RISK"] if level > rules_level else []),
            "reduced_assurance": ev.reduced_assurance,
            "degraded": ml is not None and ml_level is None,
            "iat": now,
            "exp": now + DECISION_TTL_S,
        }
        token = self.signer.sign(claims)
        elapsed_ms = round((time.perf_counter() - started) * 1000, 1)

        record = {
            **claims,
            "rules_level": rules_level,
            "ml_level": ml_level,
            "reasons_detail": rules.reasons(ev),
            "outcome": rules.policy_outcome(action, level),
            "device": payload.get("device", {}),
            "app": payload.get("app", {}),
            "attestation": att.summary() if att else None,
            "server_ms": elapsed_ms,
            "developer_class": ev.developer_class,
            "ml": ml,
            "inputs": sorted(k for k, v in (payload.get("probes") or {}).items()
                             if isinstance(v, dict) and v.get("status") == "ok" and v.get("v")
                             and k not in ("sensor_count", "selinux_mode", "app_data_dir_ok")),
            "simulated": "(simulated)" in str((payload.get("device") or {}).get("model", "")),
            "server_signals": server,
            "unmapped_alerts": converted.unmapped_alerts if converted else [],
            "coverage": {
                "schema": payload.get("schema"),
                "device_signals": converted.device_signals if converted else len(payload.get("probes") or {}),
                "unknown": len(converted.unknown) if converted else 0,
                "mapped_probes": len(payload.get("probes") or {}),
                "server_signals": len(server),
            },
        }
        self.history.record(payload, att, client_ip, inter_serial, level,
                            len(ev.tier_a) + len(ev.tier_b) + len(ev.tier_c))
        self.decisions.appendleft(record)
        return record, token

    def predict(self, probes: dict, slowdown: float = 1.0, failed: int = 0) -> dict:
        """Score raw probe values with rules + ML, no attestation. Powers the "Try it" page.
        slowdown scales probe timings (hooks make calls slower); failed adds blocked probes."""
        ms = 0.3 * min(max(slowdown, 0.1), 10)
        payload = {"probes": {k: {"status": "ok", "v": v, "ms": ms} for k, v in probes.items()}}
        for i in range(min(max(failed, 0), 20)):
            payload["probes"][f"blocked_{i}"] = {"status": "error", "ms": ms}
        ev = rules.Evidence()
        rules.evaluate_probes(payload, ev)
        rules_level = rules.decide_level(ev)
        ml = self.shadow.score_payload(payload, rules_level) if self.shadow else None
        level = max(rules_level, ml["ml_level"] if ml else 1)
        return {"level": level, "label": rules.LABELS[level], "rules_level": rules_level,
                "ml_level": ml["ml_level"] if ml else None, "reasons": rules.reasons(ev), "ml": ml}

    def _log_session(self, payload: dict, level: int, ev) -> None:
        """Append the feature vector for future training (data collection, design doc 10)."""
        if "(simulated)" in str((payload.get("device") or {}).get("model", "")):
            return  # simulated devices must never become "real" training data
        try:
            from .features import extract
            feats = [None if isinstance(v, float) and v != v else v for v in extract(payload)]
            row = {"ts": int(time.time()), "install_id": str(payload.get("install_id", ""))[:64],
                   "rules_level": level, "reasons": ev.tier_a + ev.tier_b + ev.tier_c, "features": feats}
            if payload.get("schema") == 2:  # keep every catalogue signal for future, wider models
                row["signals"] = payload.get("signals")
                row["unknown"] = payload.get("unknown")
            self.data_dir.mkdir(parents=True, exist_ok=True)
            with open(self.data_dir / "sessions.jsonl", "a") as f:
                f.write(json.dumps(row) + "\n")
        except Exception:  # noqa: BLE001
            pass

    # ---- bank side demo ----
    def bank_check(self, token: str, action: str) -> dict:
        try:
            claims = self.signer.verify(token)
        except jwt.ExpiredSignatureError:
            return {"result": "block", "why": "decision expired"}
        except jwt.InvalidTokenError as e:
            return {"result": "block", "why": f"invalid decision signature: {e}"}
        if claims.get("action") != action:
            return {"result": "block", "why": "decision was issued for another action"}
        level = claims["trust_level"]
        return {"result": rules.policy_outcome(action, level), "trust_level": level,
                "why": "signature valid, action and expiry match"}
