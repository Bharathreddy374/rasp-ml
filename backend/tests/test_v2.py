"""Schema-2 (Android app) flow: signed compact signals, mapping, server signals, HTTP + gzip.

Run: python -m unittest discover -s tests -v   (from the backend folder)
"""
import base64
import gzip
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["TRUSTPOC_OFFLINE"] = "1"

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from trustpoc.engine import Engine
from test_engine import APP_DIGEST, PKG, key_description, make_cert

SAFE, INFO, SUSPICIOUS, ALERT = 0, 1, 2, 3
PHONE = {"manufacturer": "Google", "brand": "google", "model": "Pixel 7", "device": "panther",
         "hardware": "panther", "board": "gs201", "release": "15", "sdk_int": 35,
         "security_patch": "2025-10-05",  # matches the attested patch level 202510 in key_description
         "fingerprint": "google/panther/panther:15/AP3A/1:user/release-keys"}
EMULATOR = {**PHONE, "model": "sdk_gphone64_x86_64", "device": "emu64xa", "hardware": "ranchu",
            "board": "goldfish_x86_64", "fingerprint": "google/sdk_gphone64_x86_64/emu64xa:15/AE3A/1:userdebug/dev-keys"}


def clean_signals() -> dict:
    """A genuine phone: the mapped probes all report SAFE."""
    ids = ["F016", "F017", "F018", "F037", "F038", "F041", "F043", "F045", "F046", "F047", "F050",
           "F051", "F053", "F060", "F098", "F099", "F108", "F117", "F118", "F121", "F124", "F125",
           "F126", "F127", "F128", "F129", "F130", "F133", "F138", "F139", "F140", "F141", "F142",
           "F143", "F271", "F272", "F278", "F279", "F280", "F282"]
    s = {i: [False, SAFE] for i in ids}
    s["F031"] = ["Enforcing", SAFE]
    s["F116"] = [0, SAFE]
    s["F255"] = [32, SAFE]
    return s


class Phone:
    def __init__(self, root_key, install_id="i_v2"):
        self.root_key = root_key
        self.root = make_cert("Root", root_key.public_key(), "Root", root_key)
        self.install_id = install_id
        self.counter = 0

    def body(self, engine, signals=None, device=None, unknown=None, action="login", version_code=1,
             failed_groups=None, mutate=None):
        nonce = engine.issue_nonce(self.install_id, action)["nonce"]
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        inter_key = ec.generate_private_key(ec.SECP256R1())
        inter = make_cert("Intermediate", inter_key.public_key(), "Root", self.root_key)
        leaf = make_cert("Leaf", leaf_key.public_key(), "Intermediate", inter_key,
                         key_description(base64.b64decode(nonce)))
        self.counter += 1
        payload = {
            "schema": 2, "install_id": self.install_id, "action": action, "nonce": nonce,
            "counter": self.counter, "ts": 0, "scan_ms": 400,
            "app": {"package": PKG, "version_code": version_code, "cert_sha256": [APP_DIGEST]},
            "device": device or PHONE,
            "signals": signals if signals is not None else clean_signals(),
            "unknown": unknown or [],
            "failed_groups": failed_groups or [],
        }
        text = json.dumps(payload, separators=(",", ":"))
        sig = base64.b64encode(leaf_key.sign(text.encode(), ec.ECDSA(hashes.SHA256()))).decode()
        if mutate:  # attacker edits the payload after it was signed
            p = json.loads(text)
            mutate(p)
            text = json.dumps(p, separators=(",", ":"))
        chain = [base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()
                 for c in (leaf, inter, self.root)]
        return {"payload": text, "signature": sig, "chain": chain}

    def assess(self, engine, **kw):
        b = self.body(engine, **kw)
        return engine.assess_v2(b["payload"], b["signature"], b["chain"],
                                client_ip="203.0.113.7",
                                user_agent="Dalvik/2.1.0 (Linux; U; Android 15; Pixel 7 Build/AP3A)")


def codes(res):
    return [r["code"] for r in res["reasons"]]


class V2EngineTest(unittest.TestCase):
    def setUp(self):
        tmp = Path(tempfile.mkdtemp())
        roots = tmp / "roots"
        roots.mkdir()
        self.phone = Phone(ec.generate_private_key(ec.SECP256R1()))
        (roots / "google.pem").write_bytes(self.phone.root.public_bytes(serialization.Encoding.PEM))
        self.engine = Engine(tmp / "data", roots,
                             {"expected_package": [PKG], "expected_cert_sha256": [APP_DIGEST]},
                             fetch_revocations=False)

    def test_genuine_phone_is_level_1(self):
        res = self.phone.assess(self.engine)
        self.assertEqual(res["trust_level"], 1, codes(res))
        self.assertTrue(res["attestation"]["chain_valid"])
        self.assertEqual(res["coverage"]["device_signals"], len(clean_signals()))
        self.assertTrue(res["server_signals"]["F299"])  # User-Agent matches the signed device block
        self.assertEqual(res["server_signals"]["F329"], 0)  # first time this install is seen

    def test_frida_signal_is_high_risk(self):
        s = clean_signals()
        s["F124"] = ["frida-agent.so mapped", ALERT]
        res = self.phone.assess(self.engine, signals=s)
        self.assertIn("RT_FRIDA", codes(res))
        self.assertEqual(res["trust_level"], 4)

    def test_root_plus_frida_is_critical(self):
        s = clean_signals()
        s["F043"] = ["Installed", ALERT]
        s["F126"] = ["gum-js-loop thread found", ALERT]
        res = self.phone.assess(self.engine, signals=s)
        self.assertIn("DV_ROOT_MANAGER_APP", codes(res))
        self.assertEqual(res["trust_level"], 5)

    def test_developer_options_info_counts_as_on(self):
        s = clean_signals()
        s["F278"] = ["Enabled", INFO]
        res = self.phone.assess(self.engine, signals=s)
        self.assertIn("CX_DEVELOPER_OPTIONS", codes(res))
        self.assertEqual(res["trust_level"], 3)

    def test_unknown_signals_are_not_evidence(self):
        res = self.phone.assess(self.engine, unknown=["F025", "F146", "F155"])
        self.assertEqual(res["trust_level"], 1)
        self.assertEqual(res["coverage"]["unknown"], 3)

    def test_missing_signals_stay_unknown_not_clean(self):
        res = self.phone.assess(self.engine, signals={})
        self.assertEqual(res["coverage"]["device_signals"], 0)
        rec = self.engine.decisions[0]
        self.assertNotIn("rt_frida_maps", rec["inputs"])

    def test_unmapped_alert_is_context(self):
        s = clean_signals()
        s["F027"] = ["Traces detected", ALERT]  # resetprop: no dedicated rule yet
        res = self.phone.assess(self.engine, signals=s)
        self.assertIn("DV_UNMAPPED_ALERTS", codes(res))
        self.assertEqual(res["unmapped_alerts"], ["F027"])
        self.assertEqual(res["trust_level"], 2)

    def test_emulator_from_device_block_and_sensors(self):
        s = clean_signals()
        s["F255"] = [3, SUSPICIOUS]
        res = self.phone.assess(self.engine, signals=s, device=EMULATOR)
        self.assertIn("EM_EMULATOR", codes(res))

    def test_signals_edited_after_signing_are_critical(self):
        def hide_frida(p):
            p["signals"]["F124"] = [False, SAFE]
        s = clean_signals()
        s["F124"] = ["frida-agent.so mapped", ALERT]
        b = self.phone.body(self.engine, signals=s, mutate=hide_frida)
        res = self.engine.assess_v2(b["payload"], b["signature"], b["chain"])
        self.assertIn("AT_PAYLOAD_SIGNATURE_INVALID", codes(res))
        self.assertEqual(res["trust_level"], 5)

    def test_patch_regression_across_requests(self):
        self.phone.assess(self.engine)
        older = {**PHONE, "security_patch": "2025-01-01"}
        res = self.phone.assess(self.engine, device=older)
        self.assertTrue(res["server_signals"]["F306"])
        self.assertIn("HS_PATCH_REGRESSED", codes(res))

    def test_failed_probe_groups_are_errors(self):
        res = self.phone.assess(self.engine, failed_groups=["runtime_hooking", "memory_procfs",
                                                              "timing", "sensor_touch"])
        self.assertIn("CX_PROBE_FAILURES", codes(res))

    def test_spoofed_patch_level_vs_attestation(self):
        res = self.phone.assess(self.engine, device={**PHONE, "security_patch": "2026-10-05"})
        self.assertTrue(res["server_signals"]["F025"])
        self.assertIn("DV_PROPS_VS_ATTESTATION", codes(res))

    def test_frida_dbus_handshake_is_instrumentation(self):
        s = clean_signals()
        s["F131"] = [True, ALERT]
        res = self.phone.assess(self.engine, signals=s)
        self.assertIn("RT_FRIDA", codes(res))

    def test_cert_two_sources_mismatch_is_app_tamper(self):
        s = clean_signals()
        s["F078"] = [True, ALERT]
        res = self.phone.assess(self.engine, signals=s)
        self.assertIn("AP_CERT_INCONSISTENT", codes(res))
        self.assertEqual(res["trust_level"], 4)

    def test_apk_code_vs_release_manifest(self):
        self.engine.config["release_manifests"] = [{"dex_digest": "a" * 32, "so_digest": "b" * 32}]
        s = clean_signals()
        s["F084"] = ["a" * 32, INFO]
        s["F086"] = ["b" * 32, INFO]
        res = self.phone.assess(self.engine, signals=s)
        self.assertNotIn("AP_CODE_MISMATCH", codes(res))
        self.assertFalse(res["server_signals"]["F088"])
        s["F084"] = ["c" * 32, INFO]
        res = self.phone.assess(self.engine, signals=s)
        self.assertIn("AP_CODE_MISMATCH", codes(res))

    def test_apk_manifest_tool_digests(self):
        import io
        import zipfile
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
        from apk_manifest import digest, manifest
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("classes.dex", b"dex")
            z.writestr("lib/arm64-v8a/libx.so", b"so")
            z.writestr("AndroidManifest.xml", b"m")
        path = Path(tempfile.mkdtemp()) / "app.apk"
        path.write_bytes(buf.getvalue())
        m = manifest(str(path))
        import zlib
        self.assertEqual(m["dex_digest"], digest([f"classes.dex:{zlib.crc32(b'dex'):08x}:3"]))
        self.assertEqual(m["manifest_crc"], f"{zlib.crc32(b'm'):08x}")
        self.assertEqual(m["arsc_crc"], "missing")

    def test_inline_hook_on_libc_is_code_patched(self):
        s = clean_signals()
        s["F149"] = [4, ALERT]  # 4 of 16 bytes of access() patched in memory
        res = self.phone.assess(self.engine, signals=s)
        self.assertIn("RT_CODE_PATCHED", codes(res))
        self.assertEqual(res["trust_level"], 4)

    def test_hidden_su_via_syscall_disagreement_is_root(self):
        s = clean_signals()
        s["F040"] = [1, ALERT]  # libc says missing, raw syscall sees it
        res = self.phone.assess(self.engine, signals=s)
        self.assertIn("DV_ROOT_BINARY", codes(res))

    def test_static_sensors_count_as_emulator_evidence(self):
        s = clean_signals()
        s["F255"] = [3, SUSPICIOUS]   # few sensors
        s["F231"] = [0.0, SUSPICIOUS]  # exactly zero noise
        res = self.phone.assess(self.engine, signals=s)  # genuine-looking device block
        self.assertIn("EM_EMULATOR", codes(res))

    def test_schema_1_rejected_on_v2(self):
        res = self.engine.assess_v2(json.dumps({"schema": 1}), "", [])
        self.assertIn("error", res)


def asgi_request(body: bytes, headers: dict):
    """A real Starlette Request for the endpoint, without needing an HTTP test client."""
    from starlette.requests import Request
    scope = {"type": "http", "method": "POST", "path": "/v2/assess", "query_string": b"",
             "client": ("203.0.113.9", 5555),
             "headers": [(k.lower().encode(), v.encode()) for k, v in headers.items()]}
    sent = False

    async def receive():
        nonlocal sent
        if sent:
            return {"type": "http.disconnect"}
        sent = True
        return {"type": "http.request", "body": body, "more_body": False}
    return Request(scope, receive)


class V2HttpTest(unittest.TestCase):
    """The FastAPI handlers: gzip body, legacy endpoint closed, admin closed without a token."""

    @classmethod
    def setUpClass(cls):
        os.environ["DATABASE_URL"] = ""  # never touch a real database from tests
        os.environ["ADMIN_TOKEN"] = ""
        os.environ["DEMO_MODE"] = "0"
        os.environ["ALLOW_UNSIGNED_REPORTS"] = "0"
        import app as app_module
        cls.app = app_module
        app_module.engine.data_dir = Path(tempfile.mkdtemp())  # keep test sessions out of real training data
        cls.phone = Phone(ec.generate_private_key(ec.SECP256R1()), install_id="i_http")
        app_module.engine.trust.root_keys.append(cls.phone.root.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
        app_module.engine.config["expected_package"] = [PKG]
        app_module.engine.config["expected_cert_sha256"] = [APP_DIGEST]

    def call(self, body: bytes, headers: dict):
        import asyncio
        return asyncio.run(self.app.assess_v2(asgi_request(body, headers)))

    def test_gzip_v2_assess(self):
        body = json.dumps(self.phone.body(self.app.engine)).encode()
        res = self.call(gzip.compress(body), {"content-type": "application/json", "content-encoding": "gzip",
                                              "user-agent": "Dalvik/2.1.0 (Linux; U; Android 15; Pixel 7 Build/AP3A)"})
        self.assertEqual(res["trust_level"], 1, res["reasons"])
        self.assertTrue(res["server_signals"]["F299"])
        self.assertEqual(res["server_signals"]["F339"], 1)  # first install seen from 203.0.113.0/24

    def test_plain_json_v2_assess(self):
        res = self.call(json.dumps(self.phone.body(self.app.engine)).encode(), {"content-type": "application/json"})
        self.assertIn(res["trust_level"], (1, 2))

    def test_bad_gzip_is_400(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as cm:
            self.call(b"not gzip", {"content-type": "application/json", "content-encoding": "gzip"})
        self.assertEqual(cm.exception.status_code, 400)

    def test_gzip_bomb_is_413(self):
        from fastapi import HTTPException
        bomb = gzip.compress(b"{" + b" " * (5 * 1024 * 1024) + b"}")
        with self.assertRaises(HTTPException) as cm:
            self.call(bomb, {"content-type": "application/json", "content-encoding": "gzip"})
        self.assertEqual(cm.exception.status_code, 413)

    def test_unsigned_legacy_endpoint_closed(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as cm:
            self.app.receive_features({"total_signals": 0, "signals": []})
        self.assertEqual(cm.exception.status_code, 410)

    def test_admin_closed_without_token(self):
        from fastapi import HTTPException
        with self.assertRaises(HTTPException) as cm:
            self.app.reset(token="", x_admin_token=None)
        self.assertEqual(cm.exception.status_code, 403)


if __name__ == "__main__":
    unittest.main()
