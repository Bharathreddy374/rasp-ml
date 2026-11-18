"""Backend-computed signals (F286-F365): request, device_context, geo data, history and device graph."""
import json
import tempfile
import unittest
from pathlib import Path

from helpers import phone, small_model_dir
from trustpoc import integrity, retrieval
from trustpoc.geo import GeoIP
from trustpoc.pipeline import Pipeline
from trustpoc.schema import CollectPayload
from trustpoc.scoring import ModelService
from trustpoc.store import MemoryStore

UA = "Dalvik/2.1.0 (Linux; U; Android 16; I2221 Build/BP2A)"
AID = "a" * 64
CTX = {"sim_country": "IN", "network_country": "in", "timezone": "Asia/Kolkata", "locale": "en-IN",
       "network_type": "wifi", "boot_count": 40, "uptime_ms": 3_600_000, "android_id_hash": AID}
QUIET = {"F278": ["Disabled", 0], "F279": ["Disabled", 0], "F280": ["Disabled / Off", 0]}


def facts(ip="52.95.110.1", **kw):
    return retrieval.Request(client_ip=ip, user_agent=UA, payload_bytes=5000, **kw)


def codes(res):
    return {r["code"] for r in res["decision"]["reasons"]}


class ServerSignalsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.geo_dir = Path(tempfile.mkdtemp())
        (cls.geo_dir / "dbip-country-lite.csv").write_text(
            "52.95.0.0,52.95.255.255,US\n49.36.0.0,49.36.255.255,IN\n", encoding="utf-8")
        (cls.geo_dir / "dbip-asn-lite.csv").write_text(
            "52.95.0.0,52.95.255.255,16509,Amazon.com Inc.\n49.36.0.0,49.36.255.255,55836,Reliance Jio Infocomm\n",
            encoding="utf-8")
        (cls.geo_dir / "tor-exit-nodes.txt").write_text("52.95.0.66\n", encoding="utf-8")

    def setUp(self):
        self.store = MemoryStore()
        self.pipe = Pipeline(self.store, ModelService(small_model_dir(), "enforce"),
                             {"expected_cert_sha256": [], "release_manifests": []}, GeoIP(self.geo_dir))

    def run_payload(self, p, f=None, ctx=CTX, pipe=None):
        if ctx is not None:
            p["device_context"] = dict(ctx)
        return (pipe or self.pipe).run(CollectPayload.model_validate_json(json.dumps(p)), f or facts())

    def test_every_backend_signal_is_computed_or_explained(self):
        r = self.run_payload(phone())["retrieved"]
        ss, nc = r["server_signals"], r["not_computed"]
        self.assertEqual(set(ss) | set(nc), set(retrieval.BACKEND_SIGNALS))
        self.assertFalse(set(ss) & set(nc))
        self.assertTrue(all(nc.values()))
        self.assertEqual(nc["F001"], integrity.NO_ATTESTATION)
        self.assertEqual(nc["F322"], retrieval.NO_BANK)
        self.assertEqual(nc["F306"], retrieval.NO_HISTORY)

    def test_geo_signals(self):
        res = self.run_payload(phone(signals=QUIET), facts("52.95.110.1"))
        ss = res["retrieved"]["server_signals"]
        self.assertEqual((ss["F286"], ss["F287"], ss["F288"]), (16509, "hosting", "US"))
        self.assertTrue(ss["F289"] and ss["F291"] and ss["F294"] and ss["F292"])
        self.assertFalse(ss["F293"])
        self.assertEqual(ss["F340"], 1)
        self.assertTrue({"CX_HOSTING_IP", "CX_COUNTRY_MISMATCH"} <= codes(res))

    def test_home_mobile_network_is_clean(self):
        res = self.run_payload(phone(signals=QUIET), facts("49.36.10.5"))
        ss = res["retrieved"]["server_signals"]
        self.assertEqual((ss["F287"], ss["F288"]), ("mobile", "IN"))
        self.assertFalse(ss["F289"] or ss["F291"] or ss["F292"] or ss["F294"])
        self.assertEqual(codes(res), set())

    def test_tor_exit(self):
        res = self.run_payload(phone(signals=QUIET), facts("52.95.0.66"))
        self.assertTrue(res["retrieved"]["server_signals"]["F293"])
        self.assertIn("CX_TOR_EXIT", codes(res))
        self.assertGreaterEqual(res["retrieved"]["server_signals"]["F295"], 0.9)

    def test_private_ip_has_no_geo(self):
        r = self.run_payload(phone(signals=QUIET), facts("192.168.1.18"))["retrieved"]
        self.assertEqual(r["server_signals"]["F287"], "private")
        self.assertEqual(r["not_computed"]["F288"], retrieval.NO_PUBLIC_IP)

    def test_without_geo_files_signals_are_explained(self):
        pipe = Pipeline(self.store, self.pipe.model, self.pipe.config, GeoIP(Path(tempfile.mkdtemp())))
        r = self.run_payload(phone(), pipe=pipe)["retrieved"]
        self.assertEqual(r["not_computed"]["F286"], retrieval.NO_GEO)
        self.assertEqual(r["not_computed"]["F287"], retrieval.NO_GEO)

    def test_proxy_headers_and_header_order(self):
        res = self.run_payload(phone(signals=QUIET), facts("49.36.10.5", header_names=["host", "via", "user-agent"],
                                                           proxy_headers=["via"]))
        ss = res["retrieved"]["server_signals"]
        self.assertTrue(ss["F292"])
        self.assertEqual(len(ss["F298"]), 16)
        self.assertIn("CX_PROXY_HEADERS", codes(res))

    def test_context_and_history_signals(self):
        self.run_payload(phone(session_id="c1", signals=QUIET))
        later = dict(CTX, boot_count=39, network_type="cellular")   # boot count went backwards
        res = self.run_payload(phone(session_id="c2", signals=QUIET), ctx=later)
        ss = res["retrieved"]["server_signals"]
        self.assertTrue(ss["F310"])
        self.assertEqual((ss["F301"], ss["F303"]), ("cellular", 1))
        self.assertFalse(ss["F313"])
        self.assertIn("F363", ss)
        self.assertIn("F333", ss)                 # anomaly trend against the earlier session
        self.assertLess(abs(ss["F365"]), 60_000)  # payload age in ms
        self.assertIn("HS_BOOT_COUNT_RESET", codes(res))

    def test_uptime_must_fit_the_time_that_passed(self):
        self.run_payload(phone(session_id="u1", signals=QUIET))
        res = self.run_payload(phone(session_id="u2", signals=QUIET), ctx=dict(CTX, uptime_ms=10_000_000))
        self.assertGreater(res["retrieved"]["server_signals"]["F311"], retrieval.UPTIME_DRIFT_LIMIT_S)
        self.assertIn("HS_UPTIME_INCONSISTENT", codes(res))

    def test_reinstalls_on_one_phone(self):
        for i in range(4):
            res = self.run_payload(phone(session_id="r", install_id=f"i_reinstall{i:020d}", signals=QUIET))
        self.assertEqual(res["retrieved"]["server_signals"]["F326"], 3)
        self.assertIn("HS_REINSTALLS", codes(res))

    def test_device_graph(self):
        for i in range(4):
            res = self.run_payload(phone(session_id="g", install_id=f"i_graph{i:024d}", signals=QUIET),
                                   ctx=dict(CTX, android_id_hash=f"{i:064x}"))
        ss = res["retrieved"]["server_signals"]
        self.assertEqual((ss["F343"], ss["F349"], ss["F339"], ss["F325"]), (4, 4, 4, 4))
        self.assertEqual(ss["F345"], 1.0)              # every other member is new
        self.assertEqual(ss["F350"], 0.4)              # min(1, log2(4) / 5) * 1.0
        self.assertEqual(ss["F338"], 4)                # same sensor hardware on all four

    def test_new_columns_are_stored(self):
        pk = self.run_payload(phone(), facts(header_names=["host", "user-agent"]))["id"]
        rec = self.store.get(pk)
        s = rec["session"]
        self.assertEqual(s["android_id_hash"], AID)
        self.assertEqual(s["asn"], 16509)
        self.assertEqual(s["device_context"]["sim_country"], "in")
        self.assertEqual(len(s["sensor_sig"]), 16)
        self.assertIn("F001", rec["retrieved"]["not_computed"])

    def test_without_device_context(self):
        r = self.run_payload(phone(), ctx=None)["retrieved"]
        self.assertEqual(r["not_computed"]["F326"], retrieval.NO_CONTEXT)
        self.assertNotIn("F289", r["server_signals"])


if __name__ == "__main__":
    unittest.main()
