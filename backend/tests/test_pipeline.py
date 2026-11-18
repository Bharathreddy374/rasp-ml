"""The whole pipeline against the in-memory store and a small real model."""
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from helpers import phone, small_model_dir
from trustpoc import retrieval
from trustpoc.pipeline import Pipeline
from trustpoc.schema import CollectPayload
from trustpoc.scoring import SCORE_BANDS, ModelOutcome, ModelService, risk_score
from trustpoc.store import MemoryStore

FACTS = retrieval.Request(client_ip="203.0.113.9", user_agent="Dalvik/2.1.0 (Linux; U; Android 16; I2221 Build/BP2A)",
                          payload_bytes=5181)
QUIET = {"F278": ["Disabled", 0], "F279": ["Disabled", 0], "F280": ["Disabled / Off", 0]}  # developer settings off


def codes(res: dict) -> list[str]:
    return [r["code"] for r in res["decision"]["reasons"]]


class PipelineTest(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.model = ModelService(small_model_dir(), "enforce")
        self.pipe = Pipeline(self.store, self.model, {"expected_cert_sha256": [], "release_manifests": []})

    def run_payload(self, p: dict, facts=FACTS, pipe=None) -> dict:
        return (pipe or self.pipe).run(CollectPayload.model_validate_json(json.dumps(p)), facts)

    # ---- the real phone ----
    def test_real_phone_with_developer_settings_on_is_level_3(self):
        res = self.run_payload(phone())
        d = res["decision"]
        self.assertEqual((d["level"], d["label"], d["outcome"]), (3, "SUSPICIOUS", "step_up"))
        self.assertEqual(set(codes(res)), {"CX_DEVELOPER_OPTIONS", "CX_ADB_ENABLED"})
        self.assertEqual(d["assurance"], "unverified")
        self.assertEqual(d["rules_level"], 3)

    def test_real_phone_with_settings_off_has_no_rule_evidence(self):
        res = self.run_payload(phone(signals=QUIET))
        self.assertEqual(res["decision"]["rules_level"], 1)
        self.assertEqual(codes(res), [])
        self.assertLessEqual(res["decision"]["level"], 2)

    def test_model_sees_the_features_it_needs(self):
        m = self.run_payload(phone())["model"]
        self.assertEqual(m["status"], "scored")
        self.assertEqual(sorted(m["missing_features"]), ["probe_max_ms", "probe_total_ms"])  # the app sends no per-probe timing
        self.assertAlmostEqual(m["feature_coverage"], 0.92)
        self.assertEqual(m["features"]["sensor_count"], 44)
        self.assertIsNone(m["features"]["probe_total_ms"])      # missing stays missing, never 0
        self.assertEqual(set(m["heads"]), {"hidden_root", "instrumentation", "emulator_virtual", "app_tamper_clone"})
        self.assertEqual(m["trained_on"], "synthetic")

    def test_retrieved_data_and_timings(self):
        res = self.run_payload(phone())
        ss = res["retrieved"]["server_signals"]
        self.assertTrue(ss["F299"])          # User-Agent matches the signed device block
        self.assertEqual(ss["F329"], 0)      # first time this install is seen
        self.assertEqual(ss["F339"], 1)
        self.assertEqual(res["retrieved"]["history"]["sessions_seen"], 0)
        self.assertEqual(set(res["timings_ms"]), {"normalize", "integrity", "retrieve", "rules", "model", "persist", "total"})
        self.assertEqual(set(self.store.get(res["id"])["result"]["timings_ms"]), {"normalize", "integrity", "retrieve", "rules", "model", "total"})

    # ---- persistence ----
    def test_everything_is_stored(self):
        res = self.run_payload(phone())
        rec = self.store.get(res["id"])
        self.assertEqual(rec["session"]["install_id"], res["install_id"])
        self.assertEqual(rec["session"]["signals"]["F031"], ["Enforcing", 0])
        self.assertIn("F299", rec["retrieved"]["server_signals"])
        self.assertEqual(rec["result"]["final_level"], 3)
        self.assertEqual(rec["result"]["features"]["sensor_count"], 44)
        self.assertEqual(rec["result"]["model_version"], "test-model")

    def test_retry_of_the_same_session_returns_the_stored_result(self):
        first = self.run_payload(phone(session_id="retry-1"))
        again = self.run_payload(phone(session_id="retry-1"))
        self.assertFalse(first["duplicate"])
        self.assertTrue(again["duplicate"])
        self.assertEqual(again["id"], first["id"])
        self.assertEqual(again["decision"], first["decision"])
        self.assertEqual(len(self.store.list_sessions(None, None, 10)), 1)

    # ---- attacks ----
    def test_frida_is_high_risk(self):
        res = self.run_payload(phone(signals={"F124": ["frida-agent.so mapped", 3], "F126": ["gum-js-loop thread found", 3]}))
        self.assertIn("RT_FRIDA", codes(res))
        self.assertGreaterEqual(res["decision"]["level"], 4)
        self.assertEqual(res["decision"]["outcome"], "block")

    def test_root_plus_frida_is_critical(self):
        res = self.run_payload(phone(signals={"F043": ["Installed", 3], "F124": ["frida-agent.so mapped", 3]}))
        self.assertEqual(res["decision"]["level"], 5)

    def test_inline_hooks_from_native_counts(self):
        res = self.run_payload(phone(signals={"F149": 5, "F155": 1}))
        self.assertIn("RT_CODE_PATCHED", codes(res))
        self.assertGreaterEqual(res["decision"]["level"], 4)

    def test_emulator_needs_two_independent_indicators(self):
        one = self.run_payload(phone(session_id="e1", signals={"F255": 3}))
        self.assertNotIn("EM_EMULATOR", codes(one))
        two = self.run_payload(phone(session_id="e2", signals={"F255": 3, "F231": 0, "F232": 0, "F233": 0}))
        self.assertIn("EM_EMULATOR", codes(two))

    def test_unmapped_alert_is_context_only(self):
        res = self.run_payload(phone(signals={**QUIET, "F113": ["External DEX mapped", 3]}))
        self.assertEqual(codes(res), ["DV_UNMAPPED_ALERTS"])
        self.assertEqual(res["decision"]["rules_level"], 2)
        self.assertEqual(res["coverage"]["unmapped_alerts"], ["F113"])

    # ---- retrieval from the database ----
    def test_history_regressions(self):
        self.run_payload(phone(session_id="h1", signals=QUIET, device={"security_patch": "2026-10-01", "sdk_int": 36},
                               app={"version_code": 5}))
        res = self.run_payload(phone(session_id="h2", signals=QUIET, device={"security_patch": "2025-01-01", "sdk_int": 35},
                                     app={"version_code": 4}))
        self.assertTrue({"HS_PATCH_REGRESSED", "HS_OS_DOWNGRADE", "HS_APP_VERSION_REGRESSED"} <= set(codes(res)))
        ss = res["retrieved"]["server_signals"]
        self.assertTrue(ss["F306"] and ss["F312"] and ss["F315"])
        self.assertEqual(res["retrieved"]["history"]["sessions_seen"], 1)

    def test_history_is_empty_for_a_new_install_and_grows(self):
        for i in range(3):
            res = self.run_payload(phone(session_id=f"g{i}", install_id="i_growing0000000000000000000001"))
        self.assertEqual(res["retrieved"]["history"]["sessions_seen"], 2)
        self.assertIn("F330", res["retrieved"]["server_signals"])

    def test_devices_per_network(self):
        self.run_payload(phone(session_id="n1", install_id="i_net0000000000000000000000000a"))
        res = self.run_payload(phone(session_id="n2", install_id="i_net0000000000000000000000000b"))
        self.assertEqual(res["retrieved"]["server_signals"]["F339"], 2)
        far = self.run_payload(phone(session_id="n3", install_id="i_net0000000000000000000000000c"),
                               retrieval.Request("198.51.100.4", FACTS.user_agent, 5000))
        self.assertEqual(far["retrieved"]["server_signals"]["F339"], 1)

    def test_clock_skew(self):
        old = (datetime.now(timezone.utc) - timedelta(hours=3)).isoformat(timespec="seconds")
        res = self.run_payload(phone(signals=QUIET, timestamp=old))
        self.assertEqual(codes(res), ["CX_CLOCK_SKEW"])
        self.assertGreater(res["retrieved"]["history"]["clock_skew_s"], 3 * 3600 - 60)

    def test_user_agent_mismatch(self):
        res = self.run_payload(phone(), retrieval.Request("203.0.113.9", "Dalvik/2.1.0 (Linux; U; Android 12; Pixel 6 Build/SQ1A)", 5000))
        self.assertFalse(res["retrieved"]["server_signals"]["F299"])

    def test_release_manifest_and_certificate_checks(self):
        cfg = {"expected_cert_sha256": ["00" * 32], "release_manifests": [{"dex_digest": "f" * 32}]}
        pipe = Pipeline(self.store, self.model, cfg)
        res = self.run_payload(phone(signals=QUIET), pipe=pipe)
        self.assertTrue({"AP_CODE_MISMATCH", "AP_CERT_MISMATCH"} <= set(codes(res)))
        self.assertEqual(res["retrieved"]["checks"], {"release_manifest": False, "signing_cert": False})

    # ---- risk score ----
    def test_risk_score_always_sits_inside_its_level_band(self):
        cases = [phone(session_id="sc1", signals=QUIET), phone(session_id="sc2"),
                 phone(session_id="sc3", signals={"F124": ["frida-agent.so mapped", 3]}),
                 phone(session_id="sc4", signals={"F043": ["Installed", 3], "F124": ["frida-agent.so mapped", 3]})]
        for p in cases:
            d = self.run_payload(p)["decision"]
            low, high = SCORE_BANDS[d["level"]]
            self.assertTrue(low <= d["risk_score"] <= high, d)
            self.assertEqual(d["score_basis"]["band"], [low, high])
            self.assertEqual(d["score_basis"]["from"], "model")

    def test_risk_score_is_stored(self):
        res = self.run_payload(phone())
        self.assertEqual(self.store.get(res["id"])["result"]["risk_score"], res["decision"]["risk_score"])
        self.assertEqual(self.store.list_sessions(None, None, 1)[0]["risk_score"], res["decision"]["risk_score"])

    def test_risk_score_without_a_model_is_the_band_middle(self):
        pipe = Pipeline(self.store, ModelService(Path(tempfile.mkdtemp()), "enforce"), {})
        d = self.run_payload(phone(), pipe=pipe)["decision"]
        self.assertEqual((d["level"], d["risk_score"]), (3, 50))
        self.assertEqual(d["score_basis"]["from"], "level only (model unavailable)")

    def test_risk_score_position_comes_from_the_model(self):
        def scored(heads, pct):
            return ModelOutcome(status="scored", detail={"heads": heads, "anomaly_pct": pct})
        self.assertEqual(risk_score(1, scored({"a": 0.0}, 10.0))[0], 0)       # nothing unusual: bottom of band
        self.assertEqual(risk_score(1, scored({"a": 0.0}, 100.0))[0], 19)     # most anomalous: top of band
        self.assertEqual(risk_score(4, scored({"a": 0.5}, 20.0))[0], 70)      # head probability 0.5: middle
        self.assertEqual(risk_score(5, scored({"a": 1.0}, 0.0))[0], 100)

    # ---- the model's role ----
    def test_shadow_mode_stores_ml_but_rules_decide(self):
        pipe = Pipeline(self.store, ModelService(small_model_dir(), "shadow"), {})
        res = self.run_payload(phone(signals={"F124": ["frida-agent.so mapped", 3]}), pipe=pipe)
        self.assertEqual(res["decision"]["ml_mode"], "shadow")
        self.assertIsNotNone(res["decision"]["ml_level"])
        self.assertEqual(res["decision"]["level"], res["decision"]["rules_level"])

    def test_enforce_mode_never_lowers_the_rules_level(self):
        res = self.run_payload(phone(signals={"F124": ["frida-agent.so mapped", 3]}))
        self.assertGreaterEqual(res["decision"]["level"], res["decision"]["rules_level"])

    def test_missing_model_falls_back_to_rules(self):
        pipe = Pipeline(self.store, ModelService(Path(tempfile.mkdtemp()), "enforce"), {})
        res = self.run_payload(phone(), pipe=pipe)
        self.assertEqual(res["model"]["status"], "unavailable")
        self.assertIsNone(res["decision"]["ml_level"])
        self.assertEqual(res["decision"]["level"], 3)

    def test_too_few_features_skips_the_model(self):
        mostly_unknown = [f"F{i:03d}" for i in list(range(16, 286))]
        res = self.run_payload(phone(unknown=mostly_unknown))
        self.assertEqual(res["model"]["status"], "insufficient_features")
        self.assertIsNone(res["decision"]["ml_level"])
        self.assertLess(res["model"]["feature_coverage"], 0.6)


if __name__ == "__main__":
    unittest.main()
