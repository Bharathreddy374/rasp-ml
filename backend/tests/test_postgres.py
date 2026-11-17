"""Integration test against a real PostgreSQL. Skipped unless TEST_DATABASE_URL is set.

It creates a throwaway schema (rasp_test_<random>), runs the whole pipeline through it, and drops
the schema afterwards, so it never touches the real tables:

    $env:TEST_DATABASE_URL = "postgresql://user:pass@host/db?sslmode=require"
    python -m unittest tests.test_postgres -v
"""
import json
import os
import unittest
import uuid

from helpers import phone, small_model_dir
from trustpoc import retrieval
from trustpoc.pipeline import Pipeline
from trustpoc.schema import CollectPayload
from trustpoc.scoring import ModelService
from trustpoc.store import Duplicate, PostgresStore

URL = os.environ.get("TEST_DATABASE_URL")
FACTS = retrieval.Request("203.0.113.9", "Dalvik/2.1.0 (Linux; U; Android 16; I2221 Build/BP2A)", 5181)


@unittest.skipUnless(URL, "set TEST_DATABASE_URL to run")
class PostgresTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = "rasp_test_" + uuid.uuid4().hex[:10]
        cls.store = PostgresStore(URL, cls.schema)
        cls.store.migrate()
        cls.store.migrate()  # idempotent
        cls.pipe = Pipeline(cls.store, ModelService(small_model_dir(), "enforce"), {})

    @classmethod
    def tearDownClass(cls):
        cls.store._run(lambda cur: cur.execute(f'DROP SCHEMA "{cls.schema}" CASCADE'))

    def run_payload(self, p):
        return self.pipe.run(CollectPayload.model_validate_json(json.dumps(p)), FACTS)

    def test_ping(self):
        self.assertTrue(self.store.ping())

    def test_full_round_trip(self):
        res = self.run_payload(phone(session_id="pg-1", install_id="i_pg00000000000000000000000000001"))
        self.assertEqual(res["decision"]["level"], 3)
        rec = self.store.get(res["id"])
        self.assertEqual(rec["session"]["install_id"], "i_pg00000000000000000000000000001")
        self.assertEqual(rec["session"]["signals"]["F031"], ["Enforcing", 0])        # JSONB comes back typed
        self.assertEqual(rec["session"]["device"]["sdk_int"], 36)
        self.assertEqual(rec["session"]["net24"], "203.0.113.0/24")
        self.assertTrue(rec["retrieved"]["server_signals"]["F299"])
        self.assertEqual(rec["result"]["final_level"], 3)
        self.assertTrue(40 <= rec["result"]["risk_score"] <= 59)
        self.assertEqual(rec["result"]["risk_score"], res["decision"]["risk_score"])
        self.assertEqual(rec["result"]["ml_status"], "scored")
        self.assertEqual(rec["result"]["features"]["sensor_count"], 44)
        self.assertIsNone(rec["result"]["features"]["probe_total_ms"])
        self.assertEqual({r["code"] for r in rec["result"]["reasons"]}, {"CX_DEVELOPER_OPTIONS", "CX_ADB_ENABLED"})

    def test_payload_with_nul_characters_is_stored(self):
        # The real phone sends F033 with a trailing NUL, which JSONB rejects unless it is removed first.
        res = self.run_payload(phone(session_id="pg-nul", install_id="i_pg00000000000000000000000000007",
                                     signals={"F033": "u:r:untrusted_app:s0:c1,c2\u0000"}))
        rec = self.store.get(res["id"])
        self.assertEqual(rec["session"]["signals"]["F033"], "u:r:untrusted_app:s0:c1,c2")

    def test_duplicate_session_is_not_stored_twice(self):
        first = self.run_payload(phone(session_id="pg-dup", install_id="i_pg00000000000000000000000000002"))
        again = self.run_payload(phone(session_id="pg-dup", install_id="i_pg00000000000000000000000000002"))
        self.assertTrue(again["duplicate"])
        self.assertEqual(again["id"], first["id"])
        self.assertEqual(len(self.store.list_sessions("i_pg00000000000000000000000000002", None, 10)), 1)

    def test_unique_constraint_raises_duplicate(self):
        res = self.run_payload(phone(session_id="pg-uniq", install_id="i_pg00000000000000000000000000003"))
        rec = self.store.get(res["id"])
        s = {**rec["session"], "scan_time": __import__("datetime").datetime.now(__import__("datetime").timezone.utc)}
        with self.assertRaises(Duplicate):
            self.store.save(s, rec["retrieved"], rec["result"])

    def test_history_and_network_queries(self):
        for i in range(2):
            self.run_payload(phone(session_id=f"pg-h{i}", install_id="i_pg00000000000000000000000000004"))
        last = self.run_payload(phone(session_id="pg-h2", install_id="i_pg00000000000000000000000000004"))
        self.assertEqual(last["retrieved"]["history"]["sessions_seen"], 2)
        self.assertIn("F330", last["retrieved"]["server_signals"])
        self.assertGreaterEqual(last["retrieved"]["server_signals"]["F339"], 1)

    def test_listing_and_training_export(self):
        self.run_payload(phone(session_id="pg-l1", install_id="i_pg00000000000000000000000000005"))
        rows = self.store.list_sessions("i_pg00000000000000000000000000005", 3, 10)
        self.assertEqual(rows[0]["final_level"], 3)
        self.assertEqual(self.store.list_sessions("i_pg00000000000000000000000000005", 4, 10), [])
        feats = self.store.training_features(max_rules_level=3, limit=100)
        self.assertTrue(feats and set(feats[0]["features"]) >= {"sensor_count", "root_su_which"})

    def test_failed_save_leaves_no_partial_rows(self):
        res = self.run_payload(phone(session_id="pg-tx", install_id="i_pg00000000000000000000000000006"))
        rec = self.store.get(res["id"])
        bad_result = {**rec["result"], "final_level": None}   # NOT NULL violation in the third insert
        s = {**rec["session"], "session_id": "pg-tx-2", "scan_time": __import__("datetime").datetime.now(__import__("datetime").timezone.utc)}
        with self.assertRaises(Exception):
            self.store.save(s, rec["retrieved"], bad_result)
        self.assertIsNone(self.store.find("i_pg00000000000000000000000000006", "pg-tx-2"))


if __name__ == "__main__":
    unittest.main()
