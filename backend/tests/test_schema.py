"""Stage 1: the request contract."""
import json
import unittest

from helpers import FIXTURE, phone  # noqa: F401  (adds the backend folder to sys.path)
from pydantic import ValidationError

from trustpoc.schema import CollectPayload, parse_timestamp


def validate(p: dict) -> CollectPayload:
    return CollectPayload.model_validate_json(json.dumps(p))


def problem(p: dict) -> str:
    with_err = None
    try:
        validate(p)
    except ValidationError as exc:
        with_err = "; ".join(f"{'.'.join(str(x) for x in e['loc'])}: {e['msg']}" for e in exc.errors())
    return with_err or ""


class SchemaTest(unittest.TestCase):
    def test_real_phone_payload_is_valid(self):
        p = validate(phone())
        self.assertEqual(p.action, "transfer")
        self.assertEqual(len(p.signals), 231)
        self.assertEqual(p.device.sdk_int, 36)

    def test_wrong_schema_name(self):
        p = phone()
        p["schema"] = "rasp_collect_v1"
        self.assertIn("rasp_collect_v2", problem(p))

    def test_unknown_action(self):
        self.assertIn("action", problem(phone(action="withdraw")))

    def test_missing_context_keys(self):
        p = phone()
        del p["context_keys"]["session_id"]
        self.assertIn("session_id", problem(p))

    def test_ids_are_restricted(self):
        self.assertIn("install_id", problem(phone(install_id="bad id with spaces")))

    def test_timestamp_needs_offset(self):
        self.assertIn("UTC offset", problem(phone(timestamp="2026-11-17T23:54:56")))
        self.assertEqual(parse_timestamp("2026-11-17T23:54:56+05:30").isoformat(), "2026-11-17T18:24:56+00:00")
        self.assertIn("ISO-8601", problem(phone(timestamp="yesterday")))

    def test_signal_keys_and_pairs(self):
        self.assertIn("signal IDs look like", problem(phone(signals={"hello": 1})))
        self.assertIn("pair must be", problem(phone(signals={"F016": [1, 2, 3]})))
        self.assertIn("risk must be an integer 0-3", problem(phone(signals={"F016": ["x", 7]})))
        self.assertIn("boolean, number or text", problem(phone(signals={"F016": {"a": 1}})))

    def test_nul_characters_are_removed(self):
        # Postgres cannot store NUL; /proc/self/attr/current ends with one on real phones.
        p = validate(phone(signals={"F033": "u:r:untrusted_app:s0:c1,c2\u0000", "F098": ["/data/user/0/x\u0000", 0]},
                           device={"model": "I22\u000021"}))
        self.assertEqual(p.signals["F033"], "u:r:untrusted_app:s0:c1,c2")
        self.assertEqual(p.signals["F098"], ["/data/user/0/x", 0])
        self.assertEqual(p.device.model, "I2221")
        self.assertNotIn("\\u0000", p.model_dump_json())

    def test_long_text_is_rejected(self):
        self.assertIn("longer than", problem(phone(signals={"F016": "x" * 300})))

    def test_measured_and_unknown_overlap(self):
        p = phone()
        p["unknown"].append("F016")
        self.assertIn("both measured and unknown", problem(p))

    def test_unknown_probe_group(self):
        self.assertIn("unknown probe groups", problem(phone(failed_groups=["gpu"])))

    def test_extra_top_level_fields_are_ignored(self):
        p = phone()
        p["new_field_from_a_newer_app"] = {"x": 1}
        self.assertEqual(validate(p).action, "transfer")


if __name__ == "__main__":
    unittest.main()
