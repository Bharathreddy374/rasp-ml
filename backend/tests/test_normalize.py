"""Stage 3: payload signals -> probes. The decisive cases are bare values and unknowns."""
import json
import unittest

from helpers import phone
from trustpoc import normalize
from trustpoc.normalize import D, Sig, evaluate
from trustpoc.schema import CollectPayload


def norm(**kw) -> normalize.Normalized:
    return normalize.normalize(CollectPayload.model_validate_json(json.dumps(phone(**kw))))


def v(n: normalize.Normalized, name: str):
    return n.probes[name]["v"]


class EvaluateTest(unittest.TestCase):
    def test_pair_uses_the_devices_risk_not_the_text(self):
        self.assertTrue(evaluate(Sig("Clean", 3), D(3)))          # text says clean, risk says alert
        self.assertFalse(evaluate(Sig("frida found", 1), D(3)))   # text says frida, risk below threshold

    def test_bare_value_meaning_is_fixed_per_signal(self):
        self.assertTrue(evaluate(Sig(5, None), D(3, "gt0")))
        self.assertFalse(evaluate(Sig(0, None), D(3, "gt0")))
        self.assertTrue(evaluate(Sig("1", None), D(3, "eq1")))     # ro.debuggable "1" is bad
        self.assertTrue(evaluate(Sig("0", None), D(3, "eq0")))     # ro.secure "0" is bad
        self.assertFalse(evaluate(Sig("1", None), D(3, "eq0")))
        self.assertTrue(evaluate(Sig(False, None), D(3, "false")))  # signing block missing
        self.assertTrue(evaluate(Sig(True, None), D(3, "true")))
        self.assertTrue(evaluate(Sig(0, None), D(2, "zero")))       # exactly zero sensor noise
        self.assertFalse(evaluate(Sig(0.07, None), D(2, "zero")))
        self.assertTrue(evaluate(Sig(75, None), D(2, "gtN:30")))
        self.assertTrue(evaluate(Sig("gmain, gdbus", None), D(3, "nonclean")))
        self.assertFalse(evaluate(Sig("None", None), D(3, "nonclean")))

    def test_leading_number_of_a_text(self):
        self.assertEqual(normalize.number("75 deleted mappings"), 75.0)
        self.assertIsNone(normalize.number("many"))

    def test_undecidable_is_none_not_false(self):
        self.assertIsNone(evaluate(Sig("Clean", None), D(3)))          # a pair signal that arrived bare
        self.assertIsNone(evaluate(Sig("lots", None), D(3, "gt0")))    # text where a number was expected


class NormalizeTest(unittest.TestCase):
    def test_real_phone_has_no_evidence(self):
        n = norm()
        for name in ("root_su_paths", "rt_frida_threads", "root_manager_packages"):
            self.assertEqual(v(n, name), [])
        for name in ("rt_code_patched", "rt_frida_maps", "rt_xposed", "root_magisk_mounts", "root_system_rw",
                     "root_dangerous_props", "emu_fingerprint", "emu_hardware", "emu_qemu_props",
                     "emu_static_sensors", "app_cert_inconsistent", "ctx_vpn"):
            self.assertFalse(v(n, name), name)
        self.assertTrue(v(n, "app_data_dir_ok"))
        self.assertEqual(v(n, "selinux_mode"), "Enforcing")
        self.assertEqual(v(n, "sensor_count"), 44)
        self.assertEqual(v(n, "rt_tracer_pid"), 0)
        self.assertEqual(v(n, "ctx_accessibility_services"), 0)
        self.assertEqual(n.undecidable, [])
        self.assertEqual(n.unmapped_alerts, [])

    def test_real_phone_context_flags(self):
        n = norm()
        self.assertTrue(v(n, "ctx_developer_options"))  # F278 INFO = enabled
        self.assertTrue(v(n, "ctx_adb_enabled"))        # F280 wireless debugging

    def test_unknown_and_missing_signals_never_become_probes(self):
        n = norm(signals={}, unknown=["F124", "F125", "F126", "F127", "F128", "F129", "F130", "F131", "F132", "F137"])
        self.assertNotIn("rt_frida_port", n.probes)         # F129/F130/F131 all unknown
        self.assertIn("rt_frida_maps", n.probes)            # other maps signals still decide it
        n = norm(unknown=[f"F{i:03d}" for i in range(1, 371)])
        self.assertEqual([k for k in n.probes if not k.startswith("emu_")], [])

    def test_frida_pair_signals(self):
        n = norm(signals={"F124": ["frida-agent.so mapped", 3], "F126": ["gum-js-loop thread found", 3]})
        self.assertTrue(v(n, "rt_frida_maps"))
        self.assertEqual(v(n, "rt_frida_threads"), ["F126"])

    def test_native_counts_are_bare_numbers(self):
        n = norm(signals={"F149": 5, "F155": 4})
        self.assertTrue(v(n, "rt_code_patched"))
        self.assertIn("F149", n.used)

    def test_property_polarity(self):
        self.assertFalse(v(norm(signals={"F016": "0", "F017": "1"}), "root_dangerous_props"))
        self.assertTrue(v(norm(signals={"F016": "1"}), "root_dangerous_props"))
        self.assertTrue(v(norm(signals={"F017": "0"}), "root_dangerous_props"))

    def test_undecidable_signal_is_reported_and_dropped(self):
        n = norm(signals={"F146": "not a number", "F147": 0, "F148": 0, "F149": 0, "F150": 0, "F151": 0, "F152": 0,
                          "F153": 0, "F154": 0, "F155": 0, "F156": 0, "F157": 0, "F159": 0, "F163": 0, "F360": 0})
        self.assertIn("F146", n.undecidable)
        self.assertNotIn("F146", n.used)
        self.assertFalse(v(n, "rt_code_patched"))  # the rest of the family still answers

    def test_unmapped_alert_is_listed(self):
        n = norm(signals={"F065": ["RW", 3], "F113": ["External DEX mapped", 3]})
        self.assertEqual(n.unmapped_alerts, ["F065", "F113"])

    def test_emulator_identity_from_device_block(self):
        n = norm(device={"fingerprint": "google/sdk_gphone64_x86_64/emu64xa:15/AE3A:userdebug/dev-keys",
                         "model": "sdk_gphone64_x86_64"})
        self.assertTrue(v(n, "emu_fingerprint"))
        self.assertTrue(v(n, "emu_qemu_props"))

    def test_synthetic_sensors_and_failed_groups(self):
        n = norm(signals={"F231": 0, "F232": 0, "F233": 0, "F255": 3}, failed_groups=["timing", "sensor_touch"])
        self.assertTrue(v(n, "emu_static_sensors"))
        self.assertTrue(v(n, "emu_low_sensors"))
        self.assertEqual(n.probes["group_timing"]["status"], "error")

    def test_release_manifest_and_signing_certificate(self):
        sigs = {"F084": "a" * 32, "F086": "b" * 32}
        self.assertIsNone(normalize.apk_matches_release(sigs, []))
        self.assertTrue(normalize.apk_matches_release(sigs, [{"dex_digest": "a" * 32, "so_digest": "b" * 32}]))
        self.assertFalse(normalize.apk_matches_release(sigs, [{"dex_digest": "c" * 32, "so_digest": "b" * 32}]))
        full = "87a38338387e0d42d23d013b5500c2c3cc00986b737f96a85373fc1c9585b8bf"
        self.assertTrue(normalize.cert_matches({"F076": full}, [full]))
        self.assertTrue(normalize.cert_matches({"F076": "87a38338387e0d42..."}, [full]))   # prefix from older builds
        self.assertFalse(normalize.cert_matches({"F076": "00" * 16}, [full]))
        self.assertIsNone(normalize.cert_matches({"F076": "xyz"}, [full]))


if __name__ == "__main__":
    unittest.main()
