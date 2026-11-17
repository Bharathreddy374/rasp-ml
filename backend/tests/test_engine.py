"""End-to-end tests of the scoring engine with synthetic attestation chains.

Run: python -m unittest discover -s tests -v   (from the backend folder)
"""
import base64
import datetime as dt
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ["TRUSTPOC_OFFLINE"] = "1"

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from trustpoc import der
from trustpoc.attestation import KEY_DESCRIPTION_OID
from trustpoc.engine import Engine

APP_CERT = b"fake-app-signing-certificate"
APP_DIGEST = hashlib.sha256(APP_CERT).hexdigest()
PKG = "com.example.trustdemo"


def key_description(challenge: bytes, level=1, locked=True, boot=0, digest=APP_DIGEST, pkg=PKG) -> bytes:
    app_id = der.enc_seq(
        der.enc_set(der.enc_seq(der.enc_octets(pkg.encode()), der.enc_int(1))),
        der.enc_set(der.enc_octets(bytes.fromhex(digest))))
    sw = der.enc_seq(der.enc_explicit(709, der.enc_octets(app_id)))
    rot = der.enc_seq(der.enc_octets(b"\x00" * 32), der.enc_bool(locked),
                      der.enc_int(boot, der.TAG_ENUMERATED), der.enc_octets(b"\x00" * 32))
    hw = der.enc_seq(der.enc_explicit(704, rot), der.enc_explicit(706, der.enc_int(202510)))
    return der.enc_seq(der.enc_int(300), der.enc_int(level, der.TAG_ENUMERATED), der.enc_int(300),
                       der.enc_int(level, der.TAG_ENUMERATED), der.enc_octets(challenge),
                       der.enc_octets(b""), sw, hw)


def make_cert(subject, pub, issuer, issuer_key, ext=None):
    name = lambda n: x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, n)])
    now = dt.datetime.now(dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(name(subject)).issuer_name(name(issuer))
         .public_key(pub).serial_number(x509.random_serial_number())
         .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30)))
    if ext is not None:
        b = b.add_extension(x509.UnrecognizedExtension(KEY_DESCRIPTION_OID, ext), critical=False)
    return b.sign(issuer_key, hashes.SHA256())


class Device:
    """Simulates the SDK: builds, attests and signs a payload."""

    def __init__(self, root_key):
        self.root_key = root_key
        self.root = make_cert("Root", root_key.public_key(), "Root", root_key)
        self.counter = 0

    def assess(self, engine, action="transfer", probes=None, nonce=None, kd_kwargs=None,
               reported_digest=APP_DIGEST, install_id="i_test"):
        if nonce is None:
            nonce = engine.issue_nonce(install_id, action)["nonce"]
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        inter_key = ec.generate_private_key(ec.SECP256R1())
        inter = make_cert("Intermediate", inter_key.public_key(), "Root", self.root_key)
        leaf = make_cert("Leaf", leaf_key.public_key(), "Intermediate", inter_key,
                         key_description(base64.b64decode(nonce), **(kd_kwargs or {})))
        self.counter += 1
        payload = {
            "schema": 1, "install_id": install_id, "action": action, "nonce": nonce,
            "counter": self.counter,
            "app": {"package": PKG, "cert_sha256": [reported_digest]},
            "device": {"model": "Test"},
            "probes": {k: {"status": "ok", "v": v} for k, v in (probes or {}).items()},
        }
        raw = json.dumps(payload).encode()
        sig = leaf_key.sign(raw, ec.ECDSA(hashes.SHA256()))
        chain = [base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode()
                 for c in (leaf, inter, self.root)]
        return engine.assess(base64.b64encode(raw).decode(), base64.b64encode(sig).decode(), chain), raw, sig, chain


class EngineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        roots = self.tmp / "roots"
        roots.mkdir()
        root_key = ec.generate_private_key(ec.SECP256R1())
        self.device = Device(root_key)
        (roots / "google.pem").write_bytes(self.device.root.public_bytes(serialization.Encoding.PEM))
        cfg = {"expected_package": PKG, "expected_cert_sha256": [APP_DIGEST]}
        self.engine = Engine(self.tmp / "data", roots, cfg, fetch_revocations=False)

    def last(self):
        return self.engine.decisions[0]

    def test_genuine_device_is_level_1(self):
        res, *_ = self.device.assess(self.engine)
        self.assertEqual(res["trust_level"], 1, self.last()["reasons"])
        self.assertEqual(res["outcome"], "allow")

    def test_replayed_nonce_is_critical(self):
        nonce = self.engine.issue_nonce("i_test", "transfer")["nonce"]
        self.device.assess(self.engine, nonce=nonce)
        res, *_ = self.device.assess(self.engine, nonce=nonce)
        self.assertEqual(res["trust_level"], 5)
        self.assertIn("AT_NONCE_INVALID", self.last()["reasons"])

    def test_nonce_for_other_action_is_critical(self):
        nonce = self.engine.issue_nonce("i_test", "login")["nonce"]
        res, *_ = self.device.assess(self.engine, action="transfer", nonce=nonce)
        self.assertIn("AT_NONCE_BINDING", self.last()["reasons"])
        self.assertEqual(res["trust_level"], 5)

    def test_tampered_payload_signature(self):
        nonce = self.engine.issue_nonce("i_test", "transfer")["nonce"]
        _, raw, sig, chain = self.device.assess(self.engine, nonce=nonce)
        # attacker edits the probes after signing, with a fresh nonce
        p = json.loads(raw)
        p["nonce"] = self.engine.issue_nonce("i_test", "transfer")["nonce"]
        res = self.engine.assess(base64.b64encode(json.dumps(p).encode()).decode(),
                                 base64.b64encode(sig).decode(), chain)
        self.assertIn("AT_PAYLOAD_SIGNATURE_INVALID", self.last()["reasons"])
        self.assertEqual(res["trust_level"], 5)

    def test_frida_alone_is_high_risk(self):
        res, *_ = self.device.assess(self.engine, probes={"rt_frida_threads": ["gum-js-loop"]})
        self.assertEqual(res["trust_level"], 4)

    def test_emulator_plus_frida_is_critical(self):
        res, *_ = self.device.assess(self.engine, probes={
            "rt_frida_maps": True, "emu_fingerprint": True, "emu_hardware": True})
        self.assertEqual(res["trust_level"], 5)

    def test_two_root_signals_count_once(self):
        res, *_ = self.device.assess(self.engine, probes={
            "root_su_paths": ["/system/bin/su"], "root_magisk_mounts": True})
        self.assertEqual(res["trust_level"], 4)

    def test_repackaged_app_is_critical(self):
        res, *_ = self.device.assess(self.engine, kd_kwargs={"digest": "ab" * 32},
                                     reported_digest="ab" * 32)
        self.assertIn("AP_SIGNATURE_MISMATCH", self.last()["reasons"])
        self.assertEqual(res["trust_level"], 5)

    def test_developer_options_is_step_up_not_block(self):
        res, *_ = self.device.assess(self.engine, probes={"ctx_developer_options": True,
                                                          "ctx_adb_enabled": True})
        self.assertEqual(res["trust_level"], 3)
        self.assertEqual(res["outcome"], "step_up")

    def test_unlocked_bootloader_is_developer_class(self):
        res, *_ = self.device.assess(self.engine, kd_kwargs={"locked": False, "boot": 2})
        self.assertEqual(res["trust_level"], 5)  # unverified OS is Tier A
        res, *_ = self.device.assess(self.engine, kd_kwargs={"locked": False, "boot": 1})
        self.assertEqual(res["trust_level"], 3)

    def test_software_attestation_is_reduced_assurance(self):
        res, *_ = self.device.assess(self.engine, kd_kwargs={"level": 0})
        self.assertEqual(res["trust_level"], 2)
        self.assertTrue(self.last()["reduced_assurance"])

    def test_untrusted_root_claims_ignored(self):
        other = Device(ec.generate_private_key(ec.SECP256R1()))
        res, *_ = other.assess(self.engine, kd_kwargs={"locked": False, "boot": 3})
        self.assertIn("AT_UNTRUSTED_ROOT", self.last()["reasons"])
        self.assertNotIn("AT_BOOT_FAILED", self.last()["reasons"])
        self.assertEqual(res["trust_level"], 2)

    def test_probe_errors_are_context_only(self):
        res, *_ = self.device.assess(self.engine)
        payload_probes = {f"p{i}": {"status": "error"} for i in range(5)}
        nonce = self.engine.issue_nonce("i_test", "transfer")["nonce"]
        # reuse the device path with error probes injected
        dev = self.device
        out, *_ = dev.assess(self.engine, nonce=nonce)
        self.assertEqual(out["trust_level"], 1)
        from trustpoc import rules
        ev = rules.Evidence()
        rules.evaluate_probes({"probes": payload_probes}, ev)
        self.assertEqual(rules.decide_level(ev), 2)

    def test_bank_verifies_signed_decision(self):
        res, *_ = self.device.assess(self.engine, action="transfer")
        ok = self.engine.bank_check(res["decision_jws"], "transfer")
        self.assertEqual(ok["result"], "allow")
        wrong = self.engine.bank_check(res["decision_jws"], "add_payee")
        self.assertEqual(wrong["result"], "block")
        forged = self.engine.bank_check(res["decision_jws"][:-4] + "AAAA", "transfer")
        self.assertEqual(forged["result"], "block")


if __name__ == "__main__":
    unittest.main()


class ShadowTest(unittest.TestCase):
    def test_shadow_scores_but_never_changes_level(self):
        from trustpoc.ml import ShadowModels
        import numpy as np
        from trustpoc.features import extract, FEATURES
        from trustpoc.synth import generate, FAMILIES
        sess = generate(n_genuine=400, n_per_family=60, seed=1)
        X = np.array([extract(p) for p, _, _ in sess], dtype=float)
        Y = {f: np.array([l[f] for _, l, _ in sess]) for f in FAMILIES}
        g = np.array([v == "genuine" for _, _, v in sess])
        tmp = Path(tempfile.mkdtemp())
        ShadowModels().fit(X, Y, g, {"version": "t", "data": "synthetic"}).save(tmp / "data" / "shadow_model.pkl")
        roots = tmp / "roots"; roots.mkdir()
        dev = Device(ec.generate_private_key(ec.SECP256R1()))
        (roots / "r.pem").write_bytes(dev.root.public_bytes(serialization.Encoding.PEM))
        eng = Engine(tmp / "data", roots, {"expected_package": PKG, "expected_cert_sha256": [APP_DIGEST]},
                     fetch_revocations=False)
        self.assertIsNotNone(eng.shadow)
        res, *_ = dev.assess(eng, probes={"rt_frida_threads": ["gum-js-loop"], "rt_frida_maps": True})
        rec = eng.decisions[0]
        self.assertGreaterEqual(res["trust_level"], 4)  # rules guard: never below rules
        self.assertIn("instrumentation", rec["ml"]["heads"])
        self.assertEqual(len(FEATURES), 25)
        self.assertIsNotNone(eng.shadow.ae)  # autoencoder trained alongside Isolation Forest
        self.assertTrue((tmp / "data" / "sessions.jsonl").exists())  # data collection for future training
