"""Key attestation, payload signature, nonce replay, key history (F307/F308, F316-F324, F337),
timezone vs IP country (F290) and edge-proxy fields (F296/F297/F302).

The chains are built here with a test root that the TrustStore is told to trust; the
KeyDescription extension is encoded the way AndroidKeyStore does it.
"""
import base64
import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

os.environ.setdefault("TRUSTPOC_OFFLINE", "1")

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from helpers import call, phone, small_model_dir
from trustpoc import der, retrieval
from trustpoc.api import Settings, create_app
from trustpoc.attestation import KEY_DESCRIPTION_OID, TrustStore
from trustpoc.geo import GeoIP
from trustpoc.integrity import Challenger
from trustpoc.pipeline import Pipeline
from trustpoc.schema import CollectPayload
from trustpoc.scoring import ModelService
from trustpoc.store import MemoryStore

CERT = "125ae53a90d2d8e10060a2ff82b1164ef50e33f87668bab3539cf0a263ea6b3e"
CONFIG = {"expected_cert_sha256": [CERT], "expected_packages": ["com.example.demo"], "release_manifests": []}
CTX = {"sim_country": "IN", "network_country": "in", "timezone": "Asia/Kolkata", "locale": "en-IN",
       "network_type": "wifi", "boot_count": 40, "uptime_ms": 3_600_000, "android_id_hash": "a" * 64}
SECRET = b"test-challenge-secret"


def key_description(challenge: bytes, level=1, locked=True, boot=0, os_version=160000, patch=202610,
                    package="com.example.demo", digest=CERT, created=None) -> bytes:
    created = created or datetime.now(timezone.utc)
    app_id = der.enc_seq(der.enc_set(der.enc_seq(der.enc_octets(package.encode()), der.enc_int(1))),
                         der.enc_set(der.enc_octets(bytes.fromhex(digest))))
    sw = der.enc_seq(der.enc_explicit(701, der.enc_int(int(created.timestamp() * 1000))),
                     der.enc_explicit(709, der.enc_octets(app_id)))
    rot = der.enc_seq(der.enc_octets(b"\x01" * 32), der.enc_bool(locked), der.enc_int(boot, der.TAG_ENUMERATED),
                      der.enc_octets(b"\x02" * 32))
    hw = der.enc_seq(der.enc_explicit(704, rot), der.enc_explicit(705, der.enc_int(os_version)),
                     der.enc_explicit(706, der.enc_int(patch)), der.enc_explicit(718, der.enc_int(20261005)))
    return der.enc_seq(der.enc_int(300), der.enc_int(level, der.TAG_ENUMERATED), der.enc_int(300),
                       der.enc_int(level, der.TAG_ENUMERATED), der.enc_octets(challenge), der.enc_octets(b""), sw, hw)


def _cert(subject, issuer, pub, signer, ext=None, ca=False):
    now = datetime.now(timezone.utc)
    b = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)])).public_key(pub)
         .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
         .not_valid_after(now + timedelta(days=365))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ext is not None:
        b = b.add_extension(x509.UnrecognizedExtension(KEY_DESCRIPTION_OID, ext), critical=False)
    return b.sign(signer, hashes.SHA256())


class Pki:
    def __init__(self):
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.root = _cert("Test Google root", "Test Google root", self.root_key.public_key(), self.root_key, ca=True)
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.ca = _cert("Test attestation key", "Test Google root", self.ca_key.public_key(), self.root_key, ca=True)

    def install_key(self, challenge: bytes, **kd):
        """(private key, chain as base64 DER list) like AndroidKeyStore returns them."""
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = _cert("Android Keystore Key", "Test attestation key", key.public_key(), self.ca_key,
                     ext=key_description(challenge, **kd))
        der_b64 = [base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode() for c in (leaf, self.ca, self.root)]
        return key, der_b64


def sign(key, body: bytes) -> str:
    return base64.b64encode(key.sign(body, ec.ECDSA(hashes.SHA256()))).decode()


class AttestationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki = Pki()
        cls.geo_dir = Path(tempfile.mkdtemp())
        (cls.geo_dir / "dbip-country-lite.csv").write_text(
            "52.95.0.0,52.95.255.255,US\n49.36.0.0,49.36.255.255,IN\n", encoding="utf-8")
        (cls.geo_dir / "dbip-asn-lite.csv").write_text(
            "52.95.0.0,52.95.255.255,16509,Amazon.com Inc.\n49.36.0.0,49.36.255.255,55836,Reliance Jio Infocomm\n",
            encoding="utf-8")

    def setUp(self):
        self.store = MemoryStore()
        self.trust = TrustStore(Path(tempfile.mkdtemp()), online=False)
        self.trust.add_root(self.pki.root)
        self.challenger = Challenger(SECRET)
        self.pipe = Pipeline(self.store, ModelService(small_model_dir(), "enforce"), CONFIG, GeoIP(self.geo_dir),
                             self.trust, self.challenger)

    def send(self, session, key, chain, nonce=None, install_id=None, ip="49.36.1.1", tamper=False, ctx=CTX,
             pipe=None, **req):
        nonce = nonce or self.challenger.issue()
        p = phone(session, install_id=install_id)
        p["device_context"] = dict(ctx)
        p["attestation"] = {"nonce": nonce, "chain": chain}
        body = json.dumps(p).encode()
        signature = sign(key, body + (b" " if tamper else b""))
        facts = retrieval.Request(client_ip=ip, user_agent="Dalvik/2.1.0", payload_bytes=len(body),
                                  signature=signature, **req)
        return (pipe or self.pipe).run(CollectPayload.model_validate_json(body), facts, body)

    def first(self, session="s1", install_id=None, **kd):
        nonce = self.challenger.issue()
        key, chain = self.pki.install_key(base64.b64decode(nonce), **kd)
        return key, chain, self.send(session, key, chain, nonce=nonce, install_id=install_id)

    @staticmethod
    def codes(res):
        return {r["code"] for r in res["decision"]["reasons"]}

    def test_genuine_attested_session(self):
        _, _, res = self.first()
        ss = res["retrieved"]["server_signals"]
        self.assertEqual(res["decision"]["assurance"], "attested")
        self.assertEqual(ss["F001"], True)
        self.assertEqual(ss["F003"], "TEE")
        self.assertEqual(ss["F004"], "Verified")
        self.assertEqual(ss["F005"], True)
        self.assertEqual(ss["F006"], 202610)
        self.assertEqual((ss["F008"], ss["F009"], ss["F010"], ss["F321"], ss["F364"]), (True, True, True, True, True))
        self.assertEqual(ss["F025"], False)
        self.assertEqual(ss["F324"], 1)
        self.assertEqual(ss["F337"], 1)
        self.assertEqual((ss["F316"], ss["F320"]), (0, 1))
        self.assertNotIn("F002", ss)          # offline: revocation list not loaded
        self.assertFalse({c for c in self.codes(res) if c.startswith("AT_")})
        self.assertEqual(res["decision"]["attestation"]["security_level"], "TEE")

    def test_stored_session_shows_the_attestation(self):
        key, chain, res = self.first()
        again = self.send("s1", key, chain)                           # client retry: stored result
        self.assertTrue(again["duplicate"])
        for d in (again["decision"], self.store.get(res["id"]) and __import__("trustpoc.pipeline").pipeline.render(
                self.store.get(res["id"]), duplicate=True)["decision"]):
            self.assertEqual(d["assurance"], "attested")
            self.assertEqual(d["attestation"]["security_level"], "TEE")

    def test_second_session_uses_the_same_key(self):
        key, chain, _ = self.first()
        res = self.send("s2", key, chain)
        ss = res["retrieved"]["server_signals"]
        self.assertEqual(res["decision"]["assurance"], "attested")
        self.assertEqual(ss["F321"], False)          # key was created in the first session
        self.assertEqual((ss["F307"], ss["F308"], ss["F318"]), (False, False, False))
        self.assertEqual((ss["F316"], ss["F320"]), (0, 1))

    def test_replayed_nonce_fails(self):
        nonce = self.challenger.issue()
        key, chain = self.pki.install_key(base64.b64decode(nonce))
        self.send("s1", key, chain, nonce=nonce)
        res = self.send("s2", key, chain, nonce=nonce)
        self.assertEqual(res["decision"]["assurance"], "failed")
        self.assertIs(res["retrieved"]["server_signals"]["F364"], False)
        self.assertIn("AT_NONCE_INVALID", self.codes(res))

    def test_forged_nonce_and_bad_signature(self):
        key, chain, _ = self.first()
        res = self.send("s2", key, chain, nonce=base64.b64encode(os.urandom(40)).decode(), tamper=True)
        self.assertEqual(res["decision"]["assurance"], "failed")
        self.assertTrue({"AT_NONCE_INVALID", "AT_SIGNATURE_INVALID"} <= self.codes(res))

    def test_key_made_for_another_servers_challenge(self):
        other = Challenger(b"some-other-secret").issue()
        key, chain = self.pki.install_key(base64.b64decode(other))
        res = self.send("s1", key, chain)                  # this request's own nonce is fine
        self.assertIs(res["retrieved"]["server_signals"]["F010"], False)
        self.assertEqual(res["decision"]["assurance"], "failed")
        self.assertIn("AT_CHALLENGE_UNKNOWN", self.codes(res))
        self.assertIs(res["decision"]["attestation"]["challenge_issued_here"], False)

    def test_untrusted_root(self):
        other = Pki()
        nonce = self.challenger.issue()
        key, chain = other.install_key(base64.b64decode(nonce))
        res = self.send("s1", key, chain, nonce=nonce)
        self.assertIs(res["retrieved"]["server_signals"]["F001"], False)
        self.assertIn("AT_UNTRUSTED_CHAIN", self.codes(res))
        self.assertIn("F025", res["retrieved"]["not_computed"])
        self.assertEqual(res["decision"]["assurance"], "failed")

    def test_unlocked_bootloader_and_wrong_app(self):
        _, _, res = self.first(locked=False, boot=2, package="com.evil.clone", digest="00" * 32)
        self.assertTrue({"AT_BOOTLOADER_UNLOCKED", "AT_APP_CERT_MISMATCH", "AT_PACKAGE_MISMATCH"} <= self.codes(res))
        self.assertGreaterEqual(res["decision"]["level"], 5)

    def test_software_key_and_props_mismatch(self):
        _, _, res = self.first(level=0, patch=202301)
        self.assertEqual(res["retrieved"]["server_signals"]["F025"], True)
        self.assertTrue({"AT_SOFTWARE_KEY", "AT_PROPS_MISMATCH"} <= self.codes(res))

    def test_key_shared_by_two_installs(self):
        key, chain, _ = self.first(install_id="i_one")
        res = self.send("s9", key, chain, install_id="i_two")
        self.assertEqual(res["retrieved"]["server_signals"]["F324"], 2)
        self.assertIn("AT_KEY_SHARED", self.codes(res))

    def test_boot_regressed_and_lock_changed(self):
        self.first("s1")
        _, _, res = self.first("s2", locked=False, boot=2)
        ss = res["retrieved"]["server_signals"]
        self.assertEqual((ss["F307"], ss["F308"]), (True, True))
        self.assertEqual((ss["F316"], ss["F320"]), (1, 2))
        self.assertEqual(ss["F318"], False)
        self.assertTrue({"AT_BOOT_REGRESSED", "AT_LOCK_STATE_CHANGED"} <= self.codes(res))

    def test_no_attestation_is_unverified(self):
        p = phone("s1")
        p["device_context"] = dict(CTX)
        res = self.pipe.run(CollectPayload.model_validate_json(json.dumps(p)),
                            retrieval.Request(client_ip="49.36.1.1", user_agent="x", payload_bytes=10))
        self.assertEqual(res["decision"]["assurance"], "unverified")
        self.assertIn("F001", res["retrieved"]["not_computed"])

    def test_timezone_vs_ip_country(self):
        key, chain, res = self.first()
        self.assertIs(res["retrieved"]["server_signals"]["F290"], False)          # Asia/Kolkata from India
        res = self.send("s2", key, chain, ip="52.95.1.1")
        self.assertIs(res["retrieved"]["server_signals"]["F290"], True)           # Asia/Kolkata from the US
        self.assertIn("CX_TIMEZONE_MISMATCH", self.codes(res))
        res = self.send("s3", key, chain, ip="52.95.1.1", ctx={**CTX, "timezone": "America/New_York"})
        self.assertIs(res["retrieved"]["server_signals"]["F290"], False)
        self.assertIs(retrieval.timezone_fits_country("Asia/Calcutta", "IN", datetime.now(timezone.utc)), True)
        self.assertIsNone(retrieval.timezone_fits_country("Mars/Base", "IN", datetime.now(timezone.utc)))

    def test_edge_fields(self):
        key, chain, _ = self.first()
        res = self.send("s2", key, chain, ja3="771,4865-4866", rtt_ms=42.0)
        ss, nc = res["retrieved"]["server_signals"], res["retrieved"]["not_computed"]
        self.assertEqual((ss["F296"], ss["F302"]), ("771,4865-4866", 42.0))
        self.assertIn("F297", nc)            # cohort too small
        for i in range(retrieval.JA3_COHORT_MIN):
            self.send(f"c{i}", key, chain, ja3="771,4865-4866" if i % 2 else "other")
        res = self.send("s3", key, chain, ja3="771,4865-4866")
        self.assertAlmostEqual(res["retrieved"]["server_signals"]["F297"], 11 / 21, places=3)


class ApiEdgeTest(unittest.TestCase):
    def make(self, **kw):
        settings = Settings(store="memory", config_path=Path(tempfile.mkdtemp()) / "none.json", **kw)
        trust = TrustStore(Path(tempfile.mkdtemp()), online=False)
        return create_app(settings, MemoryStore(), ModelService(small_model_dir(), "enforce"), trust, Challenger(SECRET))

    def test_challenge_endpoint(self):
        status, body = call(self.make(), "GET", "/v1/challenge")
        self.assertEqual(status, 200)
        self.assertIsNotNone(Challenger(SECRET).parse(base64.b64decode(body["nonce"])))
        status, _ = call(self.make(collect_api_key="k"), "GET", "/v1/challenge")
        self.assertEqual(status, 401)

    def test_edge_headers_need_the_edge_secret(self):
        hdr = {"x-ja3-hash": "abc", "x-client-rtt-ms": "31"}
        _, body = call(self.make(edge_secret="e"), "POST", "/v1/collect", phone("s1"), hdr)
        self.assertNotIn("F296", body["retrieved"]["server_signals"])                 # forged by the client
        _, body = call(self.make(edge_secret="e"), "POST", "/v1/collect", phone("s1"), {**hdr, "x-edge-secret": "e"})
        ss = body["retrieved"]["server_signals"]
        self.assertEqual((ss["F296"], ss["F302"]), ("abc", 31.0))
        _, body = call(self.make(trust_proxy=True), "POST", "/v1/collect", phone("s1"), hdr)
        self.assertNotIn("F296", body["retrieved"]["server_signals"])                 # TRUST_PROXY alone is not enough


if __name__ == "__main__":
    unittest.main()
