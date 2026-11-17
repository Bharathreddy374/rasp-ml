"""Device simulator: sends realistic signed, attested payloads to the POC server.

Use it to rehearse the demo, or as a backup if the phone or emulator misbehaves.
It creates its own test attestation root. Pass --trust-sim-root once to add
that root to roots/ so simulated "genuine" devices can reach Level 1.
That root is for the POC only: delete roots/sim_root.pem before any real test.

  python simulate.py --trust-sim-root          # one-time setup
  python simulate.py all                       # run every scenario
  python simulate.py genuine frida replay      # run some
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import sys
import time
import urllib.request
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from trustpoc import der
from trustpoc.attestation import KEY_DESCRIPTION_OID
from trustpoc.synth import genuine_base
import random

BASE = Path(__file__).resolve().parent
SIM_DIR = BASE / "data" / "sim"
PKG = "com.example.trustdemo"
GENUINE_CERT = b"trustdemo-genuine-signing-cert"
REPACK_CERT = b"attacker-resigned-cert"


def http(server, path, body):
    req = urllib.request.Request(server + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)


def name(n):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, n)])


def cert(subject, pub, issuer, key, ext=None, days=3650):
    now = dt.datetime.now(dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(name(subject)).issuer_name(name(issuer)).public_key(pub)
         .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
         .not_valid_after(now + dt.timedelta(days=days)))
    if ext:
        b = b.add_extension(x509.UnrecognizedExtension(KEY_DESCRIPTION_OID, ext), critical=False)
    return b.sign(key, hashes.SHA256())


def sim_root():
    SIM_DIR.mkdir(parents=True, exist_ok=True)
    kp, cp = SIM_DIR / "root_key.pem", SIM_DIR / "root_cert.pem"
    if kp.exists():
        key = serialization.load_pem_private_key(kp.read_bytes(), None)
        return key, x509.load_pem_x509_certificate(cp.read_bytes())
    key = ec.generate_private_key(ec.SECP256R1())
    c = cert("POC Simulator Attestation Root", key.public_key(), "POC Simulator Attestation Root", key)
    kp.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption()))
    cp.write_bytes(c.public_bytes(serialization.Encoding.PEM))
    return key, c


def key_description(challenge, level=1, locked=True, boot=0, app_cert=GENUINE_CERT):
    digest = hashlib.sha256(app_cert).digest()
    app_id = der.enc_seq(der.enc_set(der.enc_seq(der.enc_octets(PKG.encode()), der.enc_int(1))),
                         der.enc_set(der.enc_octets(digest)))
    sw = der.enc_seq(der.enc_explicit(709, der.enc_octets(app_id)))
    rot = der.enc_seq(der.enc_octets(b"\x00" * 32), der.enc_bool(locked),
                      der.enc_int(boot, der.TAG_ENUMERATED), der.enc_octets(b"\x00" * 32))
    hw = der.enc_seq(der.enc_explicit(704, rot), der.enc_explicit(706, der.enc_int(202510)))
    return der.enc_seq(der.enc_int(300), der.enc_int(level, der.TAG_ENUMERATED), der.enc_int(300),
                       der.enc_int(level, der.TAG_ENUMERATED), der.enc_octets(challenge),
                       der.enc_octets(b""), sw, hw)


PHONE = {"manufacturer": "Samsung", "model": "Galaxy A54 (simulated)", "release": "15", "sdk_int": 35,
         "fingerprint": "samsung/a54xnsxx/a54x:15/AP3A/...:user/release-keys", "hardware": "s5e8835"}
EMU = {"manufacturer": "Google", "model": "sdk_gphone64_x86_64 (simulated)", "release": "15", "sdk_int": 35,
       "fingerprint": "google/sdk_gphone64_x86_64/emu64xa:15/AE3A/...:userdebug/dev-keys", "hardware": "ranchu"}
FRIDA = {"rt_frida_threads": ["gum-js-loop", "gmain"], "rt_frida_maps": True}
EMULATOR = {"emu_fingerprint": True, "emu_hardware": True, "emu_qemu_props": True, "props_test_keys": True,
            "sensor_count": 6, "ctx_developer_options": True, "ctx_adb_enabled": True}

SCENARIOS = {
    "genuine": dict(title="Genuine phone", action="transfer", device=PHONE, probes={}),
    "developer": dict(title="Genuine phone, developer options + USB debugging on", action="add_payee",
                      device=PHONE, probes={"ctx_developer_options": True, "ctx_adb_enabled": True}),
    "frida": dict(title="Frida attached to the banking app", action="transfer", device=PHONE, probes=FRIDA),
    "rooted": dict(title="Magisk-rooted phone", action="login", device=PHONE,
                   probes={"root_manager_packages": ["com.topjohnwu.magisk"], "root_magisk_mounts": True},
                   kd=dict(locked=False, boot=2)),
    "emulator": dict(title="Emulator with Frida (automated attack)", action="transfer", device=EMU,
                     probes={**EMULATOR, **FRIDA}, kd=dict(level=0)),
    "repackaged": dict(title="Repackaged APK, re-signed by attacker", action="transfer", device=PHONE,
                       probes={}, kd=dict(app_cert=REPACK_CERT), reported_cert=REPACK_CERT),
    "replay": dict(title="Replay of a captured genuine request", action="transfer", device=PHONE,
                   probes={}, replay=True),
}


class SimDevice:
    def __init__(self, server, install_id):
        self.server, self.install_id = server, install_id
        self.counter = int(time.time() * 1000)  # monotonic across simulator runs, like the app's stored counter
        self.root_key, self.root = sim_root()

    def build(self, sc, nonce):
        leaf_key = ec.generate_private_key(ec.SECP256R1())
        inter_key = ec.generate_private_key(ec.SECP256R1())
        inter = cert("Sim Intermediate", inter_key.public_key(), "POC Simulator Attestation Root", self.root_key)
        leaf = cert("Android Keystore Key", leaf_key.public_key(), "Sim Intermediate", inter_key,
                    key_description(base64.b64decode(nonce), **sc.get("kd", {})), days=365)
        self.counter += 1
        payload = {
            "schema": 1, "install_id": self.install_id, "action": sc["action"], "nonce": nonce,
            "counter": self.counter, "ts": int(time.time() * 1000),
            "app": {"package": PKG, "version_code": 1,
                    "cert_sha256": [hashlib.sha256(sc.get("reported_cert", GENUINE_CERT)).hexdigest()]},
            "device": sc["device"],
            "probes": self.probes(sc),
        }
        raw = json.dumps(payload).encode()
        sig = leaf_key.sign(raw, ec.ECDSA(hashes.SHA256()))
        chain = [base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode() for c in (leaf, inter, self.root)]
        return {"payload": base64.b64encode(raw).decode(), "signature": base64.b64encode(sig).decode(), "chain": chain}

    def probes(self, sc):
        """A full, realistic probe set: a genuine baseline with the scenario's signals on top."""
        r = random.Random(self.counter % 100000)
        values = genuine_base(r)
        values.update({"ctx_developer_options": False, "ctx_adb_enabled": False,
                       "ctx_accessibility_services": [], "ctx_vpn": False, "sensor_count": 31})
        values.update(sc["probes"])
        slow = 1.6 if any(k.startswith("rt_frida") for k in sc["probes"]) else 1.0
        return {k: {"status": "ok", "v": v, "ms": round(r.lognormvariate(-1.2, 0.4) * slow, 3)}
                for k, v in values.items()}

    def run(self, key):
        sc = SCENARIOS[key]
        nonce = http(self.server, "/v1/nonce", {"install_id": self.install_id, "action": sc["action"]})["nonce"]
        body = self.build(sc, nonce)
        res = http(self.server, "/v1/assess", body)
        if sc.get("replay"):
            time.sleep(0.5)
            res = http(self.server, "/v1/assess", body)  # same nonce, same signature
        bank = http(self.server, "/v1/bank/check", {"decision_jws": res["decision_jws"], "action": sc["action"]})
        print(f"  {sc['title']:<55} Level {res['trust_level']}  {res['outcome']:<8} bank: {bank['result']}")
        return res


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("scenarios", nargs="*", default=[], help=f"all (default) or any of: {', '.join(SCENARIOS)}")
    ap.add_argument("--server", default="http://localhost:8000")
    ap.add_argument("--trust-sim-root", action="store_true", help="copy the simulator root into roots/ (POC only)")
    ap.add_argument("--delay", type=float, default=1.5, help="seconds between scenarios, for a live audience")
    a = ap.parse_args()

    if a.trust_sim_root:
        _, root = sim_root()
        (BASE / "roots").mkdir(exist_ok=True)
        (BASE / "roots" / "sim_root.pem").write_bytes(root.public_bytes(serialization.Encoding.PEM))
        print("Simulator root added to roots/sim_root.pem. Restart the server, and delete this file before real tests.")
        if not a.scenarios:
            return

    keys = list(SCENARIOS) if a.scenarios in ([], ["all"]) else a.scenarios
    unknown = [k for k in keys if k not in SCENARIOS]
    if unknown:
        ap.error(f"unknown scenario(s): {unknown}")
    dev = SimDevice(a.server.rstrip("/"), "i_sim_" + hashlib.sha256(a.server.encode()).hexdigest()[:8])
    # register the simulator's genuine build so repackaging can be detected
    http(dev.server, "/v1/admin/trust-digest", {"cert_sha256": hashlib.sha256(GENUINE_CERT).hexdigest()})
    for i, k in enumerate(keys):
        dev.run(k)
        if i < len(keys) - 1:
            time.sleep(a.delay)


if __name__ == "__main__":
    main()
