"""Android Key Attestation verification.

Verifies a certificate chain produced by AndroidKeyStore with
setAttestationChallenge(nonce) and extracts the KeyDescription extension
(OID 1.3.6.1.4.1.11129.2.1.17).

Trust model:
- The chain must verify link by link.
- The root's public key must match one of the trusted Google roots in
  roots/*.pem; otherwise the chain is "untrusted" and its claims are reported
  but must not be relied on (a self-made chain can claim anything).
- Every certificate serial is checked against Google's revocation list when
  that list could be loaded.
"""
import base64
import hashlib
import json
import logging
import os
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import der

log = logging.getLogger(__name__)

KEY_DESCRIPTION_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
REVOCATION_URL = "https://android.googleapis.com/attestation/status"
ROOTS_URL = "https://android.googleapis.com/attestation/root"

SECURITY_LEVELS = {0: "Software", 1: "TrustedEnvironment", 2: "StrongBox"}
BOOT_STATES = {0: "Verified", 1: "SelfSigned", 2: "Unverified", 3: "Failed"}

# AuthorizationList explicit tag numbers we read
TAG_ROOT_OF_TRUST = 704
TAG_OS_VERSION = 705
TAG_OS_PATCH = 706
TAG_APP_ID = 709
TAG_VENDOR_PATCH = 718
TAG_BOOT_PATCH = 719


@dataclass
class AttestationResult:
    chain_valid: bool = False
    root_trusted: bool = False
    revoked: bool = False
    revocation_checked: bool = False
    challenge: bytes = b""
    attestation_version: int | None = None
    security_level: str = "Unknown"
    keymint_security_level: str = "Unknown"
    verified_boot_state: str | None = None
    device_locked: bool | None = None
    os_version: int | None = None
    os_patch_level: int | None = None
    vendor_patch_level: int | None = None
    boot_patch_level: int | None = None
    package_names: list[str] = field(default_factory=list)
    signing_digests: list[str] = field(default_factory=list)  # hex sha256
    errors: list[str] = field(default_factory=list)
    leaf_public_key: object = None

    @property
    def hardware_backed(self) -> bool:
        return self.security_level in ("TrustedEnvironment", "StrongBox")

    @property
    def trustworthy(self) -> bool:
        """Claims can be relied on: valid chain to a Google root, not revoked."""
        return self.chain_valid and self.root_trusted and not self.revoked

    def summary(self) -> dict:
        return {
            "chain_valid": self.chain_valid,
            "root_trusted": self.root_trusted,
            "revoked": self.revoked,
            "revocation_checked": self.revocation_checked,
            "security_level": self.security_level,
            "verified_boot_state": self.verified_boot_state,
            "device_locked": self.device_locked,
            "os_patch_level": self.os_patch_level,
            "package_names": self.package_names,
            "signing_digests": self.signing_digests,
            "errors": self.errors,
        }


class TrustStore:
    """Trusted root public keys and the revocation list."""

    def __init__(self, roots_dir: Path, fetch_revocations: bool = True):
        self.root_keys: list[bytes] = []
        if roots_dir.is_dir():
            for p in sorted(roots_dir.glob("*.pem")):
                try:
                    for cert in x509.load_pem_x509_certificates(p.read_bytes()):
                        self.root_keys.append(_spki(cert))
                except Exception as e:  # noqa: BLE001
                    log.warning("could not load root %s: %s", p, e)
        online = fetch_revocations and os.environ.get("TRUSTPOC_OFFLINE") != "1"
        if online:
            self.fetch_google_roots(roots_dir)
        log.info("loaded %d trusted attestation root(s)", len(self.root_keys))
        self.revoked_serials: set[str] | None = None
        if online:
            self.refresh_revocations()

    def fetch_google_roots(self, roots_dir: Path) -> None:
        """Download Google's current attestation roots and cache them as PEM.

        The endpoint returns a JSON array whose schema is not documented, so accept
        PEM strings, base64 DER strings, or objects that contain either.
        """
        try:
            with urllib.request.urlopen(ROOTS_URL, timeout=5) as r:
                data = json.load(r)
        except Exception as e:  # noqa: BLE001
            log.warning("could not download Google roots (%s); using roots/*.pem only", e)
            return
        found: list[x509.Certificate] = []

        def visit(v):
            if isinstance(v, str):
                try:
                    if "BEGIN CERTIFICATE" in v:
                        found.extend(x509.load_pem_x509_certificates(v.encode()))
                    else:
                        found.append(x509.load_der_x509_certificate(base64.b64decode(v)))
                except Exception:  # noqa: BLE001
                    pass
            elif isinstance(v, list):
                for x in v:
                    visit(x)
            elif isinstance(v, dict):
                for x in v.values():
                    visit(x)

        visit(data)
        if not found:
            log.warning("Google roots response had no certificates I could parse")
            return
        roots_dir.mkdir(parents=True, exist_ok=True)
        (roots_dir / "google_roots.pem").write_bytes(
            b"".join(c.public_bytes(serialization.Encoding.PEM) for c in found))
        for c in found:
            k = _spki(c)
            if k not in self.root_keys:
                self.root_keys.append(k)
        log.info("downloaded %d Google attestation root(s)", len(found))

    def refresh_revocations(self) -> None:
        try:
            with urllib.request.urlopen(REVOCATION_URL, timeout=5) as r:
                data = json.load(r)
            self.revoked_serials = {k.lower() for k in data.get("entries", {})}
            log.info("loaded %d revoked attestation serials", len(self.revoked_serials))
        except Exception as e:  # noqa: BLE001
            log.warning("revocation list unavailable (%s); continuing without it", e)
            self.revoked_serials = None


def _spki(cert: x509.Certificate) -> bytes:
    return cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _authorization_list(tlv: der.TLV) -> dict[int, der.TLV]:
    out = {}
    for item in tlv.children():
        if item.cls == der.CONTEXT and item.constructed:
            inner = item.children()
            if inner:
                out[item.tag] = inner[0]
    return out


def parse_key_description(ext_value: bytes, res: AttestationResult) -> None:
    seq = der.parse_one(ext_value).children()
    if len(seq) < 8:
        raise der.DERError("KeyDescription too short")
    res.attestation_version = seq[0].as_int()
    res.security_level = SECURITY_LEVELS.get(seq[1].as_int(), "Unknown")
    res.keymint_security_level = SECURITY_LEVELS.get(seq[3].as_int(), "Unknown")
    res.challenge = seq[4].value
    sw = _authorization_list(seq[6])
    hw = _authorization_list(seq[7])
    merged = {**sw, **hw}  # hardware-enforced values win

    rot = merged.get(TAG_ROOT_OF_TRUST)
    if rot is not None:
        r = rot.children()
        res.device_locked = r[1].as_bool()
        res.verified_boot_state = BOOT_STATES.get(r[2].as_int(), "Unknown")
    for tag, attr in ((TAG_OS_VERSION, "os_version"), (TAG_OS_PATCH, "os_patch_level"),
                      (TAG_VENDOR_PATCH, "vendor_patch_level"), (TAG_BOOT_PATCH, "boot_patch_level")):
        if tag in merged:
            setattr(res, attr, merged[tag].as_int())

    app = merged.get(TAG_APP_ID)
    if app is not None:
        app_seq = der.parse_one(app.value).children()
        for info in app_seq[0].children():
            fields = info.children()
            res.package_names.append(fields[0].value.decode("utf-8", "replace"))
        if len(app_seq) > 1:
            res.signing_digests = [d.value.hex() for d in app_seq[1].children()]


def verify_chain(chain_b64: list[str], store: TrustStore) -> AttestationResult:
    res = AttestationResult()
    try:
        certs = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in chain_b64]
    except Exception as e:  # noqa: BLE001
        res.errors.append(f"cannot parse chain: {e}")
        return res
    if not certs:
        res.errors.append("empty chain")
        return res

    try:
        for child, issuer in zip(certs, certs[1:]):
            child.verify_directly_issued_by(issuer)
        certs[-1].verify_directly_issued_by(certs[-1])  # root is self-signed
        res.chain_valid = True
    except Exception as e:  # noqa: BLE001
        res.errors.append(f"chain does not verify: {e}")

    res.root_trusted = _spki(certs[-1]) in store.root_keys

    if store.revoked_serials is not None:
        res.revocation_checked = True
        serials = {format(c.serial_number, "x") for c in certs}
        res.revoked = bool(serials & store.revoked_serials)

    res.leaf_public_key = certs[0].public_key()
    try:
        ext = certs[0].extensions.get_extension_for_oid(KEY_DESCRIPTION_OID)
        parse_key_description(ext.value.value, res)
    except x509.ExtensionNotFound:
        res.errors.append("leaf has no key attestation extension")
    except Exception as e:  # noqa: BLE001
        res.errors.append(f"cannot parse key description: {e}")
    return res


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()
