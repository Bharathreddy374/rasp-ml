"""Android Key Attestation: verify the certificate chain of the app's install key.

The app creates one signing key per install in AndroidKeyStore with a server nonce as the
attestation challenge. The keystore (TEE / StrongBox) then issues a certificate chain whose
leaf carries the KeyDescription extension (OID 1.3.6.1.4.1.11129.2.1.17): security level,
verified-boot state, bootloader lock, OS / vendor patch levels, package name and signing
certificate digests, and the challenge.

Trust model
  - The chain must verify link by link, and its root's public key must be one of Google's
    attestation roots. Otherwise the claims are reported but must not be relied on: anyone
    can build a chain that claims anything.
  - Every serial is checked against Google's revocation list (refreshed every 6 hours).
  - Roots and the revocation list are downloaded from Google at startup and cached in
    data/attestation_roots/. Set TRUSTPOC_OFFLINE=1 to skip the downloads (tests).
"""
import base64
import hashlib
import json
import logging
import os
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import der

log = logging.getLogger(__name__)

KEY_DESCRIPTION_OID = x509.ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17")
REVOCATION_URL = "https://android.googleapis.com/attestation/status"
ROOTS_URL = "https://android.googleapis.com/attestation/root"
REVOCATION_TTL_S = 6 * 3600

SECURITY_LEVELS = {0: "Software", 1: "TEE", 2: "StrongBox"}
BOOT_STATES = {0: "Verified", 1: "SelfSigned", 2: "Unverified", 3: "Failed"}

# AuthorizationList explicit tags (KeyMint / Keymaster)
TAG_CREATION_DATETIME = 701
TAG_ROOT_OF_TRUST = 704
TAG_OS_VERSION = 705
TAG_OS_PATCH = 706
TAG_APP_ID = 709
TAG_VENDOR_PATCH = 718
TAG_BOOT_PATCH = 719


@dataclass
class ChainResult:
    parsed: bool = False
    chain_valid: bool = False          # every link verifies
    root_trusted: bool = False         # root is a Google attestation root
    revoked: bool = False
    revocation_checked: bool = False
    challenge: bytes = b""
    attestation_version: int | None = None
    security_level: str | None = None  # Software | TEE | StrongBox
    verified_boot_state: str | None = None
    device_locked: bool | None = None
    os_version: int | None = None      # e.g. 160000 for Android 16
    os_patch_level: int | None = None  # YYYYMM
    vendor_patch_level: int | None = None  # YYYYMMDD
    boot_patch_level: int | None = None
    created_at: datetime | None = None
    package_names: list[str] = field(default_factory=list)
    signing_digests: list[str] = field(default_factory=list)   # hex SHA-256 of the app's signing certs
    key_fp: str | None = None          # SHA-256 of the leaf public key: identifies the install key
    ca_fp: str | None = None           # SHA-256 of the certificate that issued the leaf (attestation key)
    errors: list[str] = field(default_factory=list)
    leaf_public_key: object = None

    @property
    def trustworthy(self) -> bool:
        """The claims can be relied on: valid chain to a Google root, not revoked."""
        return self.chain_valid and self.root_trusted and not self.revoked

    def summary(self) -> dict:
        return {
            "chain_valid": self.chain_valid, "root_trusted": self.root_trusted, "revoked": self.revoked,
            "revocation_checked": self.revocation_checked, "security_level": self.security_level,
            "verified_boot_state": self.verified_boot_state, "device_locked": self.device_locked,
            "os_version": self.os_version, "os_patch_level": self.os_patch_level,
            "vendor_patch_level": self.vendor_patch_level,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "package_names": self.package_names, "signing_digests": self.signing_digests,
            "key_fp": self.key_fp, "ca_fp": self.ca_fp, "errors": self.errors,
        }


class TrustStore:
    """Google's attestation root keys and the revocation list."""

    def __init__(self, cache_dir: Path, online: bool | None = None):
        self.cache_dir = cache_dir
        self.online = (os.environ.get("TRUSTPOC_OFFLINE") != "1") if online is None else online
        self.root_keys: set[bytes] = set()
        self.revoked_serials: set[str] | None = None
        self._revocations_at = 0.0
        self._lock = threading.Lock()
        for p in sorted(cache_dir.glob("*.pem")) if cache_dir.is_dir() else []:
            try:
                self.root_keys.update(_spki(c) for c in x509.load_pem_x509_certificates(p.read_bytes()))
            except Exception as exc:  # noqa: BLE001
                log.warning("could not load root %s: %s", p, exc)
        if self.online:
            self._fetch_roots()
            self.refresh_revocations()
        log.info("attestation: %d trusted root(s), revocation list %s", len(self.root_keys),
                 "loaded" if self.revoked_serials is not None else "unavailable")

    def add_root(self, cert: x509.Certificate) -> None:
        self.root_keys.add(_spki(cert))

    def _fetch_roots(self) -> None:
        """Google's current roots. The response is a JSON array of PEM strings (schema not
        documented, so PEM, base64 DER and nested objects are all accepted)."""
        try:
            with urllib.request.urlopen(ROOTS_URL, timeout=8) as r:
                data = json.load(r)
        except Exception as exc:  # noqa: BLE001
            log.warning("could not download Google attestation roots (%s); using the cache", exc)
            return
        found: list[x509.Certificate] = []

        def visit(v):
            if isinstance(v, str):
                try:
                    found.extend(x509.load_pem_x509_certificates(v.encode()) if "BEGIN CERTIFICATE" in v
                                 else [x509.load_der_x509_certificate(base64.b64decode(v))])
                except Exception:  # noqa: BLE001
                    pass
            elif isinstance(v, (list, tuple)):
                for x in v:
                    visit(x)
            elif isinstance(v, dict):
                for x in v.values():
                    visit(x)

        visit(data)
        if not found:
            log.warning("Google roots response contained no certificates")
            return
        self.root_keys.update(_spki(c) for c in found)
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            (self.cache_dir / "google_roots.pem").write_bytes(
                b"".join(c.public_bytes(serialization.Encoding.PEM) for c in found))
        except OSError:
            pass

    def refresh_revocations(self) -> None:
        try:
            with urllib.request.urlopen(REVOCATION_URL, timeout=8) as r:
                data = json.load(r)
            self.revoked_serials = {k.lower() for k in data.get("entries", {})}
            self._revocations_at = time.time()
        except Exception as exc:  # noqa: BLE001
            log.warning("attestation revocation list unavailable (%s)", exc)

    def revocations(self) -> set[str] | None:
        if self.online and time.time() - self._revocations_at > REVOCATION_TTL_S:
            with self._lock:
                if time.time() - self._revocations_at > REVOCATION_TTL_S:
                    self._revocations_at = time.time()   # one attempt per TTL, even if it fails
                    self.refresh_revocations()
        return self.revoked_serials


def _spki(cert: x509.Certificate) -> bytes:
    return cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _authorization_list(tlv: der.TLV) -> dict[int, der.TLV]:
    out = {}
    for item in tlv.children():
        if item.cls == der.CONTEXT and item.constructed:
            inner = item.children()
            if inner:
                out[item.tag] = inner[0]
    return out


def parse_key_description(ext_value: bytes, res: ChainResult) -> None:
    seq = der.parse_one(ext_value).children()
    if len(seq) < 8:
        raise der.DERError("KeyDescription too short")
    res.attestation_version = seq[0].as_int()
    res.security_level = SECURITY_LEVELS.get(seq[1].as_int(), "Unknown")
    res.challenge = seq[4].value
    sw, hw = _authorization_list(seq[6]), _authorization_list(seq[7])
    merged = {**sw, **hw}   # hardware-enforced values win

    rot = merged.get(TAG_ROOT_OF_TRUST)
    if rot is not None:
        r = rot.children()
        res.device_locked = r[1].as_bool()
        res.verified_boot_state = BOOT_STATES.get(r[2].as_int(), "Unknown")
    for tag, attr in ((TAG_OS_VERSION, "os_version"), (TAG_OS_PATCH, "os_patch_level"),
                      (TAG_VENDOR_PATCH, "vendor_patch_level"), (TAG_BOOT_PATCH, "boot_patch_level")):
        if tag in merged:
            setattr(res, attr, merged[tag].as_int())
    if TAG_CREATION_DATETIME in merged:
        res.created_at = datetime.fromtimestamp(merged[TAG_CREATION_DATETIME].as_int() / 1000, timezone.utc)

    app = merged.get(TAG_APP_ID)
    if app is not None:
        app_seq = der.parse_one(app.value).children()
        for info in app_seq[0].children():
            res.package_names.append(info.children()[0].value.decode("utf-8", "replace"))
        if len(app_seq) > 1:
            res.signing_digests = [d.value.hex() for d in app_seq[1].children()]


def verify_chain(chain_b64: list[str], store: TrustStore) -> ChainResult:
    res = ChainResult()
    try:
        certs = [x509.load_der_x509_certificate(base64.b64decode(c)) for c in chain_b64]
    except Exception as exc:  # noqa: BLE001
        res.errors.append(f"cannot parse chain: {type(exc).__name__}")
        return res
    if not certs:
        res.errors.append("empty chain")
        return res
    res.parsed = True
    try:
        for child, issuer in zip(certs, certs[1:]):
            child.verify_directly_issued_by(issuer)
        certs[-1].verify_directly_issued_by(certs[-1])   # the root signs itself
        res.chain_valid = True
    except Exception as exc:  # noqa: BLE001
        res.errors.append(f"chain does not verify: {type(exc).__name__}")
    res.root_trusted = _spki(certs[-1]) in store.root_keys

    revoked = store.revocations()
    if revoked is not None:
        res.revocation_checked = True
        res.revoked = bool({format(c.serial_number, "x") for c in certs} & revoked)

    res.leaf_public_key = certs[0].public_key()
    res.key_fp = hashlib.sha256(_spki(certs[0])).hexdigest()
    if len(certs) > 1:
        res.ca_fp = hashlib.sha256(certs[1].public_bytes(serialization.Encoding.DER)).hexdigest()
    try:
        ext = certs[0].extensions.get_extension_for_oid(KEY_DESCRIPTION_OID)
        parse_key_description(ext.value.value, res)
    except x509.ExtensionNotFound:
        res.errors.append("leaf has no key attestation extension")
    except Exception as exc:  # noqa: BLE001
        res.errors.append(f"cannot parse key description: {type(exc).__name__}")
    return res


def signature_valid(public_key, data: bytes, signature_b64: str | None) -> bool | None:
    """ECDSA-SHA256 (what AndroidKeyStore 'SHA256withECDSA' produces). None if no signature was sent."""
    if not signature_b64:
        return None
    try:
        sig = base64.b64decode(signature_b64, validate=True)
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            return False
        public_key.verify(sig, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:  # noqa: BLE001
        return False
