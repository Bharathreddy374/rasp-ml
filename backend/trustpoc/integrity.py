"""Stage 3b: payload integrity. Server challenge, key attestation and payload signature.

    GET /v1/challenge  ->  {"nonce": "<base64>", "expires_in": 300}

The nonce is stateless: 8 bytes issue time + 16 random bytes + 16 bytes HMAC-SHA256 under
CHALLENGE_SECRET. The server can tell its own nonces apart from forged ones without storing
them; a reused nonce is caught by the database (store.lookup counts earlier sessions with it).

The app keeps ONE attested key per install, created with the nonce of the session that made it
as its attestation challenge, and signs every request body with it (header X-Rasp-Signature):

    payload.attestation = {"nonce": "<this request's nonce>", "chain": ["<leaf DER b64>", ..., "<root>"]}

This stage turns that into catalogue signals:

  F001 chain valid to a Google root   F002 revoked             F003 security level
  F004 verified-boot state            F005 bootloader locked   F006 OS patch level
  F007 vendor patch level             F008 app signing cert matches the release cert
  F009 package name matches           F010 attested challenge is a nonce this server issued
  F025 device props disagree with the attestation (patch level / Android version)
  F317 key age (days)                 F321 key created in this session
  F364 payload signature valid with the attested key over a fresh nonce

History and fleet signals for the key (F307, F308, F316, F318-F320, F324, F337) are
computed in retrieval.py from the database.
"""
import base64
import hashlib
import hmac
import logging
import os
import secrets
import struct
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .attestation import TrustStore, signature_valid, verify_chain

NONCE_TTL_S = 300
NO_ATTESTATION = "the app sent no attestation (older app version, or the keystore could not create a key)"


class Challenger:
    def __init__(self, secret: bytes | None = None, ttl_s: int = NONCE_TTL_S):
        env = os.environ.get("CHALLENGE_SECRET", "")
        # Without a configured secret, nonces stay valid only until the process restarts.
        self.secret = secret or (env.encode() if env else secrets.token_bytes(32))
        if not secret and not env:
            logging.getLogger(__name__).warning(
                "CHALLENGE_SECRET is not set: nonces are valid only in this process. With several "
                "workers or after a restart, attestation fails (F010 / nonce checks). Set it.")
        self.ttl_s = ttl_s

    def issue(self, now: datetime | None = None) -> str:
        ts = int((now or datetime.now(timezone.utc)).timestamp())
        body = struct.pack(">Q", ts) + secrets.token_bytes(16)
        return base64.b64encode(body + hmac.new(self.secret, body, hashlib.sha256).digest()[:16]).decode()

    def parse(self, nonce: bytes) -> datetime | None:
        """Issue time if this server made the nonce, else None."""
        if len(nonce) != 40:
            return None
        body, mac = nonce[:24], nonce[24:]
        if not hmac.compare_digest(mac, hmac.new(self.secret, body, hashlib.sha256).digest()[:16]):
            return None
        return datetime.fromtimestamp(struct.unpack(">Q", body[:8])[0], timezone.utc)


@dataclass
class Integrity:
    present: bool = False
    signals: dict = field(default_factory=dict)
    not_computed: dict = field(default_factory=dict)
    evidence: list[tuple[str, str]] = field(default_factory=list)
    assurance: str = "unverified"        # attested | unverified | failed
    summary: dict | None = None          # stored in collect_sessions.attestation
    key_fp: str | None = None
    ca_fp: str | None = None
    nonce: str | None = None
    trustworthy: bool = False            # chain claims can be relied on (history comparisons use them)


def _patch_yyyymm(text: str) -> int | None:
    try:
        y, m = text.split("-")[:2]
        return int(y) * 100 + int(m)
    except (ValueError, AttributeError):
        return None


def evaluate(payload, raw_body: bytes, signature_b64: str | None, trust: TrustStore, challenger: Challenger,
             config: dict, now: datetime) -> Integrity:
    out = Integrity()
    block = payload.attestation
    if block is None or not block.chain:
        for fid in ("F001", "F002", "F003", "F004", "F005", "F006", "F007", "F008", "F009", "F010",
                    "F025", "F317", "F321", "F364"):
            out.not_computed[fid] = NO_ATTESTATION
        return out
    out.present = True
    out.nonce = block.nonce
    sig = out.signals

    chain = verify_chain(block.chain, trust)
    out.key_fp, out.ca_fp = chain.key_fp, chain.ca_fp
    out.trustworthy = chain.trustworthy
    sig["F001"] = chain.chain_valid and chain.root_trusted
    if chain.revocation_checked:
        sig["F002"] = chain.revoked
    else:
        out.not_computed["F002"] = "Google's revocation list could not be loaded"
    for fid, value in (("F003", chain.security_level), ("F004", chain.verified_boot_state),
                       ("F005", chain.device_locked), ("F006", chain.os_patch_level),
                       ("F007", chain.vendor_patch_level)):
        if value is not None:
            sig[fid] = value
        else:
            out.not_computed[fid] = "not present in this device's attestation record"

    expected_certs = [c.lower().replace(":", "") for c in config.get("expected_cert_sha256") or []]
    if not chain.signing_digests:
        out.not_computed["F008"] = "not present in this device's attestation record"
    elif not expected_certs:
        out.not_computed["F008"] = "no expected_cert_sha256 in config.json"
    else:
        sig["F008"] = any(d in expected_certs for d in chain.signing_digests)
    expected_pkgs = config.get("expected_packages") or []
    if not chain.package_names:
        out.not_computed["F009"] = "not present in this device's attestation record"
    elif not expected_pkgs:
        out.not_computed["F009"] = "no expected_packages in config.json"
    else:
        sig["F009"] = any(p in expected_pkgs for p in chain.package_names)

    # Challenge and freshness: the key's challenge must be a nonce we issued (when the key was
    # created); this request's nonce must be ours and fresh; the body must be signed with the key.
    sig["F010"] = challenger.parse(chain.challenge) is not None
    try:
        nonce_bytes = base64.b64decode(block.nonce or "", validate=True)
    except ValueError:
        nonce_bytes = b""
    issued = challenger.parse(nonce_bytes)
    fresh = issued is not None and 0 <= (now - issued).total_seconds() <= challenger.ttl_s + 30
    sig["F321"] = bool(nonce_bytes) and chain.challenge == nonce_bytes
    signed = signature_valid(chain.leaf_public_key, raw_body, signature_b64) if chain.leaf_public_key else None
    sig["F364"] = bool(signed) and fresh
    if chain.created_at:
        sig["F317"] = round(max((now - chain.created_at).total_seconds(), 0) / 86400, 2)
    else:
        out.not_computed["F317"] = "not present in this device's attestation record"

    # F025: the payload's device block must agree with what the hardware attested
    if chain.trustworthy:
        mismatches = []
        attested_major = chain.os_version // 10000 if chain.os_version else None
        claimed_major = int(payload.device.android_release.split(".")[0]) if payload.device.android_release.split(".")[0].isdigit() else None
        if attested_major and claimed_major and attested_major != claimed_major:
            mismatches.append("android_version")
        claimed_patch = _patch_yyyymm(payload.device.security_patch)
        if chain.os_patch_level and claimed_patch and chain.os_patch_level != claimed_patch:
            mismatches.append("security_patch")
        sig["F025"] = bool(mismatches)
        if mismatches:
            out.evidence.append(("C", "AT_PROPS_MISMATCH"))
    else:
        out.not_computed["F025"] = "the attestation chain is not trusted, so its claims cannot be compared"

    # evidence
    if not signed:
        out.evidence.append(("B", "AT_SIGNATURE_INVALID"))
    if not fresh:
        out.evidence.append(("B", "AT_NONCE_INVALID"))
    if not sig["F010"]:
        out.evidence.append(("C", "AT_CHALLENGE_UNKNOWN"))
    if not (chain.chain_valid and chain.root_trusted):
        out.evidence.append(("B", "AT_UNTRUSTED_CHAIN"))
    if chain.revoked:
        out.evidence.append(("B", "AT_REVOKED"))
    if chain.trustworthy:
        if chain.verified_boot_state not in (None, "Verified") or chain.device_locked is False:
            out.evidence.append(("B", "AT_BOOTLOADER_UNLOCKED"))
        if chain.security_level == "Software":
            out.evidence.append(("C", "AT_SOFTWARE_KEY"))
        if sig.get("F008") is False:
            out.evidence.append(("B", "AT_APP_CERT_MISMATCH"))
        if sig.get("F009") is False:
            out.evidence.append(("B", "AT_PACKAGE_MISMATCH"))

    ok = chain.trustworthy and bool(signed) and fresh and sig["F010"]
    out.assurance = "attested" if ok else "failed"
    out.summary = {**chain.summary(), "signature_valid": signed, "nonce_fresh": fresh,
                   "challenge_issued_here": sig["F010"], "key_created_in_session": sig["F321"]}
    return out
