# Payload specification (schema 2)

This is the wire contract between the Android app (`android/…/features/network/`) and the backend (`backend/app.py`, `trustpoc/engine.py`). Anyone writing a client or server must follow it exactly.

**Complete real example:** [examples/payload_example.json](examples/payload_example.json). These are the 232 signals from a genuine phone (vivo I2221, Android 16), with install ID, nonce, fingerprint and install path replaced.

## 1. Flow

```
App                                                     Backend
 │ 1. POST /v1/nonce {install_id, action} ─────────────▶ issue nonce (32 random bytes, base64)
 │ ◀──────────────────────────── {nonce, ttl_s: 60}      bound to install_id + action, single use
 │
 │ 2. AndroidKeyStore: new EC P-256 key,
 │    attestationChallenge = base64-decode(nonce)
 │ 3. scan all probes → build payload JSON (§4)
 │ 4. signature = SHA256withECDSA(payload UTF-8 bytes) with that key
 │ 5. POST /v2/assess  (gzip)  {payload, signature, chain} ─▶ verify (§6) → rules + ML → decision
 │ ◀──────────────────────────────────── decision (§7), incl. signed JWS
 │
 │ 6. App sends decision_jws with the banking request ──▶ bank backend verifies JWS (§8)
```

- A new nonce and a new key are used for **every** assessment. The key is deleted after signing.
- The backend never trusts a value just because the phone sent it. Device signals count only after the nonce, chain and signature are verified.

## 2. Transport

| | |
|---|---|
| Method / type | `POST`, `Content-Type: application/json; charset=utf-8` |
| Compression | `/v2/assess` body sent with `Content-Encoding: gzip` (plain JSON also accepted) |
| Size limits | Body ≤ 512 KB on the wire and ≤ 2 MB after decompression; otherwise **413** |
| TLS | Release builds allow HTTPS only (`usesCleartextTraffic=false`). Debug builds may use HTTP on a LAN. |
| Timeouts (app) | Connect 15 s, read 20 s |
| Base URL | e.g. `http://192.168.1.5:8000` (LAN) or `http://10.0.2.2:8000` (emulator → host) |

## 3. Request 1: nonce

`POST /v1/nonce`

```json
{ "install_id": "i_0123456789abcdef0123456789abcdef", "action": "login" }
```

| Field | Type | Rules |
|---|---|---|
| `install_id` | string, ≤ 64 | Random per install: `"i_" + 32 hex`. Stored in app-private prefs; backup is disabled so it cannot be cloned. |
| `action` | string, ≤ 32 | What the user is doing. Decides the policy outcome: `login`, `view_balance`, `add_payee`, `transfer`, `high_value_transfer`. |

Response `200`:

```json
{ "nonce": "q8N2b0dXk1yT3fVJx7hR4mLpQe9sZ2cA6uYwKiFnHoE=", "ttl_s": 60 }
```

The nonce is standard base64 of 32 random bytes. It is valid for **60 s**, **once**, and only for this `install_id` + `action`.

## 4. Request 2: assessment

`POST /v2/assess`, gzip body:

```json
{
  "payload": "{\"schema\":2,\"install_id\":\"i_…\", … }",
  "signature": "MEUCIQ…",
  "chain": ["MIIC…leaf", "MIIB…intermediate", "…", "MIIF…Google root"]
}
```

| Field | Type | Meaning |
|---|---|---|
| `payload` | string | The **exact JSON text** that was signed (§4.1). It is sent as a string so its bytes do not change in transit. |
| `signature` | string | Base64 DER ECDSA signature (SHA-256) over the UTF-8 bytes of `payload`. Empty if the device has no attested key. |
| `chain` | string[] (≤ 10) | Base64 DER X.509 certificates of the attested key, **leaf first**, ending at the root. Empty if attestation is unavailable. |

### 4.1 The signed payload

```json
{
  "schema": 2,
  "install_id": "i_0123456789abcdef0123456789abcdef",
  "action": "login",
  "nonce": "q8N2b0dXk1yT3fVJx7hR4mLpQe9sZ2cA6uYwKiFnHoE=",
  "counter": 7,
  "ts": 1794847441000,
  "scan_ms": 2082,
  "app":    { "package": "com.example.demo", "version_code": 1, "cert_sha256": ["87a383…b8bf"] },
  "device": { "manufacturer": "vivo", "brand": "iQOO", "model": "I2221", "device": "I2221",
              "hardware": "qcom", "board": "taro", "release": "16", "sdk_int": 36,
              "security_patch": "2026-10-01", "fingerprint": "iQOO/I2221/I2221:16/…:user/release-keys" },
  "signals": { "F016": ["0", 0], "F031": ["Enforcing", 0], "F146": [0, 0], "F206": [1.014, 1], "…": "…" },
  "unknown": ["F034", "F035", "…"],
  "failed_groups": []
}
```

| Field | Type | Required | Meaning / how the backend uses it |
|---|---|---|---|
| `schema` | int | yes | Must be `2`. Anything else → **400**. |
| `install_id` | string | yes | Must equal the value the nonce was issued for; otherwise `AT_NONCE_BINDING` (Tier A). |
| `action` | string | yes | Must equal the nonce's action. Selects the policy row. |
| `nonce` | string | yes | Must be unused and unexpired (`AT_NONCE_INVALID`). It must also equal the challenge inside the attestation leaf (`AT_CHALLENGE_MISMATCH`). |
| `counter` | int | yes | Strictly increasing per install, persisted on the phone. Not increasing → `AT_COUNTER_REGRESSED`. |
| `ts` | int (ms) | yes | Phone clock at build time. Informational; freshness comes from the nonce TTL. |
| `scan_ms` | int | yes | Duration of the scan. |
| `app.package` | string | yes | Compared with `config.json` `expected_package` and with the package in the attestation (`AP_PACKAGE_MISMATCH`, Tier A). |
| `app.version_code` | int | yes | History signal F315 (app version went backwards). |
| `app.cert_sha256` | string[] | yes | SHA-256 of the signing certificate(s), lowercase hex. Compared with `expected_cert_sha256` and with the attested digests (`AP_SIGNATURE_MISMATCH`, Tier A). |
| `device.*` | strings / int | yes | `android.os.Build` facts. Used for emulator checks, the attestation cross-check F025 (`security_patch`, `release`), the User-Agent check F299 and history (F306–F314). |
| `signals` | object | yes | Device signals (§5). May be empty; missing IDs are unknown. |
| `unknown` | string[] | yes | IDs of probes that produced no measurement (§5.3). |
| `failed_groups` | string[] | yes | Probe groups that threw (§5.4). |

## 5. Signal encoding

### 5.1 Entry format

```
"F146": [ value, risk ]
```

**`value`** is typed:
- Boolean, integer or float when the probe sets a typed value (`raw` in `SignalResult`), e.g. `"F116": [0, 0]` (TracerPid), `"F206": [1.014, 1]` (timing ratio), `"F078": [false, 0]`.
- Otherwise the display text: if it is purely numeric it is sent as a number, otherwise as text cut to **64 characters**, e.g. `"F031": ["Enforcing", 0]`.
- Non-finite floats are sent as `null`.

**`risk`** is the probe's own verdict. The backend uses this, never the text:

| risk | Name | Meaning |
|---|---|---|
| 0 | SAFE | Measured, nothing found |
| 1 | INFO | Measured. Neutral, or "on" for a setting (e.g. developer options = INFO when enabled) |
| 2 | SUSPICIOUS | Unusual or weak evidence |
| 3 | ALERT | Strong evidence |

`trustpoc/signals.py` decides how each ID counts:
- **Threshold mappings:** e.g. Frida signals count at ALERT; developer options count at INFO.
- **Typed values:** F031 SELinux mode, F116 TracerPid and F255 sensor count are read as values.
- **Anything else at ALERT** becomes the context reason `DV_UNMAPPED_ALERTS`.

Names, categories and descriptions are **not** sent. The meaning of each ID is in [FEATURES.md](FEATURES.md).

### 5.2 Which IDs are sent

| Sent in `signals` | Not sent |
|---|---|
| Device-observed groups: F016–F285 and F351–F370, except backend-computed rows | **F001–F015:** the certificate chain carries the attestation facts and the backend reads them itself |
| | **F286–F350, F363–F365:** network, history, graph and envelope checks are computed by the backend |
| | F025, F081, F088: backend cross-checks |

### 5.3 `unknown`

These IDs exist in the catalogue but have **no measurement on this device**. Reasons include native ART internals, in-app UI capture, per-model baselines, Play Integrity, and data that newer Android blocks (see [FEATURES.md](FEATURES.md)).

The backend treats them as unknown: **NaN** for ML and ignored by rules. They are **never treated as clean**. A probe that is silently missing from `signals` is handled the same way.

### 5.4 `failed_groups`

Probe groups that threw an exception. Their signals are absent. Each group becomes an errored probe, and 4 or more give `CX_PROBE_FAILURES` (Tier C).

Allowed values: `attestation`, `device_static`, `app_integrity`, `runtime_hooking`, `memory_procfs`, `timing`, `sensor_touch`, `risky_context`, `probe_health`.

## 6. Signing and attestation

| Step | Detail |
|---|---|
| Key | `KeyGenParameterSpec`: EC `secp256r1`, `PURPOSE_SIGN`, `DIGEST_SHA256`, `setAttestationChallenge(base64-decode(nonce))`, alias `trust_req_<uuid>`. Deleted after use. |
| Signature | `Signature("SHA256withECDSA")` over `payload.toByteArray(UTF_8)`. DER encoded, then base64 (`NO_WRAP`). |
| Chain | `KeyStore.getCertificateChain(alias)`, each certificate `.encoded` (DER) then base64. Leaf first. |

The backend verifies in this order. Any Tier A hit gives Level 5.

1. Body size and gzip; `schema == 2`.
2. Nonce consumed: unknown, expired or reused → `AT_NONCE_INVALID`; issued for another install or action → `AT_NONCE_BINDING`.
3. Chain: each certificate signed by the next, the root self-signed (`AT_CHAIN_INVALID`). The root must match **Google's attestation roots**; otherwise `AT_UNTRUSTED_ROOT` and the claims are ignored. Serials are checked against **Google's revocation list** (`AT_KEY_REVOKED`).
4. Leaf KeyDescription: challenge == nonce (`AT_CHALLENGE_MISMATCH`), security level, verified boot, bootloader lock, patch levels, package, signing digests.
5. Signature over the payload bytes with the leaf's public key (`AT_PAYLOAD_SIGNATURE_INVALID`).
6. Counter strictly increasing (`AT_COUNTER_REGRESSED`).
7. Signals → probes → rules (Tiers B/C) → ML → server-side signals → level = `max(rules, ML)`.

No chain (device cannot attest) → `AT_NO_ATTESTATION`, reduced assurance, Level ≥ 2. With `STRICT_HARDENING=1`, sensitive actions also require trusted hardware attestation (`AT_HARDWARE_REQUIRED`, Tier A).

## 7. Response

`200 OK`:

```json
{
  "decision_jws": "eyJhbGciOiJFUzI1NiIsImtpZCI6Ij…",
  "decision_id": "d_4e6ae85c096d4d89",
  "trust_level": 3,
  "label": "SUSPICIOUS",
  "outcome": "step_up",
  "rules_level": 3,
  "ml_level": 1,
  "reasons": [
    { "code": "CX_DEVELOPER_OPTIONS", "tier": "C", "text": "Developer options enabled." },
    { "code": "CX_ADB_ENABLED", "tier": "C", "text": "USB debugging enabled." }
  ],
  "reduced_assurance": false,
  "attestation": {
    "chain_valid": true, "root_trusted": true, "revoked": false, "revocation_checked": true,
    "security_level": "TrustedEnvironment", "verified_boot_state": "Verified", "device_locked": true,
    "os_patch_level": 202610, "package_names": ["com.example.demo"],
    "signing_digests": ["87a383…b8bf"], "errors": []
  },
  "server_signals": { "F025": false, "F299": true, "F329": 0, "F339": 1 },
  "unmapped_alerts": [],
  "coverage": { "schema": 2, "device_signals": 232, "unknown": 52, "mapped_probes": 34, "server_signals": 5 },
  "server_ms": 9.4
}
```

| Field | Meaning |
|---|---|
| `trust_level` / `label` | 1 GENUINE · 2 NORMAL · 3 SUSPICIOUS · 4 HIGH_RISK · 5 CRITICAL |
| `outcome` | Policy for `action` × level: `allow`, `step_up` or `block`. The bank owns the final policy (`rules.POLICY`). |
| `rules_level` / `ml_level` | The two inputs. The final level is `max(rules, ML)`. `ml_level` is `null` if the model is not loaded. |
| `reasons` | Evidence with tier: A (cryptographic), B (strong, grouped by family), C (context), ML. |
| `attestation` | The backend's verdict on the chain. This is where F001–F010 are read. |
| `server_signals` | Backend-computed catalogue signals for this request (F286–F350 subset, plus F025 and F088). |
| `unmapped_alerts` | ALERT signals with no dedicated rule yet (counted as Tier C). |
| `coverage` | Signals received, unknown, mapped to rules, computed on the server. |
| `decision_jws` | Signed decision for the bank (§8). |

### Errors

| Status | When |
|---|---|
| 400 | Not JSON, invalid gzip, `payload` not a JSON object, or `schema` ≠ 2 |
| 413 | Body > 512 KB, or > 2 MB after decompression |
| 422 | Envelope fields missing or of the wrong type |
| 410 | Legacy `POST /v1/features` (unsigned) while `ALLOW_UNSIGNED_REPORTS` is off |

A replay, a bad signature or a wrong app is **not** an HTTP error. It returns `200` with `trust_level: 5`, so attackers learn nothing extra.

## 8. Decision token for the bank

`decision_jws` is a compact **JWS, ES256**, with header `kid` = the first 16 hex characters of SHA-256 of the public key. Claims:

```json
{
  "decision_id": "d_4e6ae85c096d4d89", "install_id": "i_…", "action": "login", "nonce": "…",
  "trust_level": 3, "label": "SUSPICIOUS", "reasons": ["CX_DEVELOPER_OPTIONS", "CX_ADB_ENABLED"],
  "reduced_assurance": false, "degraded": false, "iat": 1794847441, "exp": 1794847741
}
```

- The public key is at `GET /v1/public-key` (PEM).
- The bank must check the signature, `exp` (5 minutes), and that `action` matches the operation being authorised.
- `POST /v1/bank/check {decision_jws, action}` shows this check.

## 9. Size

Measured on the genuine phone:

| | Bytes |
|---|---|
| Payload JSON (232 signals, 52 unknown) | ~5.9 KB |
| Envelope incl. chain (4–5 certificates) and signature, gzipped | ~4–5.5 KB on the wire (phone 5.2 KB, emulator 4.0 KB) |

The certificate chain is most of the compressed size; certificates do not compress.

## 10. Versions and legacy endpoints

| Endpoint | Schema | Status |
|---|---|---|
| `POST /v2/assess` | 2 (this document) | **Current**, used by the app |
| `POST /v1/assess` | 1 (`payload` is base64 of JSON with named `probes`) | Kept for the simulator and web demo |
| `POST /v1/predict` | raw probe values, unsigned | "Try it" page only; no attestation |
| `POST /v1/features` | unsigned 370-signal report | **Disabled** (410) unless `ALLOW_UNSIGNED_REPORTS=1` |

Changing the payload format means raising `schema` and adding a new endpoint version. Never change the meaning of an existing signal ID; add new IDs instead.
