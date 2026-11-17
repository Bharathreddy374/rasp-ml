# Payload specification: `rasp_collect_v2`

This is the contract between the Android app and the backend. The backend's reply and what it does with the payload are in [BACKEND.md](BACKEND.md); the meaning of each signal ID is in [FEATURES.md](FEATURES.md).

The earlier **signed and attested** format (nonce, hardware key, signature, `POST /v2/assess`) is archived in [archive/SIGNED_SCHEMA2.md](archive/SIGNED_SCHEMA2.md). The backend no longer accepts it.

## 1. Request

`POST /v1/collect`, plain JSON, `Content-Type: application/json`, at most 256 KB. The app builds it in `android/…/features/network/CollectPayload.kt` and sends it to the full collector URL entered in the **Send to API** dialog. **Copy JSON** and **Share** produce the same payload.

```json
{
  "schema": "rasp_collect_v2",
  "action": "transfer",
  "context_keys": {
    "install_id": "i_548295d787bb4a15b00f4102e4755a9f",
    "session_id": "session-64f6be3c-0bd6-4589-a0b1-afc96fbc7123"
  },
  "device": {
    "manufacturer": "vivo", "model": "I2221", "android_release": "16", "sdk_int": 36,
    "fingerprint": "iQOO/I2221i/I2221:16/BP2A.250605.031.A3_V000L1/…:user/release-keys",
    "security_patch": "2026-10-01", "scan_timestamp": "2026-11-17T23:54:56+05:30"
  },
  "app": { "version_code": 1 },
  "device_context": { "sim_country": "in", "network_country": "in", "timezone": "Asia/Kolkata", "locale": "en-IN",
                      "network_type": "wifi", "boot_count": 412, "uptime_ms": 86400000, "android_id_hash": "9f2c…64 hex" },
  "signals": {
    "F016": 0,
    "F018": ["release-keys", 0],
    "F031": ["Enforcing", 0],
    "F146": 0,
    "F206": 1.06,
    "F231": 0.07073,
    "F278": ["Enabled", 1],
    "battery_temp_c": 32.8
  },
  "unknown": ["F034", "F035", "…"],
  "failed_groups": []
}
```

A complete real example (231 signals, 54 unknown) is [../backend/tests/fixtures/genuine_phone.json](../backend/tests/fixtures/genuine_phone.json).

## 2. Fields

| Field | Type | Required | Rules |
|---|---|---|---|
| `schema` | string | yes | Exactly `rasp_collect_v2` |
| `action` | string | yes | `login`, `view_balance`, `add_payee`, `transfer`, `high_value_transfer`. Selects the policy row. |
| `context_keys.install_id` | string | yes | 1–128 characters of letters, digits and `_ . : -`. Stable per install; a new one after a reinstall. History is kept per `install_id`. |
| `context_keys.session_id` | string | yes | Same characters. **New for every send.** `(install_id, session_id)` is unique: a retry returns the stored result. |
| `device.manufacturer`, `model`, `android_release`, `fingerprint` | string | yes | `android.os.Build`. Used for emulator checks and the User-Agent comparison. |
| `device.sdk_int` | int 1–100 | yes | History: OS downgrade, SDK change |
| `device.security_patch` | string | no | History: patch level regression |
| `device.scan_timestamp` | string | yes | ISO-8601 **with a UTC offset**. The phone's clock; compared with the server's for skew. |
| `app.version_code` | int ≥ 0 | yes | History: app version regression |
| `device_context` | object | no | Facts for server-side signals; every field optional. `sim_country`, `network_country` (ISO 3166 alpha-2), `timezone` (IANA), `locale` (BCP 47, e.g. `en-IN`), `network_type` (`wifi` · `cellular` · `ethernet` · `vpn` · `other` · `none`), `boot_count`, `uptime_ms`, `android_id_hash` (64 hex: SHA-256 of `rasp-ml/android-id/v1:` + `ANDROID_ID`; the raw ID never leaves the phone). Used for F289, F291, F301, F303, F310, F311, F326. |
| `signals` | object | yes | See §3. Up to 600 entries. |
| `unknown` | string[] | no | IDs of signals this device could not measure (§4) |
| `failed_groups` | string[] | no | Probe groups that threw: `attestation`, `device_static`, `app_integrity`, `runtime_hooking`, `memory_procfs`, `timing`, `sensor_touch`, `risky_context`, `server_side`, `probe_health` |

Unknown extra top-level fields are ignored. Text values are limited to 256 characters, and **NUL characters are removed**.

## 3. Signals

Each entry is a **bare value** or a **pair**.

```
"F146": 0                       bare value: boolean, number or short text
"F124": ["Clean", 0]            pair: [display value, risk]
```

| risk | Name | Meaning |
|---|---|---|
| 0 | SAFE | Measured, nothing found |
| 1 | INFO | Measured. Neutral, or "on" for a setting (developer options enabled is INFO). |
| 2 | SUSPICIOUS | Unusual or weak evidence |
| 3 | ALERT | Strong evidence |

The app sends these **55 IDs as pairs** (`CollectPayload.PAIR_IDS`): F018–F021, F028, F031, F037–F041, F043, F045–F047, F050, F051, F053, F055, F057–F060, F063, F065, F098, F099, F108, F109, F113, F117, F118, F121, F124–F132, F137–F143, F166, F257, F278–F280, F282. Every other signal is a bare value. Counts such as `F146` (patched bytes) are bare numbers; flags are booleans.

How the backend reads them (full rules in [BACKEND.md](BACKEND.md)):
- **Pair:** the risk decides; the text is never parsed.
- **Bare:** the meaning is fixed per ID (count > 0, `ro.debuggable == "1"`, flag true, …).
- A bare value whose meaning cannot be decided is treated as **missing, never as clean**.

Which IDs are sent: the device-observed ones. The attestation rows (F001–F015) and the server-side rows (F286–F350) are not sent; the backend computes the latter ([BACKEND.md §4](BACKEND.md#4--retrieve-retrievalpy)).

## 4. `unknown` and `failed_groups`

- **`unknown`** lists signals that exist in the catalogue but have **no measurement on this device** (blocked by newer Android, needs native code not built yet, needs UI capture, and so on). They are never counted as clean. A signal must not appear in both `signals` and `unknown` (422).
- **`failed_groups`** lists probe groups that crashed. Two or more raise `CX_PROBE_FAILURES` (Tier C).

## 5. Response

`200` with the decision, the model outcome, what was retrieved, coverage and timings: see [BACKEND.md §1](BACKEND.md#post-v1collect). Errors: `401`, `413`, `422` (with a field-by-field list), `503` (nothing stored, retry with the same `session_id`).

## 6. Security

`rasp_collect_v2` has **no nonce, counter, app identity, signature or attestation**. The server cannot tell a genuine device from a forged or replayed request, which is why every decision carries `"assurance": "unverified"`. Replays of the *same* `session_id` are harmless (the stored result is returned); a replay with a new `session_id` is a new session.

Use it for data collection and risk scoring, not as proof. Set `COLLECT_API_KEY` on the server and use HTTPS in production (release builds disallow cleartext HTTP; the app does not send an API key yet).

## 7. Size

About 5.2 KB of JSON for the real phone (231 signals, 54 unknown). Server time per request is about 0.5 s with a remote database.

## 8. Compatibility

- Add new signal IDs freely; never change the meaning of an existing ID.
- A new payload format means a new `schema` value and a new endpoint version. The server rejects other `schema` values with 422.
