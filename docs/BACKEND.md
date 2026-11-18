# Backend

One job: **receive a `rasp_collect_v2` payload from the app, work out what it means, store everything, and return a decision.**

```
POST /v1/collect
   │
   ├─ 1 validate     schema.py        shape, types, sizes. Bad request → 422 with the exact field.
   ├─ 2 de-duplicate pipeline.py      (install_id, session_id) already stored? → return the stored result
   ├─ 3 normalise    normalize.py     signals → the named probes the rules and the model use
   ├─ 4 retrieve     retrieval.py     facts the phone cannot supply: request, history from the DB, config checks
   ├─ 5 rules        rules.py         evidence tiers → rules level 1-5
   ├─ 6 model        scoring.py       25 features → ML level, probabilities, explanation
   ├─ 7 decide       pipeline.py      final level, label, allow / step_up / block for the action
   ├─ 8 persist      store.py         session + retrievals + result, ONE statement (all or nothing)
   └─ 9 respond      pipeline.render  same shape for a new call, a retry, and GET /v1/sessions/{id}
```

Each stage is one module with one responsibility. Nothing in `api.py` (HTTP, auth, limits) knows how a decision is made, and nothing in the pipeline knows about HTTP.

> **Assurance.** The collector payload is not signed or attested, so every decision carries `"assurance": "unverified"`.
> Level 1 means *"the data this device reported shows nothing wrong"*, not *"this device is proven genuine"*. A forged payload can say anything.
> The earlier signed and attested flow is archived in [archive/SIGNED_SCHEMA2.md](archive/SIGNED_SCHEMA2.md) (code: git commit `dd44271`).

## 1. API

| Endpoint | Auth | Purpose |
|---|---|---|
| `GET /health` | none | Liveness: database reachable, model loaded. `503` if the database is down. |
| `GET /v1/challenge` | `X-Api-Key` if `COLLECT_API_KEY` is set | `{"nonce", "expires_in": 300}`: a fresh server nonce for key attestation (§2, stage 3b). |
| `POST /v1/collect` | `X-Api-Key` if `COLLECT_API_KEY` is set | The one write path: payload in, decision out. |
| `GET /v1/sessions/{id}` | `X-Admin-Token` | One stored session: what the phone sent, what was retrieved, what was decided. |
| `GET /v1/sessions` | `X-Admin-Token` | List: `?install_id=`, `?min_level=4`, `?limit=50`. |
| `GET /v1/model` | `X-Admin-Token` | Model card: features, thresholds, evaluation, mode. |

Admin endpoints answer **403** until `ADMIN_TOKEN` is set. Interactive docs: `/docs`.

Removed in this version, because nothing in the new flow uses them: `/v1/nonce`, `/v2/assess`, `/v1/assess`, `/v1/predict`, `/v1/features` (both methods), `/v1/bank/check`, `/v1/public-key`, `/v1/decisions`, `/v1/demo*`, `/v1/admin/*`, `/v1/ml/report`, the dashboard and the web demo.

### `POST /v1/collect`

Request: the payload from [PAYLOAD.md](PAYLOAD.md), `Content-Type: application/json`, at most `MAX_BODY_KB` (256).

| Status | Meaning |
|---|---|
| `200` | Decision returned and stored. `duplicate: true` means this session was already stored; the stored decision is returned and nothing new is written. |
| `401` | `COLLECT_API_KEY` is set and `X-Api-Key` is missing or wrong |
| `413` | Body too large |
| `422` | Payload invalid. `detail` is a list of `{field, problem}` |
| `503` | The database is unavailable. **Nothing was stored; retry with the same `session_id`.** |

Response:

```json
{
  "id": "f54a721a-173c-4068-afbf-a4103acc4ed6",
  "install_id": "i_548295d7…", "session_id": "session-8ade2307-…",
  "received_at": "2026-11-17T18:55:20+00:00",
  "duplicate": false,

  "decision": {
    "level": 3, "risk_score": 54, "score_basis": {"band": [40, 59], "position": 0.76, "from": "model"},
    "label": "SUSPICIOUS", "outcome": "step_up", "action": "transfer",
    "assurance": "unverified",
    "rules_level": 3, "ml_level": 1, "ml_mode": "enforce",
    "reasons": [
      {"code": "CX_DEVELOPER_OPTIONS", "tier": "C", "text": "Developer options enabled."},
      {"code": "CX_ADB_ENABLED",       "tier": "C", "text": "USB or wireless debugging enabled."}
    ]
  },

  "model": {
    "status": "scored", "version": "shadow-20261118-0017", "trained_on": "synthetic",
    "feature_coverage": 0.92, "missing_features": ["probe_total_ms", "probe_max_ms"],
    "anomaly_pct": 88.0, "top_head": "app_tamper_clone", "agreement": "agree",
    "heads": {"hidden_root": 0.001, "instrumentation": 0.001, "emulator_virtual": 0.0, "app_tamper_clone": 0.021},
    "explanation": [], "features": {"sensor_count": 44.0, "ctx_adb_enabled": 1.0, "probe_total_ms": null}
  },

  "retrieved": {
    "server_signals": {"F299": true, "F304": 1, "F329": 203, "F330": 3, "F339": 1},
    "history": {"sessions_seen": 1, "first_seen": "…", "last_level": 3, "clock_skew_s": 2.6},
    "checks": {"release_manifest": null, "signing_cert": null}
  },

  "coverage": {"signals_received": 230, "unknown_reported": 54, "used_by_rules_and_model": 80,
               "undecidable": [], "unmapped_alerts": [], "probes_built": ["…"]},
  "timings_ms": {"normalize": 1.1, "retrieve": 159, "rules": 0.1, "model": 29, "persist": 165, "total": 520}
}
```

## 2. Stage by stage

### 1 · Validate: [schema.py](../backend/trustpoc/schema.py)
Strict on shape and size, tolerant on content. Required: `schema == "rasp_collect_v2"`, `action` (one of the five), `context_keys.install_id/session_id`, `device.*`, `app.version_code`, `signals`.
- A signal is a bare value or `[value, risk]` with risk 0–3. IDs look like `F016`; `battery_temp_c` is the one allowed extra key.
- A signal cannot be both measured and listed in `unknown`.
- `scan_timestamp` must be ISO-8601 **with** a UTC offset.
- Unknown extra top-level fields are ignored, so a newer app does not break this server.
- **NUL characters are removed** from all text. Android's `/proc/self/attr/current` ends with one, and PostgreSQL rejects NUL in JSON. This was found with a real phone payload.

### 3 · Normalise: [normalize.py](../backend/trustpoc/normalize.py)
The only place that interprets signal values. Two shapes arrive:

| Shape | Example | How it is read |
|---|---|---|
| Pair | `"F124": ["Clean", 0]` | The device's own **risk** decides. The text is never parsed. |
| Bare | `"F146": 0`, `"F016": "0"`, `"F078": false` | Meaning is fixed **per signal**: a count > 0, `ro.debuggable == "1"`, `ro.secure == "0"`, a flag, exactly-zero sensor noise, … |

- A signal whose meaning cannot be decided (a text where a number was expected) goes to `coverage.undecidable` and is treated as **missing**, never as clean.
- Missing, `unknown` and undecidable signals do not become probes; the model sees them as NaN.
- Any ALERT-risk signal that no rule uses is listed in `unmapped_alerts` and counts as context (Tier C).

### 3b · Integrity: [integrity.py](../backend/trustpoc/integrity.py) and [attestation.py](../backend/trustpoc/attestation.py)
App 1.3+ keeps **one hardware-attested EC key per install** in AndroidKeyStore. It is created the first time the app sends, with that request's `/v1/challenge` nonce as the attestation challenge. Every request then carries `attestation: {nonce, chain}` and is signed with the key (header `X-Rasp-Signature`: ECDSA-SHA256 over the exact body bytes).

- **Nonce:** stateless, 8-byte issue time + 16 random bytes + 16-byte HMAC under `CHALLENGE_SECRET`; valid for 300 s. A reused nonce is caught by the database (`nonce_uses`).
- **Chain:** verified link by link; the root must be one of Google's attestation roots, downloaded at startup into `data/attestation_roots/`. Serials are checked against Google's revocation list (refreshed every 6 h). `TRUSTPOC_OFFLINE=1` skips both downloads (tests).
- **Assurance:** `attested` when the chain is trusted, the body signature is valid, the nonce is fresh and unused, and the key's challenge was issued by this server. `failed` if attestation was sent but any of that fails. `unverified` if none was sent (older app, or no usable keystore).

| Signals | From |
|---|---|
| F001 chain to a Google root · F002 revoked · F003 security level · F004 verified boot · F005 bootloader locked · F006/F007 OS / vendor patch · F008 app signing cert = `expected_cert_sha256` · F009 package in `expected_packages` · F010 key challenge issued here · F025 attested OS / patch vs the payload · F317 key age (days) · F321 key created in this session · F364 signed + fresh nonce | the chain and signature |
| F307 boot state went from Verified to not · F308 lock state changed · F316 key changes in 30 d · F318 attestation CA changed · F319 another key seen with this Android ID · F320 distinct keys for this install · F324 installs presenting this key in 24 h · F337 installs whose key came from the same attestation certificate in 7 d | history and fleet counts (`store.lookup`) |

Reasons: `AT_SIGNATURE_INVALID`, `AT_NONCE_INVALID`, `AT_UNTRUSTED_CHAIN`, `AT_REVOKED`, `AT_KEY_SHARED` (family *integrity*, Tier B); `AT_BOOTLOADER_UNLOCKED`, `AT_BOOT_REGRESSED` (*root*, B); `AT_APP_CERT_MISMATCH`, `AT_PACKAGE_MISMATCH` (*app*, B); `AT_SOFTWARE_KEY`, `AT_PROPS_MISMATCH`, `AT_LOCK_STATE_CHANGED`, `AT_CHALLENGE_UNKNOWN` (the key was made for a challenge this server did not issue, e.g. after `CHALLENGE_SECRET` changed; the app replaces the key on its next send) (C).

### 4 · Retrieve: [retrieval.py](../backend/trustpoc/retrieval.py)
Computes the 86 catalogue signals the phone never reports. Each one ends up either in `server_signals` or in `not_computed` with the reason, **never silently absent**. All IDs match [FEATURES.md](FEATURES.md). There is **one database round trip** (`store.lookup`): history, per-network / ASN / sensor / Android-ID counts and the device graph come from a single SQL statement.

| Source | Signals computed |
|---|---|
| **Request** | F287 IP scope / ASN type · F292 proxy (proxy headers, hosting ASN, device VPN) · F296 JA3 and F302 client RTT (only from our edge worker, see below) · F297 share of this JA3 among sessions of the same app version + Android SDK (30 d, needs 20+) · F298 header-order hash · F299 User-Agent vs device · F365 payload age (ms) · clock skew |
| **Geo data** in `backend/data/geo/` (`python tools/update_geo.py`) | F286 ASN · F288 IP country · F293 Tor exit · F294 hosting / data centre · F340 installs on the ASN in 24 h |
| **`device_context`** (optional block from the app) | F289 IP vs SIM country · F290 phone timezone's UTC offset fits no zone of the IP country (tz database `zone.tab`; `CX_TIMEZONE_MISMATCH`) · F291 IP vs locale country · F301 network type · F303 network-type switches in 24 h · F310 boot count went backwards · F311 uptime drift vs the time between sessions (s) · F326 other installs on this phone in 30 d (hashed Android ID) |
| **History**: this install's sessions | F304 IP changes in 30 min · F305 request timing regularity · F306 patch regressed · F309 fingerprint changed · F312 OS downgrade · F313 kernel changed · F314 SDK changed · F315 app version regressed · F329 seconds since first seen · F330/F331/F332 level and rule history (30 d) · F333 anomaly trend vs the last 5 sessions · F363 phone clock moved forward |
| **Network** | F295 share of risky sessions from this /24 in 30 d (raised for Tor and hosting) · F325 new installs on the /24 in 24 h · F339 installs on the /24 in 24 h |
| **Device graph**: installs linked by a shared /24 or a shared Android ID in 7 days, up to 2 hops | F338 installs with identical sensor hardware · F343/F349 component size · F344 emulator share · F345 new-install share · F347 mean level of the members (0–1) · F348 entity age (days) · F350 farm score = min(1, log2(size)/5) × worst share |
| **Checks** against `config.json` | release manifest (F084–F092 → F088) · signing certificate (F076 → F081) |

New reasons (all Tier C unless noted): `CX_HOSTING_IP`, `CX_TOR_EXIT`, `CX_PROXY_HEADERS`, `CX_COUNTRY_MISMATCH`, `CX_CLOCK_SKEW`, `HS_PATCH_REGRESSED`, `HS_OS_DOWNGRADE`, `HS_APP_VERSION_REGRESSED`, `HS_BOOT_COUNT_RESET`, `HS_UPTIME_INCONSISTENT` (> 300 s drift), `HS_REINSTALLS` (3+ other installs), `GR_FARM_CLUSTER` (farm score ≥ 0.7). A manifest or certificate mismatch is Tier B (`AP_CODE_MISMATCH`, `AP_CERT_MISMATCH`).

**Edge fields.** `X-Ja3-Hash` and `X-Client-Rtt-Ms` are only believed when `EDGE_SECRET` is set and the request carries the same value in `X-Edge-Secret`, i.e. it came through our own [edge/cloudflare-worker.js](../edge/cloudflare-worker.js). `TRUST_PROXY` alone no longer trusts them: a client could send any value. Cloudflare gives every plan the RTT; JA3 needs Bot Management (Enterprise).

**Not computed (reason stored per session in `not_computed`):**
- **Attestation:** only when the app sent none (older app, no keystore), or a field is absent from the device's attestation record. History signals (F307, F308, F318) need an earlier attested session.
- **Play Integrity:** F011–F015 need a Google Cloud project.
- **Bank data:** F322, F323, F327, F328, F334–F336, F341, F342, F346. These need account, payee or fraud-outcome data.
- **Edge / infrastructure:** F296, F297, F302 without the edge worker; F300 (DNS probe).
- **Geo:** the geo signals are reported as not computed until the data files are downloaded, and for private IPs.

### 5 · Rules: [rules.py](../backend/trustpoc/rules.py)
| Tier | Meaning | Effect |
|---|---|---|
| B | Strong evidence, grouped in **families**: root · instrumentation · virtual · app | 2 families → Level 5 · 1 family → Level 4 |
| C | Context: developer settings, VPN, accessibility, history regressions, unmapped alerts, clock skew | developer class or 2+ → Level 3 · 1 → Level 2 |
| none | | Level 1 |

There is no Tier A here: cryptographic proof needs a signed payload.

### 6 · Model: [scoring.py](../backend/trustpoc/scoring.py)
An explicit contract for the ML layer:

| | |
|---|---|
| **Input** | Exactly 25 features, in `features.FEATURES` order (root, hooking, emulator, app, context, probe health) |
| **Missing** | A probe that is absent becomes **NaN**, never 0 |
| **Coverage** | Share of the 25 features present. Below **0.6** the model is **not run** (`insufficient_features`). |
| **Output** | `ml_level` 1–5, four head probabilities (hidden root, instrumentation, emulator/virtual, app tamper/clone), anomaly percentile, top contributing features, and the exact feature vector |
| **Status** | `scored` · `insufficient_features` · `unavailable` (no model file) · `error` (model raised) |
| **Mode** | `ML_MODE=enforce` (default): final = `max(rules, ML)`. The model can raise risk, never lower what rules found. `ML_MODE=shadow`: the model is scored and stored; rules alone decide. |

**Risk score (0 = no risk, 100 = critical).** Every decision also gets a single number, which the app shows as a bar. It can never contradict the level, because each level owns a fixed band:

| Level | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|
| Score band | 0–19 | 20–39 | 40–59 | 60–79 | 80–100 |

Where the score falls inside the band comes from the model: the larger of the highest threat-head probability and the anomaly percentile above the median, `(pct − 50) / 50`. Without a scored model the score is the middle of the band. `score_basis` in the response says which applied. Example: the genuine phone is Level 3, anomaly p88 → position 0.76 → **54**.

The score is stored in `session_results.risk_score` and listed by `GET /v1/sessions`. Like the ML level, its position inside the band is only as good as the model, which is trained on synthetic data.

For the current app, 23 of 25 features are present: `probe_total_ms` and `probe_max_ms` are never sent, because the app does not time each probe. They stay NaN (coverage 0.92).

> **The model is trained on synthetic data.** Its scores validate the pipeline; they are not measured accuracy.
> Everything needed to retrain on real data is stored: `session_results.features`.
> `python train_shadow.py` reads the stored vectors of sessions the rules scored Level 1–2 and adds them as negatives.
> Those are **pseudo-labels** ("no indicators found"), not verified-clean devices. A hidden attack the rules miss would be learned as normal. Use independently verified labels (attack lab, confirmed fraud) before trusting the result.

### 8 · Persist: [store.py](../backend/trustpoc/store.py) and [db/schema.sql](../backend/db/schema.sql)
One request writes one row to each table, **in a single SQL statement**, so a session is stored completely or not at all.

| Table | Holds |
|---|---|
| `collect_sessions` | What the phone sent (`signals`, `unknown`, `failed_groups`, `device`, `app`) plus `device_context` and request metadata: `client_ip`, `net24`, `asn`, `sensor_sig`, `android_id_hash`, `header_hash`, `ja3`, `user_agent`, `received_at` (server clock), `scan_time` (phone clock); attestation: `attestation` (verified chain summary), `attest_key_fp`, `attest_ca_fp`, `nonce`, `assurance`. **Unique on `(install_id, session_id)`.** |
| `session_retrievals` | What the server looked up: `server_signals`, `not_computed` (`{signal: reason}`), `history` summary, `checks`, `retrieval_ms` |
| `session_results` | The outcome: `rules_level`, `ml_level`, `final_level`, `risk_score`, `label`, `outcome`, `assurance`, `ml_mode`, `ml_status`, `model_version`, `model_data`, `feature_coverage`, `reasons`, `features` (the exact vector, `null` = missing), `ml` (probabilities, anomaly, explanation), `coverage`, `timings_ms` |

Properties:
- **Idempotent:** the unique key means a retry never creates a second row. The retry returns the stored decision.
- **Fail loud:** if the database is down, the call returns 503 and stores nothing. The client retries safely.
- **Fast:** pooled autocommit connections and one round trip per step. About **0.5 s** per request against a remote Neon database (find 160 ms, retrieve 160 ms, persist 165 ms, model 30 ms).
- Tables are created at startup (`CREATE … IF NOT EXISTS`). The older tables `feature_reports`, `feature_model_results` and `device_assessments` are left untouched.

## 3. Configuration

Environment variables (a `backend/.env` file is loaded if present; it is git-ignored).

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | required | PostgreSQL URL. Without it the server refuses to start (unless `STORE=memory`). |
| `DB_SCHEMA` | `public` | Schema for the tables |
| `STORE` | `postgres` | `memory` = throwaway development run, lost on restart |
| `ADMIN_TOKEN` | empty | Enables the three admin endpoints (`X-Admin-Token`) |
| `COLLECT_API_KEY` | empty | If set, `POST /v1/collect` requires `X-Api-Key`. **The app does not send this header yet.** |
| `ML_MODE` | `enforce` | `enforce` or `shadow` |
| `TRUST_PROXY` | `0` | `1` reads the client IP from `X-Forwarded-For` (behind Render, nginx) |
| `MAX_BODY_KB` | `256` | Request size limit |
| `CHALLENGE_SECRET` | random per process | HMAC key for `/v1/challenge` nonces. **Set it in production**: without it, a restart invalidates every install key's challenge (F010 false) until the app makes a new key. |
| `EDGE_SECRET` | empty | Shared with the edge worker; enables F296 / F297 / F302 |
| `TRUSTPOC_OFFLINE` | `0` | `1` skips downloading Google's attestation roots and revocation list |
| `GEO_DATA` (build arg) | `0` | `1` downloads the country / ASN / Tor data during the Docker build |

`backend/config.json`: `expected_cert_sha256` (list of release-certificate SHA-256 digests; also used for the attested F008), `expected_packages` (F009: `com.example.demo`, `com.example.demo.dev`) and `release_manifests` (entries from `tools/apk_manifest.py`). Both empty = the checks are off.

## 4. Run and test

```powershell
cd backend
python -m venv venv; .\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe train_shadow.py                      # trains data/shadow_model.pkl (about 20 s)
$env:ADMIN_TOKEN = "choose-a-long-secret"
.\venv\Scripts\python.exe -m uvicorn app:app --host 0.0.0.0 --port 8000
```

```powershell
.\venv\Scripts\python.exe -m unittest discover -s tests         # 70 tests, no database needed
```

The database tests run only when `TEST_DATABASE_URL` is set. They create a throwaway schema `rasp_test_<random>`, run the whole pipeline through it, and drop it afterwards:

```powershell
$env:TEST_DATABASE_URL = "postgresql://user:pass@host/db?sslmode=require"
.\venv\Scripts\python.exe -m unittest tests.test_postgres -v    # 8 tests
```

Try it with the real payload:

```powershell
curl.exe -X POST http://localhost:8000/v1/collect -H "Content-Type: application/json" --data-binary "@backend/tests/fixtures/genuine_phone.json"
```

### Download the dataset
[tools/download_dataset.py](../backend/tools/download_dataset.py) exports every stored session for ML work. It reads `DATABASE_URL` from `backend/.env`.

```bash
python tools/download_dataset.py                 # all real sessions -> data/datasets/<UTC time>/
python tools/download_dataset.py --days 7        # last 7 days
python tools/download_dataset.py --install <id>  # one phone
python tools/download_dataset.py --include-test  # also load-test / deployment-check installs
```

| File | Contents |
|---|---|
| `dataset.csv` | One row per session (about 500 columns): session and device info, `ctx_*` device context, **F001–F370** (phone values, or server-computed for F286–F365; booleans 1/0; empty = missing), `F###_risk` (the phone's verdict for pair signals), `mf_*` (the model's 25 input features), `assurance` (attested / failed / unverified) and `att_*` (the verified key attestation: security level, boot state, bootloader lock, patch levels, chain / signature / nonce checks, `att_key_fp` = which install key), and the results (`rules_level`, `ml_level`, `final_level`, `risk_score`, `outcome`, `anomaly_pct`, `head_*` probabilities, `reason_codes`) |
| `results.csv` | One row per session: who / when / which device, `assurance`, `att_key_fp`, and only the rule and ML results |
| `dictionary.csv` | Every column with its group and meaning (catalogue names from [FEATURES.md](FEATURES.md)) |
| `summary.txt` | Session, install, level and assurance counts |

`final_level` is a pseudo-label: rules plus a model trained on synthetic data. Verify sessions (attack lab, confirmed fraud) before using it as ground truth. The output folder is under `backend/data/`, which git ignores.

## 5. Limits and decisions

| | |
|---|---|
| Unsigned payload | Anyone who can reach the endpoint can submit data. Use `COLLECT_API_KEY` and HTTPS in production; the app does not send the key yet. |
| Unverified assurance | A forged payload can claim a clean device. Level 1 is not proof. |
| Synthetic model | Scores validate the pipeline only (see stage 6). |
| Pseudo-labels for retraining | Rules-based negatives can teach the model the rules' blind spots. |
| History is per `install_id` | A reinstall creates a new install, so history starts again. |
| No rate limiting | Add it at the proxy. |
| Connection pool | Four idle connections per process; fine for one instance, size it for more. |
