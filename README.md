# RASP-ML: Android device trust and banking-app tamper detection

An Android app collects **370 integrity signals** and sends them to a Python backend. The backend works out what they mean (rules + ML), stores the session and the result in PostgreSQL, and returns a **5-level trust decision**: allow, step up, or block.

```
Phone app                               Backend                                      PostgreSQL
─────────                               ───────                                      ──────────
scan 370 signals (Kotlin + native C)
POST /v1/collect  rasp_collect_v2 ───▶  validate → de-duplicate → normalise
                                        → retrieve (request facts, this install's history, config checks)
                                        → rules (tiers B/C) → model (25 features) → decide
                                        → one statement ──────────────────────▶  collect_sessions
                                                                                  session_retrievals
◀──────────── level 1-5, outcome, reasons, model output, retrieved data ──────   session_results
```

| Folder | What |
|---|---|
| `android/` | Feature Catalogue app (Kotlin, Jetpack Compose). Probes in `features/probes/`, native probes in `app/src/main/cpp/trustprobe.c`, payload builder in `features/network/CollectPayload.kt`. |
| `backend/` | FastAPI service. One module per pipeline stage in `trustpoc/` (`schema`, `normalize`, `retrieval`, `rules`, `scoring`, `pipeline`, `store`), SQL in `db/schema.sql`, 70 tests in `tests/`. |
| `docs/` | [How to use](docs/USAGE.md) · [Backend: pipeline, API, database, model](docs/BACKEND.md) · [Payload specification](docs/PAYLOAD.md) · [Feature catalogue: what, how, device variance](docs/FEATURES.md) |

## Status

Tested on a genuine vivo I2221 (Android 16) end to end, and on a rooted Android 17 emulator with Frida 17.

| Scenario | Result |
|---|---|
| Genuine phone, developer options and ADB on | **Level 3**, step-up. Full session stored in 3 tables, about 0.5 s server time. |
| Rooted emulator | **Level 5**: emulator, debuggable build, synthetic sensors |
| Rooted emulator + Frida root-hiding hooks | **Level 5**: `RT_FRIDA` and `RT_CODE_PATCHED`, the exact hooked functions identified |

- **Signals:** the app measures 230 of 370 on the device and reports 54 as unknown. The backend computes 12 more from the request and each install's history. The rest need data this service does not have (GeoIP, accounts, a device graph).
- **Not production-ready yet:** the payload is **unsigned** (so every decision is `assurance: unverified`), the ML models are trained on **synthetic data**, and there is no rate limiting. See [docs/BACKEND.md §5](docs/BACKEND.md#5-limits-and-decisions).
- The earlier signed and attested flow (hardware key attestation, nonce, `/v2/assess`) was removed from the backend and is archived in [docs/archive/SIGNED_SCHEMA2.md](docs/archive/SIGNED_SCHEMA2.md) (code: commit `dd44271`).

## Quick start

```powershell
cd backend; python -m venv venv; .\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe train_shadow.py
"DATABASE_URL=postgresql://user:password@host/db?sslmode=require" | Set-Content .env
.\venv\Scripts\python.exe -m uvicorn app:app --host 0.0.0.0 --port 8000
```

Then open `android/` in Android Studio, run the app on a phone on the same Wi-Fi, tap **Send to API**, enter `http://<laptop-ip>:8000/v1/collect` and tap **Send payload**. Full steps are in [docs/USAGE.md](docs/USAGE.md).
