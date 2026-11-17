# RASP-ML: Android device trust and banking-app tamper detection

An Android app collects **370 integrity signals** and proves them with **hardware key attestation**. A Python backend verifies them, scores them with **rules + ML**, and returns a **signed 5-level trust decision**. The bank uses that decision to allow, step up or block an action.

```
Phone app                                 Backend
──────────                                ───────
POST /v1/nonce ─────────────────────────▶ one-time nonce (60 s)
TEE key with nonce as attestation challenge
scan 370 signals (Kotlin + native C)
sign payload with the TEE key
POST /v2/assess (gzip) ─────────────────▶ verify nonce, attestation chain, signature, counter
                                          map signals → rules (tiers A/B/C) + ML
                                          compute server-side signals (history, network)
◀──────────────────────── signed decision: level 1-5, reasons, allow / step_up / block
```

| Folder | What |
|---|---|
| `android/` | Feature Catalogue app (Kotlin, Jetpack Compose). Probes in `features/probes/`, native probes in `app/src/main/cpp/trustprobe.c`, signed client in `features/network/`. |
| `backend/` | FastAPI service: `trustpoc/attestation.py` (Google key attestation), `signals.py` (signal → rule mapping), `rules.py`, `ml.py`, `server_signals.py`, dashboard, simulator, tests. |
| `docs/` | [How to use](docs/USAGE.md) · [Feature catalogue: what, how, device variance](docs/FEATURES.md) |

## Status

Tested on a genuine vivo I2221 (Android 16) and on a rooted Android 17 emulator with Frida 17.

| Scenario | Result |
|---|---|
| Genuine phone, developer options and ADB on | **Level 3**, step-up. Attestation: Google root, TEE, verified boot, locked. |
| Rooted emulator | **Level 5**: emulator, debuggable build, untrusted software attestation |
| Rooted emulator + Frida root-hiding hooks | **Level 5**: `RT_FRIDA` and `RT_CODE_PATCHED`, exact hooked functions identified |

- **Signals:** 232 measured on the device (23 native), 81 on the backend, 57 still unknown (each with its reason).
- **Not production-ready yet:** the ML models are trained on synthetic data, history is kept in memory, and Play Integrity is not integrated. See [docs/USAGE.md §7](docs/USAGE.md#7-production-gaps).

## Quick start

```powershell
cd backend; python -m venv venv; .\venv\Scripts\python.exe -m pip install -r requirements.txt
.\venv\Scripts\python.exe train_shadow.py
.\venv\Scripts\python.exe -m uvicorn app:app --host 0.0.0.0 --port 8000
```

Then open `android/` in Android Studio, run the app on a phone on the same Wi-Fi, tap **Send to API**, enter `http://<laptop-ip>:8000` and tap **Assess device**. Full steps are in [docs/USAGE.md](docs/USAGE.md).
