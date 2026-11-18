# Deploy on AWS EC2 (Docker + nginx)

One EC2 instance runs two containers:

```
phone ──HTTPS──► (Cloudflare or ALB: TLS) ──HTTP :80──► nginx ──► app: uvicorn + FastAPI ──► Neon Postgres
                                                            │
                                                            └─ volume "models": retrained model (optional)
```

| File | Purpose |
|---|---|
| `docker-compose.yml` | `app` (the backend image), `nginx` (port 80), `retrain` (one-off model training) |
| `nginx/default.conf` | Reverse proxy: rate limit 10 req/s per IP, 300 KB body limit, `X-Forwarded-For`, timeouts |
| `nginx/https.conf.example` | Optional HTTPS on the box with a certificate you already have (no certbot) |
| `.env.example` | Settings; copy to `.env` (git-ignored) |
| `setup-ec2.sh` | Installs Docker, adds swap, creates `.env` with generated secrets, starts everything |

## 1. Instance
- **Size:** t3.small (2 vCPU, 2 GB) or larger. The image build trains the model (about 1 GB RAM, ~1-2 min); the script adds 2 GB swap so a t3.micro also works, slowly.
- **OS:** Ubuntu 24.04 or Amazon Linux 2023.
- **Security group:** inbound 22 (your IP only), 80 (and 443 if you add HTTPS). **Never open 8000.**
- **Region:** ap-southeast-1 (Singapore), next to the Neon database.

## 2. Install
```bash
git clone -b deploy/aws-ec2 https://github.com/Bharathreddy374/rasp-ml.git
cd rasp-ml/deploy/aws-ec2
sudo bash setup-ec2.sh            # asks for DATABASE_URL once
curl -s http://localhost/health
```

## 3. HTTPS (the app needs it)
Release builds of the app only talk HTTPS. Without certbot, pick one:
- **Cloudflare (simplest):** point a domain's DNS at the instance's Elastic IP with the orange cloud on. Cloudflare serves HTTPS; it reaches nginx on port 80 ("Flexible"), or on 443 with a Cloudflare origin certificate ("Full", see `https.conf.example`).
- **AWS ALB + ACM:** a free ACM certificate on an Application Load Balancer, forwarding to the instance on port 80; health check path `/health`.
- **Your own certificate:** `nginx/https.conf.example`.

The client IP stays correct in every case: each proxy appends to `X-Forwarded-For`, and the app (`TRUST_PROXY=1`) walks it from the right, skipping private and Cloudflare addresses.

Then set the app's collector URL to the new domain (`android/app/build.gradle.kts`, `RENDER_COLLECTOR`) and ship a new APK.

## 4. Server and model: decisions
- **uvicorn stays.** It is a production ASGI server; `--workers` (`WEB_CONCURRENCY`, default 2) gives one process per vCPU, and nginx in front handles slow clients, limits and buffering. Gunicorn would only add a process manager that uvicorn's `--workers` already provides.
- **`CHALLENGE_SECRET` is required with more than one worker.** Each worker checks nonces issued by the others, so they must share the key (and it must survive restarts). `setup-ec2.sh` generates it.
- **The model is trained inside the image (at `docker build`), on synthetic data.** That is the right default: the model always matches the image's scikit-learn version and feature list, and the build needs no database secret (a secret passed to a build would stay in the image layers).
- **Retraining on real data is a separate, explicit step:**
  ```bash
  docker compose run --rm retrain     # synthetic + real low-risk sessions from DATABASE_URL
  docker compose restart app
  ```
  It writes to the `models` volume, which survives rebuilds. The app prefers `MODEL_DIR=/models` and falls back to the image's model; a volume model trained on a different feature list is ignored automatically (logged), so a code update never runs a mismatched model. Retrain again after such an update.

## 5. Operate
```bash
docker compose ps                       # status (app shows healthy / unhealthy)
docker compose logs -f app              # app logs (rotated: 5 x 10 MB)
git pull && docker compose up -d --build   # update: rebuild image (retrains the built-in model)
docker compose run --rm retrain && docker compose restart app   # model on real data
```

Download the dataset from any machine with the repo and `DATABASE_URL`: `python backend/tools/download_dataset.py`.
