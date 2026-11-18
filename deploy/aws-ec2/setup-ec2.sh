#!/usr/bin/env bash
# One-time setup of the collector on a fresh EC2 instance (Ubuntu 22.04/24.04 or Amazon Linux 2023).
#
#   git clone -b deploy/aws-ec2 https://github.com/Bharathreddy374/rasp-ml.git
#   cd rasp-ml/deploy/aws-ec2
#   sudo bash setup-ec2.sh
#
# Installs Docker + the compose plugin, adds 2 GB swap (training the model at build needs ~1 GB),
# creates .env with generated secrets, asks for DATABASE_URL, then builds and starts the stack.
set -euo pipefail
cd "$(dirname "$0")"

if [ "$(id -u)" -ne 0 ]; then echo "run with sudo"; exit 1; fi

# ---- Docker ----
if ! command -v docker >/dev/null 2>&1; then
  . /etc/os-release
  if [ "${ID}" = "amzn" ]; then
    dnf install -y docker
    mkdir -p /usr/local/lib/docker/cli-plugins
    arch=$(uname -m); [ "$arch" = "aarch64" ] || arch=x86_64
    curl -fsSL "https://github.com/docker/compose/releases/download/v2.29.7/docker-compose-linux-${arch}" \
      -o /usr/local/lib/docker/cli-plugins/docker-compose
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
  else
    apt-get update -y
    apt-get install -y ca-certificates curl
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" \
      > /etc/apt/sources.list.d/docker.list
    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  fi
  systemctl enable --now docker
  [ -n "${SUDO_USER:-}" ] && usermod -aG docker "$SUDO_USER" || true
fi

# ---- swap (t3.micro / t3.small have 1-2 GB RAM) ----
if ! swapon --show | grep -q '/swapfile'; then
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
  grep -q '/swapfile' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# ---- .env ----
if [ ! -f .env ]; then
  cp .env.example .env
  sed -i "s|^ADMIN_TOKEN=.*|ADMIN_TOKEN=$(openssl rand -hex 24)|" .env
  sed -i "s|^CHALLENGE_SECRET=.*|CHALLENGE_SECRET=$(openssl rand -hex 32)|" .env
  read -r -p "DATABASE_URL (postgresql://...): " db
  sed -i "s|^DATABASE_URL=.*|DATABASE_URL=${db}|" .env
  chmod 600 .env
  echo ".env created (ADMIN_TOKEN and CHALLENGE_SECRET generated; keep CHALLENGE_SECRET stable)"
fi

# ---- build and start ----
docker compose up -d --build
echo
docker compose ps
echo
echo "Check:  curl -s http://localhost/health"
echo "Open port 80 (and 443 if you add HTTPS) in the instance's security group. Do NOT open 8000."
