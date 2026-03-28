#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Sentinel V2 — AWS EC2 Deploy Script (Ubuntu 22.04)
#
# Run ONCE on a fresh EC2 instance:
#   chmod +x deploy.sh && sudo ./deploy.sh
#
# What it does:
#   1. Moves real SSH to port 2222 (so port 22 is free for the honeypot)
#   2. Installs Docker + Docker Compose plugin
#   3. Configures firewall
#   4. Starts Cowrie + Monitor as Docker services
#   5. Enables auto-start on reboot via systemd
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SENTINEL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
die()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }

[[ $EUID -ne 0 ]] && die "Run as root: sudo ./deploy.sh"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Sentinel V2 — Deployment"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# ── 1. Check .env ─────────────────────────────────────────────────────────────
if [ ! -f "$SENTINEL_DIR/.env" ]; then
    die ".env not found. Create it at $SENTINEL_DIR/.env with your API keys before deploying."
fi
log ".env found."

# ── 2. Move real SSH to port 2222 ─────────────────────────────────────────────
if grep -qE "^Port 2222" /etc/ssh/sshd_config; then
    warn "SSH already on port 2222, skipping."
else
    log "Moving real SSH to port 2222..."
    sed -i 's/^#\?Port 22$/Port 2222/' /etc/ssh/sshd_config
    grep -q "^Port" /etc/ssh/sshd_config || echo "Port 2222" >> /etc/ssh/sshd_config
    systemctl restart sshd
    log "SSH moved to port 2222. Keep this terminal open and reconnect with: ssh -p 2222 ubuntu@<IP>"
fi

# ── 3. Install Docker ─────────────────────────────────────────────────────────
if command -v docker &>/dev/null; then
    warn "Docker already installed: $(docker --version)"
else
    log "Installing Docker..."
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
        > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable docker
    systemctl start docker
    log "Docker installed."
fi

# ── 4. Firewall ───────────────────────────────────────────────────────────────
if command -v ufw &>/dev/null; then
    log "Configuring firewall..."
    ufw --force reset > /dev/null
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 2222/tcp  comment "Admin SSH"
    ufw allow 22/tcp    comment "Honeypot SSH"
    ufw allow 23/tcp    comment "Honeypot Telnet"
    ufw --force enable
    log "Firewall: admin=2222 | honeypot=22,23"
fi

# ── 5. Start the stack ────────────────────────────────────────────────────────
log "Starting Sentinel V2 stack..."
cd "$SENTINEL_DIR/docker"
docker compose pull -q
docker compose up -d --build
log "Stack started: api-service-prod (Cowrie) + sentinel-monitor"

# ── 6. systemd — auto-start on reboot ────────────────────────────────────────
log "Installing systemd service for auto-start..."
cat > /etc/systemd/system/sentinel.service << EOF
[Unit]
Description=Sentinel V2 Honeypot Stack
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=${SENTINEL_DIR}/docker
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sentinel.service
log "Auto-start enabled."

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo -e "${GREEN} Sentinel V2 deployed!${NC}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  Honeypot SSH  : port 22  (internet-facing)"
echo "  Admin SSH     : port 2222 (your access)"
echo "  Monitor logs  : docker logs -f sentinel-monitor"
echo "  Cowrie logs   : docker logs -f api-service-prod"
echo "  Stop          : systemctl stop sentinel"
echo "  Restart       : systemctl restart sentinel"
echo ""
