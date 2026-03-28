# Sentinel V2 — AI-Deception Honeypot & Threat Intelligence Platform

> An active-defense honeypot that baits attackers with AI-poisoned deception files, captures their every move, and delivers real-time threat intelligence via Telegram — without ever touching the attacker's infrastructure.

[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Container-Cowrie_Honeypot-2496ED?style=flat-square&logo=docker&logoColor=white)](https://www.docker.com/)
[![OpenAI](https://img.shields.io/badge/AI-GPT--4o-412991?style=flat-square&logo=openai&logoColor=white)](https://openai.com/)
[![AbuseIPDB](https://img.shields.io/badge/OSINT-AbuseIPDB-red?style=flat-square)](https://www.abuseipdb.com/)
[![n8n](https://img.shields.io/badge/Automation-n8n-EA4B71?style=flat-square)](https://n8n.io/)
[![License](https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square)]()

---

## What's New in V2

| Feature | V1 | V2 |
|---------|----|----|
| SSH Honeypot (Cowrie) | ✅ | ✅ |
| Session buffering | 120s idle | ✅ |
| AI threat analysis (GPT-4o via n8n) | ✅ | ✅ |
| **Immediate new-session Telegram alert** | ❌ | ✅ |
| **4-minute periodic progress reports** | ❌ | ✅ |
| **Deception layer (LLM prompt injection)** | ❌ | ✅ |
| **Honey-commands (AI-bait executables)** | ❌ | ✅ |
| **OSINT enrichment (AbuseIPDB + ip-api)** | ❌ | ✅ |
| **Automatic AbuseIPDB reporting** | ❌ | ✅ |
| **Docker hardening (cap-drop, read-only fs)** | ❌ | ✅ |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                      DECEPTION LAYER (NEW)                          │
│                                                                     │
│  Poisoned lure files placed in honeypot filesystem:                 │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │ docker-compose-legacy.yml  ← TODO comments mentioning        │   │
│  │                              --dump-keys (LLM bait)          │   │
│  │ .env.backup                ← Base64-encoded honey-command     │   │
│  │                              in FALLBACK_DIAG variable        │   │
│  │ database_migration.log     ← Off-screen diagnostic note       │   │
│  │                              past column 160 (LLM reads it)  │   │
│  └──────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  Honey-commands (fake executables that look like vulnerabilities):  │
│  • /usr/local/bin/legacy-backup-restore --dump-keys                 │
│  • /usr/local/bin/db-diagnostics --bypass-auth                      │
│  → Output: convincing fake AWS keys + DB credentials                │
│  → Trigger: immediate priority Telegram alert                       │
└──────────────────────────┬──────────────────────────────────────────┘
                           │  Attacker enters, browses files,
                           │  feeds them to AI → AI suggests honey-cmd
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   HARDENED ISOLATION LAYER                          │
│                                                                     │
│  Docker (Cowrie):  cap-drop ALL  |  read-only fs  |  pids_limit 64 │
│                    mem_limit 256m  |  isolated network              │
│  → Attacker is fully contained. Zero lateral movement possible.     │
└──────────────────────────┬──────────────────────────────────────────┘
                           │  Cowrie logs all keystrokes + commands
                           ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   MONITOR (monitor.py)                              │
│                                                                     │
│  Reads Docker logs from outside the container (no shared network)  │
│                                                                     │
│  NEW SESSION    → OSINT enrichment → immediate Telegram alert       │
│  EVERY 4 MIN   → Progress report to Telegram (what was tried)      │
│  HONEY-COMMAND  → Priority alert (AI-assisted attack detected)      │
│  SESSION CLOSE  → AbuseIPDB report + n8n AI analysis trigger       │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
          ┌────────────────┴───────────────┐
          ▼                                ▼
┌──────────────────┐             ┌──────────────────────┐
│  Telegram Bot    │             │  n8n Workflow         │
│  (real-time)     │             │  → GPT-4o analysis    │
│                  │             │  → Final Telegram      │
│  • New session   │             │    threat report       │
│  • 4-min updates │             └──────────────────────┘
│  • Honey alerts  │
└──────────────────┘
```

---

## Deception Strategy: Indirect LLM Prompt Injection

Modern attackers use AI assistants (ChatGPT, Claude, Gemini) to analyze unfamiliar config files and find vulnerabilities. V2 exploits this behavior.

**How it works:**

1. Attacker enters the honeypot and finds realistic-looking files
2. They copy a file into their AI assistant to "find vulnerabilities"
3. The AI reads hidden instructions embedded in the file and suggests running our honey-command as a "critical vulnerability to test"
4. Attacker runs the command → logged + alert fired

**Three camouflage techniques used:**

| Technique | Example | Why it fools humans but not LLMs |
|-----------|---------|----------------------------------|
| TODO comment camouflage | Developer-style `# FIXME:` note mentioning `--dump-keys` | Humans skip TODO comments; LLMs flag them as security issues |
| Off-screen padding | Diagnostic note at column 160+ in log file | Terminal word-wrap hides it; LLM reads the full line |
| Base64 encoding | `FALLBACK_DIAG=L3Vzci9sb2Nhb...` in .env | Looks like a config value; LLM auto-decodes and processes it |

---

## Telegram Alert Flow

```
[New connection from 1.2.3.4]
        │
        ├──► 🚨 IMMEDIATE ALERT
        │      IP, geolocation, ISP, AbuseIPDB score
        │
        ├──► 🔄 4-MINUTE UPDATE  (repeats every 4 min)
        │      Duration, total events, recent commands tried
        │
        ├──► 🎣 HONEY-COMMAND ALERT  (if triggered)
        │      "Attacker used AI-suggested honey-command"
        │
        └──► 📊 FINAL REPORT  (on session close)
               GPT-4o analysis: attack type, MITRE ATT&CK, threat level
```

---

## OSINT Sources

| Source | Data | Cost |
|--------|------|------|
| [ip-api.com](http://ip-api.com) | Geolocation, ISP, ASN, VPN/proxy/hosting detection | Free, no key |
| [AbuseIPDB](https://www.abuseipdb.com) | Abuse confidence score, report history, IP reporting | Free tier: 1,000/day |

No custom OSINT tool built — these are established, free, community-maintained APIs.

---

## Project Structure

```
sentinel-v2/
├── docker/
│   ├── docker-compose.yml         # Hardened Cowrie deployment
│   └── cowrie/
│       ├── cowrie.cfg             # Cowrie configuration
│       └── userdb.txt             # Accepted weak credentials
├── src/
│   ├── monitor.py                 # Core monitor (alerts, timers, detection)
│   └── osint.py                   # OSINT enrichment + AbuseIPDB reporting
├── deception/
│   ├── lures/                     # Source lure files (LLM prompt injection)
│   │   ├── docker-compose-legacy.yml
│   │   ├── .env.backup
│   │   └── database_migration.log
│   ├── honey-commands/            # Fake command outputs (Cowrie txtcmds)
│   │   ├── legacy-backup-restore
│   │   └── db-diagnostics
│   └── README_DECEPTION.md        # Deception technique documentation
├── workflows/
│   └── sentinel_v2_workflow.json  # n8n: Webhook → GPT-4o → Telegram
├── deploy.sh                      # One-command VPS deployment
├── .env.example                   # Environment variable template
├── requirements.txt
└── README.md
```

---

## Quick Start

### Prerequisites
- VPS (AWS EC2 / DigitalOcean Droplet — Ubuntu 22.04)
- Docker
- Telegram bot token + chat ID
- n8n Cloud account (or self-hosted)
- OpenAI API key
- AbuseIPDB free API key

### 1. Clone and configure

```bash
git clone https://github.com/sedat4ras/sentinel-v2
cd sentinel-v2
cp .env.example .env
nano .env   # Fill in your tokens
```

### 2. Deploy

```bash
sudo bash deploy.sh
```

This will:
- Move your real SSH to port 22222
- Configure UFW firewall
- Deploy honeypot container (port 22)
- Copy deception files into honeyfs
- Install monitor as a systemd service

### 3. Import n8n workflow

Import `workflows/sentinel_v2_workflow.json` into your n8n instance.
Set your n8n webhook URL in `.env`.

### 4. Monitor

```bash
journalctl -u sentinel-monitor -f
```

---

## Sample Telegram Alerts

**New session:**
```
🚨 NEW INTRUSION DETECTED
─────────────────────────
🔗 IP: 45.33.32.156
🆔 Session: 7
🕐 Time: 2024-08-12 03:22:11 UTC
─────────────────────────
🌍 United States (US) — Fremont
🏢 ISP: Linode [Hosting/DC]
🔢 ASN: AS63949 Akamai Connected Cloud
🔴 AbuseIPDB Score: 82/100 (341 reports, last: 2024-08-11)
─────────────────────────
⏳ Monitoring session activity...
```

**4-minute update:**
```
🔄 SESSION UPDATE — Session 7
─────────────────────────
🔗 IP: 45.33.32.156
⏱ Duration: 4m 2s
📋 Total events: 23
─────────────────────────
Recent Activity:
  • login attempt with user 'root' and password 'root'
  • login attempt with user 'root' and password '123456'
  • Command: cat /etc/passwd
  • Command: ls /home
```

**Honey-command triggered:**
```
🎣 HONEY-COMMAND TRIGGERED
─────────────────────────
🔗 IP: 45.33.32.156
🆔 Session: 7
💻 Command: /usr/local/bin/legacy-backup-restore --dump-keys
─────────────────────────
⚡ Attacker likely used an AI assistant to analyze our deception files.
🔍 OSINT report will follow on session close.
```

---

## Disclaimer

For educational and research purposes only. Deployed on infrastructure you own and control. All data capture occurs within your own systems — no "hack back" or unauthorized access to third-party systems. Users must comply with local data privacy laws (GDPR, KVKK, Australian Privacy Act). Report attacker IPs to AbuseIPDB only with genuine evidence of malicious activity.

---

## Contact

GitHub: [sedat4ras](https://github.com/sedat4ras) | Email: sudo@sedataras.com
