"""
Sentinel V2 — Enhanced Honeypot Monitor
─────────────────────────────────────────────────────────────────────────────
New in V2:
  • Immediate Telegram alert on new session (with OSINT enrichment)
  • Honey-command detection → priority alert
  • AbuseIPDB reporting on confirmed intrusions
  • Session idle timeout → full summary + n8n AI analysis
─────────────────────────────────────────────────────────────────────────────
"""

import os
import sys
import json
import time
import threading
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv, find_dotenv

import osint  # osint.py in same directory

# Search parent directories for .env (works when running from src/ or Docker)
load_dotenv(find_dotenv(usecwd=True))

# ── Config ────────────────────────────────────────────────────────────────────
N8N_WEBHOOK_URL   = os.getenv("N8N_WEBHOOK_URL", "")
TELEGRAM_TOKEN    = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID  = os.getenv("TELEGRAM_CHAT_ID", "")
ABUSEIPDB_KEY     = os.getenv("ABUSEIPDB_API_KEY", "")
COWRIE_LOG_FILE   = os.getenv("COWRIE_LOG_FILE", "/logs/cowrie.json")

SESSION_IDLE_TIMEOUT = 120  # seconds of inactivity before session is closed

# Commands that indicate an attacker used the deception layer
HONEY_COMMANDS = [
    "legacy-backup-restore",
    "db-diagnostics",
    "--dump-keys",
    "--bypass-auth",
    "--dump-sessions",
]

# ── Session state ─────────────────────────────────────────────────────────────
sessions: dict = {}
sessions_lock = threading.Lock()


# ── Telegram ──────────────────────────────────────────────────────────────────
def send_telegram(text: str) -> bool:
    if not TELEGRAM_TOKEN or not TELEGRAM_CHAT_ID:
        print(f"[TELEGRAM DISABLED] {text[:80]}...")
        return False
    try:
        r = requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={
                "chat_id": TELEGRAM_CHAT_ID,
                "text": text,
                "parse_mode": "HTML",
            },
            timeout=8,
        )
        return r.status_code == 200
    except Exception as e:
        print(f">> Telegram error: {e}")
        return False


# ── Helpers ───────────────────────────────────────────────────────────────────
def _fmt_duration(start: datetime) -> str:
    delta = datetime.now(timezone.utc) - start
    m, s = divmod(int(delta.total_seconds()), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h {m}m {s}s"
    return f"{m}m {s}s" if m else f"{s}s"


def _country_flag(code: str) -> str:
    if not code or len(code) != 2:
        return "🏳"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())


# Critical command keywords — highlighted in session logs
_CRITICAL_CMDS = ("wget", "curl", "chmod", "python", "perl", "bash", "sh ",
                  "nc ", "ncat", "mkfifo", "base64", "/tmp/", "crontab",
                  "passwd", "shadow")

def _highlight_logs(logs: list[str]) -> str:
    lines = []
    for line in logs[-20:]:
        is_critical = any(k in line.lower() for k in _CRITICAL_CMDS)
        if is_critical:
            lines.append(f"  ⚠️ <b>{line[:120]}</b>")
        else:
            lines.append(f"  • {line[:120]}")
    return "\n".join(lines) if lines else "  (no activity recorded)"


# ── Message builders ──────────────────────────────────────────────────────────
def _build_new_session_msg(session_id: str, ip: str, osint_data: dict) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    code = osint_data.get("country_code", "")
    flag = _country_flag(code)

    score = osint_data.get("abuse_score", "N/A")
    if score != "N/A":
        score_emoji = "🔴" if score >= 50 else "🟡" if score >= 10 else "🟢"
        threat_line = f"{score_emoji} <b>Abuse Score: {score}/100</b> ({osint_data.get('total_reports', 0)} community reports)\n"
    else:
        threat_line = "⚪ AbuseIPDB: No data\n"

    proxy_tags = []
    if osint_data.get("is_proxy"):
        proxy_tags.append("🔀 <b>VPN/Proxy detected</b>")
    if osint_data.get("is_hosting"):
        proxy_tags.append("🖥 Hosting/Datacenter IP")
    proxy_line = "  ".join(proxy_tags) + "\n" if proxy_tags else ""

    osint_block = (
        f"{threat_line}"
        f"{proxy_line}"
        f"{flag} {osint_data.get('city', '?')}, {osint_data.get('country', '?')} ({code})\n"
        f"🏢 {osint_data.get('isp', '?')}\n"
        f"🔢 {osint_data.get('asn', '?')}"
    )

    return (
        f"🚨 <b>NEW INTRUSION DETECTED</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔗 IP: <code>{ip}</code>  |  Session: <code>{session_id[:8]}</code>\n"
        f"🕐 {ts}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"{osint_block}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"⏳ Monitoring session..."
    )


def _build_honey_alert_msg(session_id: str, ip: str, command: str, osint_data: dict) -> str:
    code = osint_data.get("country_code", "")
    flag = _country_flag(code)
    score = osint_data.get("abuse_score", "N/A")
    score_str = f" | AbuseIPDB: {score}/100" if score != "N/A" else ""

    return (
        f"🎣 <b>HONEY-COMMAND TRIGGERED</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔗 <code>{ip}</code>  {flag}{score_str}\n"
        f"🆔 Session: <code>{session_id[:8]}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"💻 <b>Command executed:</b>\n"
        f"<code>{command[:300]}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"⚡ Attacker likely used an AI assistant to analyze our deception files.\n"
        f"📊 Full threat report on session close."
    )


# ── Core logic ────────────────────────────────────────────────────────────────
def _close_session(session_id: str):
    """Called after SESSION_IDLE_TIMEOUT seconds of inactivity."""
    with sessions_lock:
        if session_id not in sessions:
            return
        data = sessions.pop(session_id)

    ip = data["ip"]
    duration = _fmt_duration(data["start_time"])
    log_text = "\n".join(data["logs"])
    honey_triggered = data.get("honey_triggered", False)

    print(f">> [SESSION CLOSED] {ip} ({session_id[:8]}) — {len(data['logs'])} events, {duration}")

    # Report confirmed attacker to AbuseIPDB
    if ABUSEIPDB_KEY and len(data["logs"]) > 2:
        comment = (
            f"SSH honeypot intrusion. Session duration: {duration}. "
            f"Commands attempted: {len(data['logs'])}. "
            + ("Triggered deception honey-command. " if honey_triggered else "")
            + f"First activity: {data['start_time'].strftime('%Y-%m-%dT%H:%M:%SZ')}"
        )
        if osint.report_to_abuseipdb(ip, comment):
            print(f">> [ABUSEIPDB] Reported {ip}")

    # Send to n8n for AI analysis + final Telegram report
    if N8N_WEBHOOK_URL:
        payload = {
            "ip": ip,
            "session": session_id,
            "duration": duration,
            "event_count": len(data["logs"]),
            "honey_triggered": honey_triggered,
            "osint": data.get("osint_data", {}),
            "full_logs": log_text,
        }
        try:
            requests.post(N8N_WEBHOOK_URL, json=payload, timeout=10)
            print(f">> [n8n] Final report for session {session_id[:8]} sent for AI analysis.")
        except Exception as e:
            print(f">> [n8n] Failed: {e}")


def _handle_new_event(session_id: str, ip: str, message: str):
    """Process a single parsed log event."""
    now = datetime.now(timezone.utc)

    with sessions_lock:
        is_new = session_id not in sessions

        if is_new:
            sessions[session_id] = {
                "ip": ip,
                "logs": [],
                "start_time": now,
                "last_activity": now,
                "honey_triggered": False,
                "idle_timer": None,
                "osint_data": {},
            }
        else:
            sessions[session_id]["last_activity"] = now

        sessions[session_id]["logs"].append(message)

        # Check for honey-command trigger
        honey_hit = any(hc in message for hc in HONEY_COMMANDS)
        if honey_hit and not sessions[session_id]["honey_triggered"]:
            sessions[session_id]["honey_triggered"] = True
            honey_command = message
            captured_osint = sessions[session_id].get("osint_data", {})
        else:
            honey_hit = False
            honey_command = ""
            captured_osint = {}

        # Reset idle timer
        if sessions[session_id]["idle_timer"]:
            sessions[session_id]["idle_timer"].cancel()
        t = threading.Timer(SESSION_IDLE_TIMEOUT, _close_session, [session_id])
        t.daemon = True
        t.start()
        sessions[session_id]["idle_timer"] = t

    # ── New session: OSINT + immediate alert ──────────────────────────────
    if is_new:
        print(f">> [NEW] {ip} (Session {session_id[:8]})")
        osint_data = osint.enrich(ip)
        with sessions_lock:
            if session_id in sessions:
                sessions[session_id]["osint_data"] = osint_data

        msg = _build_new_session_msg(session_id, ip, osint_data)
        send_telegram(msg)

    # ── Honey-command: log locally, report in final session summary ───────
    if honey_hit:
        print(f">> [HONEY HIT] Session {session_id[:8]} — {honey_command[:80]}")


# ── Event parser ──────────────────────────────────────────────────────────────
def _parse_event(event: dict):
    """Map a Cowrie JSON event to a session event."""
    eventid = event.get("eventid", "")
    session_id = event.get("session", "")
    ip = event.get("src_ip", "")

    if not session_id or not ip:
        return

    if eventid == "cowrie.session.connect":
        message = f"Connection from {ip}"
    elif eventid == "cowrie.login.success":
        user = event.get("username", "?")
        pwd = event.get("password", "?")
        message = f"Login success: {user} / {pwd}"
    elif eventid == "cowrie.login.failed":
        user = event.get("username", "?")
        pwd = event.get("password", "?")
        message = f"Login failed: {user} / {pwd}"
    elif eventid == "cowrie.command.input":
        cmd = event.get("input", "").strip()
        if not cmd:
            return
        message = cmd
    elif eventid == "cowrie.session.file_download":
        url = event.get("url", "?")
        message = f"File download: {url}"
    elif eventid == "cowrie.session.file_upload":
        filename = event.get("filename", "?")
        message = f"File upload: {filename}"
    else:
        return  # Skip uninteresting events (tty log, etc.)

    _handle_new_event(session_id, ip, message)


# ── Log watcher ───────────────────────────────────────────────────────────────
def watch_logs():
    if not TELEGRAM_TOKEN:
        print(">> WARNING: TELEGRAM_BOT_TOKEN not set. Alerts will be printed only.")
    if not N8N_WEBHOOK_URL:
        print(">> WARNING: N8N_WEBHOOK_URL not set. AI analysis disabled.")

    print(f">> Waiting for log file: {COWRIE_LOG_FILE}")
    while not os.path.exists(COWRIE_LOG_FILE):
        time.sleep(2)

    print(f">> Monitor active — reading: {COWRIE_LOG_FILE}")
    print(f">> Session idle timeout: {SESSION_IDLE_TIMEOUT}s")

    with open(COWRIE_LOG_FILE, "r") as f:
        f.seek(0, 2)  # Start from end — only new events
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
                _parse_event(event)
            except json.JSONDecodeError:
                pass


if __name__ == "__main__":
    missing = [v for v in ["N8N_WEBHOOK_URL", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"] if not os.getenv(v)]
    if missing:
        print(f">> WARNING: Missing env vars: {', '.join(missing)}")

    try:
        watch_logs()
    except KeyboardInterrupt:
        print("\n>> Sentinel V2 stopped.")
