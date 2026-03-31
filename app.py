"""
SOC Analyst Dashboard — Flask Backend
Per-user log isolation, Kali log simulator, alert engine, PDF export,
total-logs tracking, analytics APIs.
"""

import json
import os
import random
import re
import threading
import uuid
from datetime import datetime, timedelta
from functools import wraps
from io import BytesIO

from flask import (Flask, Response, jsonify, redirect, render_template,
                   request, session, url_for)
from fpdf import FPDF
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = "soc-dashboard-2026-secret-key"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASETS_DIR = os.path.join(BASE_DIR, "datasets")
USERS_FILE = os.path.join(DATASETS_DIR, "users.json")
BLOCKED_IPS: dict[str, set] = {}  # per-user blocked IPs

_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_username(username):
    """Sanitise username for use in filenames."""
    return re.sub(r'[^a-zA-Z0-9_-]', '_', username)


def user_logs_path(username):
    """Return the path to a user's personal log file."""
    return os.path.join(DATASETS_DIR, f"logs_{_safe_username(username)}.json")


def user_stats_path(username):
    """Return the path to a user's personal stats file."""
    return os.path.join(DATASETS_DIR, f"stats_{_safe_username(username)}.json")


def load_json(filepath):
    with _lock:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, (list, dict)) else []
        except (FileNotFoundError, json.JSONDecodeError):
            return []


def load_stats(filepath):
    """Load the stats dict file, returning a default dict if missing."""
    with _lock:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return data
            return {"total_logs": 0, "today_logs": 0, "critical_alerts": 0, "history": []}
        except (FileNotFoundError, json.JSONDecodeError):
            return {"total_logs": 0, "today_logs": 0, "critical_alerts": 0, "history": []}


def save_json(filepath, data):
    with _lock:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            if request.path.startswith("/api/") or request.path.startswith("/export/"):
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def current_user():
    return session.get("user", "default")


def get_blocked(username):
    if username not in BLOCKED_IPS:
        BLOCKED_IPS[username] = set()
    return BLOCKED_IPS[username]


def next_id(logs):
    return max((l.get("id", 0) for l in logs), default=0) + 1


def update_user_stats(username, severity=None):
    """Increment total_logs and today_logs in the user stats file.
    If severity is 'critical', also increment critical_alerts."""
    path = user_stats_path(username)
    stats = load_stats(path)
    today = datetime.now().strftime("%Y-%m-%d")

    stats["total_logs"] = stats.get("total_logs", 0) + 1

    # Reset today_logs if the date changed
    if stats.get("_last_date") != today:
        stats["today_logs"] = 0
        stats["_last_date"] = today
    stats["today_logs"] = stats.get("today_logs", 0) + 1

    if severity and severity.lower() == "critical":
        stats["critical_alerts"] = stats.get("critical_alerts", 0) + 1

    # History: keep daily totals for the last 30 days
    history = stats.get("history", [])
    if history and history[-1].get("date") == today:
        history[-1]["count"] = history[-1].get("count", 0) + 1
    else:
        history.append({"date": today, "count": 1})
    # Keep last 30 entries
    if len(history) > 30:
        history = history[-30:]
    stats["history"] = history

    save_json(path, stats)
    return stats


def init_user_stats(username, logs):
    """Initialize stats file from existing logs."""
    path = user_stats_path(username)
    if os.path.exists(path):
        return
    today = datetime.now().strftime("%Y-%m-%d")
    total = len(logs)
    today_count = sum(1 for l in logs if l.get("timestamp", "").startswith(today))
    critical = sum(1 for l in logs if l.get("severity") == "critical")
    history = []
    # Group by date
    date_counts = {}
    for l in logs:
        d = l.get("timestamp", "")[:10]
        if d:
            date_counts[d] = date_counts.get(d, 0) + 1
    for d in sorted(date_counts.keys()):
        history.append({"date": d, "count": date_counts[d]})
    stats = {
        "total_logs": total,
        "today_logs": today_count,
        "critical_alerts": critical,
        "_last_date": today,
        "history": history[-30:]
    }
    save_json(path, stats)


# ---------------------------------------------------------------------------
# Seed logs for new users
# ---------------------------------------------------------------------------

SEED_LOGS = [
    {"event_type": "SSH_BRUTE_FORCE", "severity": "critical", "source_ip": "192.168.1.105",
     "message": "Multiple failed SSH login attempts detected from 192.168.1.105 (23 attempts in 60s)",
     "tool": "auth.log", "port": 22, "protocol": "TCP", "status": "open"},
    {"event_type": "PORT_SCAN", "severity": "high", "source_ip": "10.10.14.33",
     "message": "SYN port scan detected on ports 1-1024 from 10.10.14.33",
     "tool": "nmap", "port": 445, "protocol": "TCP", "status": "filtered"},
    {"event_type": "MALWARE_DETECTED", "severity": "critical", "source_ip": "172.16.0.88",
     "message": "Reverse shell payload detected in network traffic from 172.16.0.88",
     "tool": "wireshark", "port": 4444, "protocol": "TCP", "status": "open"},
    {"event_type": "SUSPICIOUS_TRAFFIC", "severity": "medium", "source_ip": "192.168.1.200",
     "message": "Unusual outbound DNS traffic to known C2 domain detected",
     "tool": "tcpdump", "port": 53, "protocol": "UDP", "status": "open"},
    {"event_type": "PORT_SCAN", "severity": "high", "source_ip": "10.10.14.55",
     "message": "Aggressive nmap scan (-T4 -A) detected targeting web servers",
     "tool": "nmap", "port": 80, "protocol": "TCP", "status": "open"},
    {"event_type": "SSH_BRUTE_FORCE", "severity": "high", "source_ip": "192.168.1.150",
     "message": "Failed SSH login attempts from 192.168.1.150 (12 attempts in 30s)",
     "tool": "auth.log", "port": 22, "protocol": "TCP", "status": "open"},
    {"event_type": "MALWARE_DETECTED", "severity": "critical", "source_ip": "203.0.113.42",
     "message": "Metasploit meterpreter session detected on port 8080",
     "tool": "snort", "port": 8080, "protocol": "TCP", "status": "open"},
    {"event_type": "SUSPICIOUS_TRAFFIC", "severity": "medium", "source_ip": "10.10.14.77",
     "message": "Data exfiltration attempt - large outbound transfer to external IP",
     "tool": "wireshark", "port": 443, "protocol": "TCP", "status": "open"},
    {"event_type": "SSH_BRUTE_FORCE", "severity": "high", "source_ip": "192.168.1.99",
     "message": "Dictionary attack on SSH service from compromised internal host",
     "tool": "auth.log", "port": 22, "protocol": "TCP", "status": "open"},
    {"event_type": "MALWARE_DETECTED", "severity": "critical", "source_ip": "198.51.100.10",
     "message": "Cobalt Strike beacon communication detected on port 50050",
     "tool": "snort", "port": 50050, "protocol": "TCP", "status": "open"},
    {"event_type": "SUSPICIOUS_TRAFFIC", "severity": "low", "source_ip": "192.168.1.180",
     "message": "Unusual ICMP traffic pattern detected - possible ping sweep",
     "tool": "tcpdump", "port": 0, "protocol": "ICMP", "status": "open"},
    {"event_type": "PORT_SCAN", "severity": "high", "source_ip": "10.10.14.90",
     "message": "Full TCP connect scan detected targeting all 65535 ports",
     "tool": "nmap", "port": 8443, "protocol": "TCP", "status": "open"},
    {"event_type": "MALWARE_DETECTED", "severity": "critical", "source_ip": "185.220.101.5",
     "message": "Ransomware C2 callback detected - TOR exit node communication",
     "tool": "snort", "port": 9001, "protocol": "TCP", "status": "open"},
]

DEST_IPS = [f"10.0.0.{i}" for i in range(1, 16)]


def create_seed_logs():
    """Generate timestamped seed logs for a new user."""
    logs = []
    base_time = datetime.now() - timedelta(hours=2)
    for i, seed in enumerate(SEED_LOGS):
        ts = base_time + timedelta(minutes=i * 3)
        logs.append({
            "id": i + 1,
            "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S"),
            "source_ip": seed["source_ip"],
            "destination_ip": random.choice(DEST_IPS),
            "event_type": seed["event_type"],
            "severity": seed["severity"],
            "message": seed["message"],
            "tool": seed["tool"],
            "port": seed["port"],
            "protocol": seed["protocol"],
            "status": seed["status"],
        })
    return logs


# ---------------------------------------------------------------------------
# Kali Linux Log Simulator
# ---------------------------------------------------------------------------

SUSPICIOUS_IPS = [
    "10.10.14.33", "10.10.14.55", "10.10.14.77", "10.10.14.90",
    "192.168.1.105", "192.168.1.150", "192.168.1.200", "192.168.1.99",
    "203.0.113.42", "198.51.100.10", "185.220.101.5", "172.16.0.88",
    "45.33.32.156", "91.121.87.10", "104.248.50.15",
]

KALI_TEMPLATES = [
    {"event_type": "SSH_BRUTE_FORCE",
     "message": "Multiple failed SSH login attempts from {ip} ({n} attempts in 60s)",
     "tool": "auth.log", "port": 22, "protocol": "TCP"},
    {"event_type": "PORT_SCAN",
     "message": "SYN port scan detected on ports 1-1024 from {ip}",
     "tool": "nmap", "port": 0, "protocol": "TCP"},
    {"event_type": "MALWARE_DETECTED",
     "message": "Reverse shell payload detected in traffic from {ip}",
     "tool": "snort", "port": 4444, "protocol": "TCP"},
    {"event_type": "SUSPICIOUS_TRAFFIC",
     "message": "Unusual outbound traffic to known C2 domain from {ip}",
     "tool": "tcpdump", "port": 53, "protocol": "TCP"},
]


def generate_random_log(logs):
    t = random.choice(KALI_TEMPLATES)
    ip = random.choice(SUSPICIOUS_IPS)
    sev_map = {
        "SSH_BRUTE_FORCE": random.choice(["high", "critical"]),
        "PORT_SCAN": random.choice(["medium", "high"]),
        "MALWARE_DETECTED": "critical",
        "SUSPICIOUS_TRAFFIC": random.choice(["low", "medium"]),
    }
    port = t["port"] if t["port"] else random.choice([80, 443, 445, 3306, 8080, 8443])
    severity = sev_map.get(t["event_type"], "medium")
    return {
        "id": next_id(logs),
        "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "source_ip": ip,
        "destination_ip": random.choice(DEST_IPS),
        "event_type": t["event_type"],
        "severity": severity,
        "message": t["message"].format(ip=ip, n=random.randint(8, 50)),
        "tool": t["tool"],
        "port": port,
        "protocol": t["protocol"],
        "status": random.choice(["open", "filtered", "closed", "blocked"]),
    }, severity


def maybe_inject(username):
    """~30% chance to auto-insert a Kali-simulated log."""
    if random.random() < 0.30:
        path = user_logs_path(username)
        logs = load_json(path)
        entry, severity = generate_random_log(logs)
        logs.append(entry)
        if len(logs) > 500:
            logs = logs[-500:]
        save_json(path, logs)
        update_user_stats(username, severity)


# ---------------------------------------------------------------------------
# Alert & Incident Engine
# ---------------------------------------------------------------------------

def build_alerts(logs):
    return [
        {"id": l["id"], "timestamp": l["timestamp"], "source_ip": l["source_ip"],
         "event_type": l["event_type"], "severity": l["severity"], "message": l["message"]}
        for l in logs if l.get("severity") in ("high", "critical")
    ]


def build_incidents(logs, blocked):
    groups = {}
    for l in logs:
        key = f"{l['source_ip']}|{l['event_type']}"
        if key not in groups:
            groups[key] = {
                "incident_id": f"INC-{l['id']:04d}",
                "source_ip": l["source_ip"],
                "event_type": l["event_type"],
                "severity": l["severity"],
                "first_seen": l["timestamp"],
                "last_seen": l["timestamp"],
                "count": 0,
                "blocked": l["source_ip"] in blocked,
            }
        groups[key]["last_seen"] = l["timestamp"]
        groups[key]["count"] += 1
        if groups[key]["count"] >= 5:
            groups[key]["severity"] = "critical"
    return sorted(groups.values(), key=lambda x: x["count"], reverse=True)


def build_stats(logs, blocked):
    sev = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    events = {}
    hours = {}
    dates = {}
    login_ips = {}

    for l in logs:
        s = l.get("severity", "low")
        sev[s] = sev.get(s, 0) + 1

        et = l.get("event_type", "UNKNOWN")
        events[et] = events.get(et, 0) + 1

        ts = l.get("timestamp", "")
        h = ts[11:13] if len(ts) >= 13 else "00"
        hours[h] = hours.get(h, 0) + 1

        d = ts[:10] if len(ts) >= 10 else "unknown"
        dates[d] = dates.get(d, 0) + 1

        if et == "SSH_BRUTE_FORCE":
            src = l.get("source_ip", "?")
            login_ips[src] = login_ips.get(src, 0) + 1

    # Incident count = unique (ip, event_type) pairs with high/critical severity
    inc_keys = set()
    for l in logs:
        if l.get("severity") in ("high", "critical"):
            inc_keys.add(f"{l['source_ip']}|{l['event_type']}")

    # Chart: Network Traffic (hourly)
    h_sorted = sorted(hours.keys())
    traffic = {"labels": [f"{h}:00" for h in h_sorted],
               "data": [hours[h] for h in h_sorted]}

    # Chart: Threat Activity (by event type)
    threats = {"labels": list(events.keys()), "data": list(events.values())}

    # Chart: Login Attempts (by IP, top 12)
    login_sorted = sorted(login_ips.items(), key=lambda x: x[1], reverse=True)[:12]
    logins = {"labels": [x[0] for x in login_sorted] or ["None"],
              "data": [x[1] for x in login_sorted] or [0]}

    # Chart: Incident Trend (last 7 days)
    trend_labels, trend_data = [], []
    for i in range(6, -1, -1):
        day = datetime.now() - timedelta(days=i)
        trend_labels.append(day.strftime("%b %d"))
        trend_data.append(dates.get(day.strftime("%Y-%m-%d"), 0))

    # Severity breakdown for analytics
    severity_breakdown = {"labels": list(sev.keys()), "data": list(sev.values())}

    return {
        "total_logs": len(logs),
        "total_alerts": sev["high"] + sev["critical"],
        "total_incidents": len(inc_keys),
        "blocked_ips": len(blocked),
        "severity": severity_breakdown,
        "threats": threats,
        "traffic": traffic,
        "login_attempts": logins,
        "trend": {"labels": trend_labels, "data": trend_data},
    }


# ---------------------------------------------------------------------------
# Auth Routes
# ---------------------------------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if not username or not password:
            return render_template("register.html", error="All fields required.")
        users = load_json(USERS_FILE)
        if any(u["username"] == username for u in users):
            return render_template("register.html", error="Username already exists.")
        users.append({
            "username": username,
            "password": generate_password_hash(password),
            "role": "analyst",
            "created": datetime.now().isoformat(),
        })
        save_json(USERS_FILE, users)

        # Create personal log file with seed data
        lpath = user_logs_path(username)
        if not os.path.exists(lpath):
            seed_logs = create_seed_logs()
            save_json(lpath, seed_logs)
            init_user_stats(username, seed_logs)

        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        users = load_json(USERS_FILE)
        user = next((u for u in users if u["username"] == username), None)
        if user and check_password_hash(user["password"], password):
            session["user"] = username
            session["role"] = user.get("role", "analyst")
            # Ensure log file exists
            lpath = user_logs_path(username)
            if not os.path.exists(lpath):
                seed_logs = create_seed_logs()
                save_json(lpath, seed_logs)
                init_user_stats(username, seed_logs)
            else:
                # Make sure stats file exists for existing users
                spath = user_stats_path(username)
                if not os.path.exists(spath):
                    logs = load_json(lpath)
                    init_user_stats(username, logs)
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="Invalid credentials.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Page Routes
# ---------------------------------------------------------------------------

@app.route("/")
@login_required
def dashboard():
    return render_template("index.html", user=current_user())


# ---------------------------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------------------------

@app.route("/api/logs")
@login_required
def api_logs():
    user = current_user()
    maybe_inject(user)
    return jsonify(load_json(user_logs_path(user)))


@app.route("/api/search")
@login_required
def api_search():
    user = current_user()
    ip = request.args.get("ip", "").strip()
    sev = request.args.get("severity", "").strip().lower()
    event = request.args.get("event_type", "").strip()
    logs = load_json(user_logs_path(user))
    if ip:
        logs = [l for l in logs if ip in l.get("source_ip", "") or ip in l.get("destination_ip", "")]
    if sev:
        logs = [l for l in logs if l.get("severity", "").lower() == sev]
    if event:
        logs = [l for l in logs if l.get("event_type", "") == event]
    return jsonify(logs)


@app.route("/api/alerts")
@login_required
def api_alerts():
    user = current_user()
    maybe_inject(user)
    return jsonify(build_alerts(load_json(user_logs_path(user))))


@app.route("/api/incidents")
@login_required
def api_incidents():
    user = current_user()
    return jsonify(build_incidents(load_json(user_logs_path(user)), get_blocked(user)))


@app.route("/api/stats")
@login_required
def api_stats():
    user = current_user()
    maybe_inject(user)
    return jsonify(build_stats(load_json(user_logs_path(user)), get_blocked(user)))


@app.route("/api/add-log", methods=["POST"])
@login_required
def api_add_log():
    user = current_user()
    data = request.get_json(silent=True) or {}

    # Validate required fields
    source_ip = data.get("source_ip", "").strip()
    destination_ip = data.get("destination_ip", "").strip() or "10.0.0.1"
    event_type = data.get("event_type", "").strip()
    severity = data.get("severity", "medium").strip().lower()
    status = data.get("status", "open").strip().lower()

    if not source_ip:
        return jsonify({"error": "source_ip is required."}), 400
    if not event_type:
        return jsonify({"error": "event_type is required."}), 400
    if not destination_ip:
        return jsonify({"error": "destination_ip is required."}), 400
    if severity not in ("low", "medium", "high", "critical"):
        severity = "medium"
    if status not in ("open", "filtered", "closed", "blocked"):
        status = "open"

    path = user_logs_path(user)
    logs = load_json(path)

    entry = {
        "id": next_id(logs),
        "uid": str(uuid.uuid4())[:8],
        "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "event_type": event_type,
        "severity": severity,
        "message": data.get("message", "").strip() or f"{event_type} from {source_ip}",
        "tool": data.get("tool", "manual").strip() or "manual",
        "port": int(data.get("port", 0)),
        "protocol": data.get("protocol", "TCP").strip() or "TCP",
        "status": status,
    }

    logs.append(entry)
    if len(logs) > 500:
        logs = logs[-500:]
    save_json(path, logs)

    # Update persistent stats
    update_user_stats(user, severity)

    return jsonify({"success": True, "log": entry})


@app.route("/api/total-logs")
@login_required
def api_total_logs():
    """Return lifetime stats for the current user."""
    user = current_user()
    stats = load_stats(user_stats_path(user))
    today = datetime.now().strftime("%Y-%m-%d")
    # If date rolled over, reset today_logs
    if stats.get("_last_date") != today:
        stats["today_logs"] = 0
    return jsonify({
        "total_logs": stats.get("total_logs", 0),
        "today_logs": stats.get("today_logs", 0),
        "critical_alerts": stats.get("critical_alerts", 0),
        "history": stats.get("history", []),
    })


@app.route("/api/block-ip", methods=["POST"])
@login_required
def api_block_ip():
    user = current_user()
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "IP address required"}), 400
    blocked = get_blocked(user)
    blocked.add(ip)
    return jsonify({"success": True, "message": f"IP {ip} blocked.", "blocked": list(blocked)})


@app.route("/api/clear-logs", methods=["POST"])
@login_required
def api_clear_logs():
    user = current_user()
    save_json(user_logs_path(user), [])
    return jsonify({"success": True, "message": "All logs cleared."})


# ---------------------------------------------------------------------------
# PDF Export
# ---------------------------------------------------------------------------

@app.route("/export/pdf")
@login_required
def export_pdf():
    user = current_user()
    logs = load_json(user_logs_path(user))

    pdf = FPDF(orientation="L", unit="mm", format="A4")
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "SOC Analyst Dashboard - Log Report", ln=True, align="C")
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(0, 6,
             f"User: {user}   |   Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}   |   Total: {len(logs)}",
             ln=True, align="C")
    pdf.ln(6)

    # Table header
    headers = ["ID", "Timestamp", "Source IP", "Dest IP", "Event Type", "Severity", "Status"]
    widths = [14, 42, 38, 32, 48, 22, 20]
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_fill_color(30, 0, 60)
    pdf.set_text_color(255, 255, 255)
    for h, w in zip(headers, widths):
        pdf.cell(w, 7, h, border=1, fill=True, align="C")
    pdf.ln()

    # Rows
    pdf.set_font("Helvetica", "", 7)
    pdf.set_text_color(0, 0, 0)
    for log in logs:
        vals = [
            str(log.get("id", "")),
            str(log.get("timestamp", "")),
            str(log.get("source_ip", "")),
            str(log.get("destination_ip", "")),
            str(log.get("event_type", "")),
            str(log.get("severity", "")),
            str(log.get("status", "")),
        ]
        for v, w in zip(vals, widths):
            pdf.cell(w, 6, v[:24], border=1, align="C")
        pdf.ln()

    pdf_bytes = bytes(pdf.output())

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Type": "application/pdf",
            "Content-Disposition": f"attachment; filename=SOC_Report_{_safe_username(user)}.pdf",
            "Content-Length": str(len(pdf_bytes)),
        },
    )


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    os.makedirs(DATASETS_DIR, exist_ok=True)
    if not os.path.exists(USERS_FILE):
        save_json(USERS_FILE, [])
    app.run(debug=True, port=5000)
