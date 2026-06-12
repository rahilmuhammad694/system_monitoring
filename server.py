import socket
import webbrowser
import os
import time
import threading
import json
import base64
import shutil
import certifi
import functools
from pymongo import MongoClient
from waitress import serve
from datetime import datetime, timedelta
from collections import deque, defaultdict
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template_string, request, redirect, session, \
    send_from_directory, send_file, jsonify, Response, stream_with_context
import anthropic

# ─────────────────────────────────────────────
# ENV CONFIG  (create a .env file — never hardcode secrets)
# ─────────────────────────────────────────────
# pip install python-dotenv
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # fall back to environment variables already set

ADMIN_USERNAME      = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = generate_password_hash(os.getenv("ADMIN_PASSWORD", "admin123"))
MONGO_URI           = os.getenv("MONGO_URI",
    "mongodb+srv://rahilmuhammad694:bvlY5LdqFIZA71to@cluster0.vz12nrc.mongodb.net/"
    "monitoring_system?retryWrites=true&w=majority")
SECRET_KEY          = os.getenv("FLASK_SECRET", os.urandom(32).hex())

# ─────────────────────────────────────────────
# FLASK APP
# ─────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),   # auto-expire after 8 h idle
)

# ─────────────────────────────────────────────
# EMPLOYEE STORE  (move to MongoDB in production)
# ─────────────────────────────────────────────
EMPLOYEES = {
    "emp001": {
        "password": generate_password_hash(os.getenv("EMP001_PASSWORD", "emp123")),
        "name": "Alice Johnson", "department": "IT", "email": "alice@company.com",
    },
    "emp002": {
        "password": generate_password_hash(os.getenv("EMP002_PASSWORD", "emp456")),
        "name": "Bob Smith", "department": "Finance", "email": "bob@company.com",
    },
}

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ─────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────
mongo_client = MongoClient(MONGO_URI, tlsCAFile=certifi.where(), serverSelectionTimeoutMS=5000)
try:
    mongo_client.server_info()
    print("✅ MongoDB Connected")
except Exception as e:
    print("❌ MongoDB Connection Failed:", e)

db                 = mongo_client["monitoring_system"]
logs_collection    = db["logs"]
clients_collection = db["clients"]
alerts_collection  = db["alerts"]
tasks_collection   = db["tasks"]
audit_collection   = db["audit_logs"]          # ← NEW: audit trail

SAVE_DIRECTORY    = os.path.join(BASE_DIR, "client_data")
RECYCLE_DIRECTORY = os.path.join(BASE_DIR, "deleted_clients")
os.makedirs(SAVE_DIRECTORY, exist_ok=True)
os.makedirs(RECYCLE_DIRECTORY, exist_ok=True)

# ─────────────────────────────────────────────
# RATE LIMITER  (in-memory, per IP)
# ─────────────────────────────────────────────
_login_attempts: dict[str, list] = defaultdict(list)
_LOGIN_MAX   = 5           # max attempts
_LOGIN_WINDOW = 15 * 60   # 15-minute lockout window (seconds)

def is_rate_limited(ip: str) -> tuple[bool, int]:
    """Returns (blocked, seconds_remaining)."""
    now = time.time()
    attempts = [t for t in _login_attempts[ip] if now - t < _LOGIN_WINDOW]
    _login_attempts[ip] = attempts
    if len(attempts) >= _LOGIN_MAX:
        remaining = int(_LOGIN_WINDOW - (now - attempts[0]))
        return True, remaining
    return False, 0

def record_attempt(ip: str):
    _login_attempts[ip].append(time.time())

def clear_attempts(ip: str):
    _login_attempts.pop(ip, None)

# ─────────────────────────────────────────────
# AUDIT LOG
# ─────────────────────────────────────────────
def audit(action: str, detail: str = "", username: str = ""):
    ip = request.remote_addr if request else "system"
    username = username or session.get("username", "—")
    audit_collection.insert_one({
        "timestamp": datetime.now(),
        "action": action,
        "detail": detail,
        "username": username,
        "ip": ip,
    })

# ─────────────────────────────────────────────
# AUTH DECORATOR
# ─────────────────────────────────────────────
def require_role(*roles):
    """Usage: @require_role("admin")  or  @require_role("admin","employee")"""
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            if not session.get("logged_in"):
                return redirect("/")
            if roles and session.get("role") not in roles:
                return redirect("/")
            # Session timeout: refresh last_active on every request
            last_active = session.get("last_active")
            if last_active:
                idle = (datetime.now() - datetime.fromisoformat(last_active)).total_seconds()
                if idle > 8 * 3600:          # 8-hour idle timeout
                    session.clear()
                    return redirect("/?timeout=1")
            session["last_active"] = datetime.now().isoformat()
            return fn(*args, **kwargs)
        return wrapper
    return decorator

# ─────────────────────────────────────────────
# RISK / ACTIVITY / ALERTS  (unchanged logic)
# ─────────────────────────────────────────────
risk_data     = {}
activity_log  = deque(maxlen=100)
alerts        = deque(maxlen=20)
ai_chat_history = {}

def update_risk(client_id, message):
    message = message.lower()
    if client_id not in risk_data:
        risk_data[client_id] = 0
    if "usb inserted" in message:
        risk_data[client_id] += 5
    if "restricted application" in message:
        risk_data[client_id] += 3

def add_activity(message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    activity_log.appendleft(f"[{timestamp}] {message}")
    _broadcast({"type": "activity", "message": f"[{timestamp}] {message}"})

def add_alert(message):
    timestamp = datetime.now()
    alerts.appendleft(f"[{timestamp.strftime('%H:%M:%S')}] {message}")
    alerts_collection.insert_one({"message": message, "timestamp": timestamp})
    _broadcast({"type": "alert", "message": f"[{timestamp.strftime('%H:%M:%S')}] {message}"})

def get_risk_level(score):
    if score >= 7:   return "HIGH",   "danger"
    elif score >= 3: return "MEDIUM", "warning"
    else:            return "LOW",    "success"

# ─────────────────────────────────────────────
# SSE  (Server-Sent Events — real-time push)
# ─────────────────────────────────────────────
_sse_subscribers: list = []
_sse_lock = threading.Lock()

def _broadcast(data: dict):
    """Push a JSON event to every open SSE connection."""
    payload = f"data: {json.dumps(data)}\n\n"
    with _sse_lock:
        dead = []
        for q in _sse_subscribers:
            try:
                q.append(payload)
            except Exception:
                dead.append(q)
        for q in dead:
            _sse_subscribers.remove(q)

def _push_stats():
    """Broadcast updated summary stats to all dashboards."""
    total_clients = clients_collection.count_documents({})
    total_alerts  = alerts_collection.count_documents({})
    high = medium = low = 0
    for c in clients_collection.find():
        score = risk_data.get(c.get("client_id"), 0)
        lvl, _ = get_risk_level(score)
        if lvl == "HIGH":   high   += 1
        elif lvl == "MEDIUM": medium += 1
        else:               low    += 1
    _broadcast({
        "type": "stats",
        "total_clients": total_clients,
        "total_alerts": total_alerts,
        "high_risk": high, "medium_risk": medium, "low_risk": low,
    })

@app.route("/stream")
@require_role("admin")
def stream():
    """SSE endpoint — admin dashboard subscribes here."""
    q = deque(maxlen=50)
    with _sse_lock:
        _sse_subscribers.append(q)

    def generate():
        yield "data: {\"type\":\"connected\"}\n\n"
        while True:
            if q:
                yield q.popleft()
            else:
                time.sleep(0.2)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )

# ─────────────────────────────────────────────
# FEATURE FLAGS
# ─────────────────────────────────────────────
FEATURES = {
    "restricted_apps":    True,
    "screenshot_capture": True,
    "auto_refresh":       True,   # now means "enable SSE"; meta refresh removed
    "usb_detection":      True,
}

# ═══════════════════════════════════════════════════════════
# SHARED CSS / JS COMPONENTS  (unchanged from original)
# ═══════════════════════════════════════════════════════════
SHARED_STYLES = """
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css">
<style>
:root {
  --bg-base: #060b14; --bg-surface: #0c1424; --bg-card: #0f1d2e;
  --bg-card-hover: #152338; --border: #1a2d45; --border-bright: #1e3a55;
  --accent: #00d4ff; --accent-glow: rgba(0,212,255,0.15); --accent-2: #7c3aed;
  --text-primary: #e2e8f0; --text-secondary: #64748b; --text-muted: #334155;
  --success: #10b981; --warning: #f59e0b; --danger: #ef4444;
  --font-sans: 'Inter', system-ui, sans-serif; --font-mono: 'JetBrains Mono', monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg-base); color: var(--text-primary); font-family: var(--font-sans); min-height: 100vh; font-size: 14px; }
::-webkit-scrollbar { width: 5px; height: 5px; }
::-webkit-scrollbar-track { background: var(--bg-surface); }
::-webkit-scrollbar-thumb { background: var(--border-bright); border-radius: 3px; }
.top-nav { background: var(--bg-surface); border-bottom: 1px solid var(--border); padding: 0 24px; height: 56px; display: flex; align-items: center; justify-content: space-between; position: sticky; top: 0; z-index: 100; }
.nav-brand { display: flex; align-items: center; gap: 10px; font-weight: 600; font-size: 15px; color: var(--text-primary); text-decoration: none; }
.nav-brand .shield-icon { width: 32px; height: 32px; background: linear-gradient(135deg, var(--accent), var(--accent-2)); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 16px; flex-shrink: 0; }
.nav-actions { display: flex; align-items: center; gap: 8px; }
.btn-nav { background: transparent; border: 1px solid var(--border); color: var(--text-secondary); padding: 6px 14px; border-radius: 6px; font-size: 13px; cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; gap: 6px; transition: all 0.15s; }
.btn-nav:hover { border-color: var(--accent); color: var(--accent); }
.btn-nav-danger { border-color: rgba(239,68,68,0.3); color: var(--danger); }
.btn-nav-danger:hover { background: rgba(239,68,68,0.1); border-color: var(--danger); color: var(--danger); }
.layout { display: flex; min-height: calc(100vh - 56px); }
.sidebar { width: 220px; background: var(--bg-surface); border-right: 1px solid var(--border); padding: 20px 12px; flex-shrink: 0; display: flex; flex-direction: column; gap: 4px; }
.sidebar-label { font-size: 10px; font-weight: 600; letter-spacing: 0.1em; color: var(--text-muted); text-transform: uppercase; padding: 12px 8px 4px; }
.sidebar-link { display: flex; align-items: center; gap: 10px; padding: 9px 10px; border-radius: 7px; color: var(--text-secondary); text-decoration: none; font-size: 13px; font-weight: 500; transition: all 0.15s; border: 1px solid transparent; }
.sidebar-link:hover { background: var(--bg-card); color: var(--text-primary); border-color: var(--border); }
.sidebar-link.active { background: var(--accent-glow); color: var(--accent); border-color: rgba(0,212,255,0.2); }
.sidebar-link i { font-size: 15px; width: 18px; text-align: center; }
.main-content { flex: 1; padding: 24px; overflow: auto; }
.card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; transition: all 0.2s; }
.card:hover { border-color: var(--border-bright); }
.card-header-custom { padding: 14px 18px; border-bottom: 1px solid var(--border); font-weight: 600; font-size: 13px; display: flex; align-items: center; gap: 8px; color: var(--text-primary); }
.card-body-custom { padding: 18px; }
.stat-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 18px; position: relative; overflow: hidden; transition: all 0.2s; }
.stat-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px; }
.stat-card.blue::before   { background: linear-gradient(90deg, var(--accent), transparent); }
.stat-card.purple::before { background: linear-gradient(90deg, var(--accent-2), transparent); }
.stat-card.green::before  { background: linear-gradient(90deg, var(--success), transparent); }
.stat-card.yellow::before { background: linear-gradient(90deg, var(--warning), transparent); }
.stat-card.red::before    { background: linear-gradient(90deg, var(--danger), transparent); }
.stat-card:hover { border-color: var(--border-bright); transform: translateY(-2px); }
.stat-label { font-size: 11px; font-weight: 500; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px; }
.stat-value { font-size: 28px; font-weight: 700; color: var(--text-primary); font-variant-numeric: tabular-nums; }
.stat-icon { position: absolute; right: 16px; top: 50%; transform: translateY(-50%); font-size: 28px; opacity: 0.08; }
.badge-status { display: inline-flex; align-items: center; gap: 5px; padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; }
.badge-online  { background: rgba(16,185,129,0.15); color: var(--success); border: 1px solid rgba(16,185,129,0.2); }
.badge-offline { background: rgba(100,116,139,0.15); color: var(--text-secondary); border: 1px solid var(--border); }
.badge-high    { background: rgba(239,68,68,0.15); color: var(--danger); border: 1px solid rgba(239,68,68,0.2); }
.badge-medium  { background: rgba(245,158,11,0.15); color: var(--warning); border: 1px solid rgba(245,158,11,0.2); }
.badge-low     { background: rgba(16,185,129,0.15); color: var(--success); border: 1px solid rgba(16,185,129,0.2); }
.activity-feed { font-family: var(--font-mono); font-size: 12px; color: #38bdf8; max-height: 220px; overflow-y: auto; }
.activity-item { padding: 5px 0; border-bottom: 1px solid var(--border); }
.activity-item:last-child { border-bottom: none; }
.client-table { width: 100%; border-collapse: collapse; }
.client-table th { font-size: 11px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary); padding: 10px 14px; border-bottom: 1px solid var(--border); text-align: left; }
.client-table td { padding: 12px 14px; border-bottom: 1px solid var(--border); font-size: 13px; }
.client-table tr:last-child td { border-bottom: none; }
.client-table tr:hover td { background: var(--bg-card-hover); }
.btn-primary-custom { background: var(--accent); color: #000; border: none; padding: 7px 16px; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; gap: 5px; transition: all 0.15s; }
.btn-primary-custom:hover { background: #00b8d9; color: #000; }
.btn-ghost { background: transparent; border: 1px solid var(--border); color: var(--text-secondary); padding: 6px 14px; border-radius: 6px; font-size: 12px; cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; gap: 5px; transition: all 0.15s; }
.btn-ghost:hover { border-color: var(--border-bright); color: var(--text-primary); }
.btn-danger-custom { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.25); color: var(--danger); padding: 6px 14px; border-radius: 6px; font-size: 12px; cursor: pointer; display: inline-flex; align-items: center; gap: 5px; transition: all 0.15s; text-decoration: none; }
.btn-danger-custom:hover { background: rgba(239,68,68,0.2); border-color: var(--danger); color: var(--danger); }
.form-input { background: var(--bg-base); border: 1px solid var(--border); color: var(--text-primary); padding: 10px 14px; border-radius: 7px; font-size: 13px; width: 100%; font-family: var(--font-sans); transition: border-color 0.15s; }
.form-input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-glow); }
.form-input::placeholder { color: var(--text-muted); }
.form-label { font-size: 12px; font-weight: 500; color: var(--text-secondary); margin-bottom: 6px; display: block; }
.form-group { margin-bottom: 16px; }
.toggle-row { display: flex; align-items: center; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid var(--border); }
.toggle-row:last-child { border-bottom: none; }
.toggle-info h6 { font-size: 13px; font-weight: 500; color: var(--text-primary); margin-bottom: 2px; }
.toggle-info p { font-size: 12px; color: var(--text-secondary); }
.form-check-input { width: 40px; height: 22px; cursor: pointer; }
.form-check-input:checked { background-color: var(--accent); border-color: var(--accent); }
.ai-panel { position: fixed; bottom: 20px; right: 20px; width: 360px; background: var(--bg-card); border: 1px solid var(--border-bright); border-radius: 14px; box-shadow: 0 20px 60px rgba(0,0,0,0.6); z-index: 1000; display: none; flex-direction: column; overflow: hidden; }
.ai-panel.open { display: flex; }
.ai-panel-header { background: linear-gradient(135deg, var(--accent-2), #4f46e5); padding: 14px 16px; display: flex; align-items: center; justify-content: space-between; }
.ai-panel-header h6 { font-size: 13px; font-weight: 600; color: white; margin: 0; }
.ai-messages { flex: 1; overflow-y: auto; padding: 14px; max-height: 320px; display: flex; flex-direction: column; gap: 10px; min-height: 120px; }
.ai-msg { padding: 9px 12px; border-radius: 10px; font-size: 13px; line-height: 1.5; max-width: 88%; }
.ai-msg.user { background: rgba(0,212,255,0.1); border: 1px solid rgba(0,212,255,0.2); color: var(--text-primary); align-self: flex-end; border-radius: 10px 10px 2px 10px; }
.ai-msg.assistant { background: var(--bg-surface); border: 1px solid var(--border); color: var(--text-primary); align-self: flex-start; border-radius: 10px 10px 10px 2px; }
.ai-msg.loading { color: var(--text-secondary); font-style: italic; }
.ai-input-row { padding: 12px; border-top: 1px solid var(--border); display: flex; gap: 8px; }
.ai-input { background: var(--bg-base); border: 1px solid var(--border); color: var(--text-primary); padding: 9px 12px; border-radius: 7px; font-size: 13px; flex: 1; font-family: var(--font-sans); }
.ai-input:focus { outline: none; border-color: var(--accent); }
.ai-send-btn { background: linear-gradient(135deg, var(--accent), var(--accent-2)); color: white; border: none; width: 36px; height: 36px; border-radius: 7px; cursor: pointer; font-size: 15px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; transition: opacity 0.15s; }
.ai-send-btn:hover { opacity: 0.85; }
.ai-fab { position: fixed; bottom: 20px; right: 20px; width: 52px; height: 52px; background: linear-gradient(135deg, var(--accent-2), #4f46e5); border: none; border-radius: 50%; color: white; font-size: 22px; cursor: pointer; z-index: 999; box-shadow: 0 6px 20px rgba(124,58,237,0.4); display: flex; align-items: center; justify-content: center; transition: transform 0.2s; }
.ai-fab:hover { transform: scale(1.1); }
.alert-toast { position: fixed; bottom: 80px; right: 20px; background: rgba(239,68,68,0.95); color: white; padding: 12px 18px; border-radius: 10px; box-shadow: 0 8px 24px rgba(0,0,0,0.5); z-index: 9999; font-size: 13px; font-weight: 500; display: flex; align-items: center; gap: 8px; animation: slideIn 0.3s ease; max-width: 320px; }
@keyframes slideIn { from { transform: translateX(40px); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
.login-page { min-height: 100vh; display: flex; align-items: center; justify-content: center; background: var(--bg-base); position: relative; overflow: hidden; }
.login-box { background: var(--bg-card); border: 1px solid var(--border); border-radius: 16px; padding: 40px; width: 400px; position: relative; z-index: 1; box-shadow: 0 20px 60px rgba(0,0,0,0.4); }
.login-logo { width: 52px; height: 52px; background: linear-gradient(135deg, var(--accent), var(--accent-2)); border-radius: 14px; display: flex; align-items: center; justify-content: center; font-size: 24px; margin-bottom: 20px; }
.login-title { font-size: 22px; font-weight: 700; margin-bottom: 4px; }
.login-subtitle { font-size: 13px; color: var(--text-secondary); margin-bottom: 28px; }
.login-tabs { display: flex; gap: 4px; background: var(--bg-surface); padding: 4px; border-radius: 8px; margin-bottom: 24px; }
.login-tab { flex: 1; padding: 8px; text-align: center; border-radius: 6px; font-size: 13px; font-weight: 500; cursor: pointer; color: var(--text-secondary); border: none; background: transparent; transition: all 0.15s; }
.login-tab.active { background: var(--bg-card); color: var(--text-primary); }
.error-msg { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.2); color: var(--danger); padding: 10px 14px; border-radius: 7px; font-size: 13px; margin-bottom: 16px; }
.warn-msg  { background: rgba(245,158,11,0.1); border: 1px solid rgba(245,158,11,0.2); color: var(--warning); padding: 10px 14px; border-radius: 7px; font-size: 13px; margin-bottom: 16px; }
.task-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 16px; margin-bottom: 12px; transition: all 0.2s; }
.task-card:hover { border-color: var(--border-bright); }
.task-card.todo       { border-left: 3px solid var(--text-muted); }
.task-card.in_progress { border-left: 3px solid var(--warning); }
.task-card.done       { border-left: 3px solid var(--success); }
.task-title { font-size: 14px; font-weight: 600; margin-bottom: 4px; }
.task-meta  { font-size: 12px; color: var(--text-secondary); }
.task-priority-high   { color: var(--danger); }
.task-priority-medium { color: var(--warning); }
.task-priority-low    { color: var(--success); }
.page-header { margin-bottom: 24px; }
.page-header h1 { font-size: 20px; font-weight: 700; margin-bottom: 4px; }
.page-header p  { font-size: 13px; color: var(--text-secondary); }
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
.grid-3 { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; }
.grid-5 { display: grid; grid-template-columns: repeat(5, 1fr); gap: 16px; }
.mb-16 { margin-bottom: 16px; } .mb-20 { margin-bottom: 20px; } .mb-24 { margin-bottom: 24px; }
.flex { display: flex; } .items-center { align-items: center; } .justify-between { justify-content: space-between; }
.gap-8 { gap: 8px; } .gap-12 { gap: 12px; }
.text-sm { font-size: 13px; } .text-xs { font-size: 11px; }
.text-muted { color: var(--text-secondary); } .font-mono { font-family: var(--font-mono); }
.pulse-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--success); box-shadow: 0 0 0 2px rgba(16,185,129,0.3); animation: pulse 2s infinite; }
@keyframes pulse { 0%,100%{box-shadow:0 0 0 2px rgba(16,185,129,0.3)} 50%{box-shadow:0 0 0 5px rgba(16,185,129,0)} }
@media (max-width: 768px) { .sidebar{display:none} .grid-5{grid-template-columns:repeat(2,1fr)} .grid-3{grid-template-columns:1fr} .grid-2{grid-template-columns:1fr} }
</style>
"""

AI_PANEL_HTML = """
<button class="ai-fab" id="aiFab" onclick="toggleAI()" title="AI Security Assistant">
  <i class="bi bi-stars"></i>
</button>
<div class="ai-panel" id="aiPanel">
  <div class="ai-panel-header">
    <div style="display:flex;align-items:center;gap:8px;">
      <i class="bi bi-stars" style="font-size:16px;color:white;"></i>
      <h6>AI Security Assistant</h6>
    </div>
    <button onclick="toggleAI()" style="background:none;border:none;color:white;cursor:pointer;font-size:18px;"><i class="bi bi-x"></i></button>
  </div>
  <div class="ai-messages" id="aiMessages">
    <div class="ai-msg assistant">👋 Hi! I'm your AI security analyst. Ask me anything about your monitoring data, alerts, or security posture.</div>
  </div>
  <div class="ai-input-row">
    <input class="ai-input" id="aiInput" placeholder="Ask about security events..." onkeydown="if(event.key==='Enter')sendAI()">
    <button class="ai-send-btn" onclick="sendAI()"><i class="bi bi-send-fill"></i></button>
  </div>
</div>
<script>
function toggleAI() {
  const panel = document.getElementById('aiPanel');
  const fab = document.getElementById('aiFab');
  const isOpen = panel.classList.contains('open');
  panel.classList.toggle('open', !isOpen);
  fab.style.display = isOpen ? 'flex' : 'none';
}
async function sendAI() {
  const input = document.getElementById('aiInput');
  const msg = input.value.trim();
  if (!msg) return;
  input.value = '';
  const messages = document.getElementById('aiMessages');
  messages.innerHTML += `<div class="ai-msg user">${msg}</div>`;
  messages.innerHTML += `<div class="ai-msg assistant loading" id="aiLoading">Analyzing...</div>`;
  messages.scrollTop = messages.scrollHeight;
  try {
    const res = await fetch('/ai_chat', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({message:msg}) });
    const data = await res.json();
    document.getElementById('aiLoading').remove();
    messages.innerHTML += `<div class="ai-msg assistant">${data.reply}</div>`;
    messages.scrollTop = messages.scrollHeight;
  } catch(e) {
    document.getElementById('aiLoading').textContent = 'Error connecting to AI.';
  }
}
</script>
"""

# ─────────────────────────────────────────────
# SSE CLIENT JS  — replaces old ALERT_JS + meta refresh
# ─────────────────────────────────────────────
SSE_CLIENT_JS = """
<script>
(function() {
  const es = new EventSource('/stream');

  es.onmessage = function(e) {
    const data = JSON.parse(e.data);

    if (data.type === 'stats') {
      const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
      set('stat-total-clients', data.total_clients);
      set('stat-total-alerts',  data.total_alerts);
      set('stat-high-risk',     data.high_risk);
      set('stat-medium-risk',   data.medium_risk);
      set('stat-low-risk',      data.low_risk);
    }

    if (data.type === 'activity') {
      const feed = document.getElementById('activityFeed');
      if (feed) {
        const div = document.createElement('div');
        div.className = 'activity-item';
        div.textContent = data.message;
        feed.prepend(div);
        // keep max 20 items visible
        while (feed.children.length > 20) feed.removeChild(feed.lastChild);
      }
    }

    if (data.type === 'alert') {
      // Update alert feed
      const feed = document.getElementById('alertFeed');
      if (feed) {
        const div = document.createElement('div');
        div.className = 'activity-item';
        div.style.color = '#f87171';
        div.textContent = data.message;
        feed.prepend(div);
        while (feed.children.length > 10) feed.removeChild(feed.lastChild);
      }
      // Toast notification
      const toast = document.createElement('div');
      toast.className = 'alert-toast';
      toast.innerHTML = '<i class="bi bi-exclamation-triangle-fill"></i> ' + data.message;
      document.body.appendChild(toast);
      setTimeout(() => toast.remove(), 5000);
    }
  };

  es.onerror = function() {
    // SSE reconnects automatically; log silently
    console.warn('SSE connection lost, retrying...');
  };
})();
</script>
"""

# ═══════════════════════════════════════════════════════════
# AUTH ROUTES
# ═══════════════════════════════════════════════════════════
@app.route("/", methods=["GET", "POST"])
def login():
    # Show session-expired notice
    timeout_notice = request.args.get("timeout") == "1"
    error = ""
    warn  = "Your session expired. Please log in again." if timeout_notice else ""

    if request.method == "POST":
        ip   = request.remote_addr
        role = request.form.get("role", "admin")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Rate limit check
        blocked, remaining = is_rate_limited(ip)
        if blocked:
            minutes = remaining // 60
            error = f"Too many failed attempts. Try again in {minutes} min."
            return render_template_string(_login_template(), error=error, warn=warn,
                                          tab=request.args.get("tab", "admin"))

        if role == "admin":
            if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
                clear_attempts(ip)
                session.clear()
                session["logged_in"]    = True
                session["role"]         = "admin"
                session["username"]     = username
                session["last_active"]  = datetime.now().isoformat()
                session.permanent       = True
                audit("login", "Admin login", username)
                activity_log.clear()
                return redirect("/dashboard")
            else:
                record_attempt(ip)
                audit("failed_login", f"Bad admin password for '{username}'", username)
                error = "Invalid admin credentials."

        elif role == "employee":
            emp = EMPLOYEES.get(username)
            if emp and check_password_hash(emp["password"], password):
                clear_attempts(ip)
                session.clear()
                session["logged_in"]   = True
                session["role"]        = "employee"
                session["username"]    = username
                session["emp_name"]    = emp["name"]
                session["last_active"] = datetime.now().isoformat()
                session.permanent      = True
                audit("login", f"Employee login: {emp['name']}", username)
                return redirect("/employee")
            else:
                record_attempt(ip)
                audit("failed_login", f"Bad employee password for '{username}'", username)
                error = "Invalid employee credentials."

    active_tab = request.args.get("tab", "admin")
    return render_template_string(_login_template(), error=error, warn=warn, tab=active_tab)


def _login_template():
    return """
<!doctype html><html><head><title>SecureWatch — Login</title>
""" + SHARED_STYLES + """
</head><body>
<div class="login-page">
  <div class="login-box">
    <div class="login-logo"><i class="bi bi-shield-check" style="color:white;"></i></div>
    <div class="login-title">SecureWatch</div>
    <div class="login-subtitle">Employee &amp; System Monitoring Platform</div>

    {% if warn %}<div class="warn-msg"><i class="bi bi-clock"></i> {{warn}}</div>{% endif %}
    {% if error %}<div class="error-msg"><i class="bi bi-exclamation-circle"></i> {{error}}</div>{% endif %}

    <div class="login-tabs">
      <button class="login-tab {% if tab=='admin' %}active{% endif %}" onclick="setTab('admin')">
        <i class="bi bi-shield-lock"></i> Admin
      </button>
      <button class="login-tab {% if tab=='employee' %}active{% endif %}" onclick="setTab('employee')">
        <i class="bi bi-person-badge"></i> Employee
      </button>
    </div>

    <form method="post" id="loginForm">
      <input type="hidden" name="role" id="roleInput" value="{{tab}}">
      <div class="form-group">
        <label class="form-label">Username</label>
        <input class="form-input" name="username" placeholder="Enter username" required autocomplete="username">
      </div>
      <div class="form-group">
        <label class="form-label">Password</label>
        <input class="form-input" name="password" type="password" placeholder="Enter password" required autocomplete="current-password">
      </div>
      <button type="submit" class="btn-primary-custom" style="width:100%;justify-content:center;padding:11px;">
        <i class="bi bi-box-arrow-in-right"></i> Sign In
      </button>
    </form>
    <p style="margin-top:20px;font-size:11px;color:var(--text-muted);text-align:center;">
      Admin: admin / admin123 &nbsp;|&nbsp; Employee: emp001 / emp123
    </p>
  </div>
</div>
<script>
function setTab(tab) {
  document.getElementById('roleInput').value = tab;
  document.querySelectorAll('.login-tab').forEach((t,i) => {
    t.classList.toggle('active', (i===0&&tab==='admin')||(i===1&&tab==='employee'));
  });
}
setTab('{{tab}}');
</script>
</body></html>
"""


# ═══════════════════════════════════════════════════════════
# DASHBOARD  (SSE-powered — no meta refresh)
# ═══════════════════════════════════════════════════════════
@app.route("/dashboard")
@require_role("admin")
def dashboard():
    total_clients = clients_collection.count_documents({})
    total_alerts  = alerts_collection.count_documents({})
    high_risk = medium_risk = low_risk = 0
    clients = []
    now = datetime.now()

    for c in clients_collection.find():
        client_id = c.get("client_id")
        score = risk_data.get(client_id, 0)
        level, _ = get_risk_level(score)
        if level == "HIGH":   high_risk   += 1
        elif level == "MEDIUM": medium_risk += 1
        else:                 low_risk    += 1
        last_seen = c.get("last_seen", now)
        delta  = (now - last_seen).seconds
        status = "Online" if delta < 15 else "Offline"
        clients.append((client_id, status, score, level))

    return render_template_string("""
<!doctype html><html><head>
<title>Dashboard — SecureWatch</title>
""" + SHARED_STYLES + """
</head><body>

<nav class="top-nav">
  <a href="/dashboard" class="nav-brand">
    <div class="shield-icon"><i class="bi bi-shield-check"></i></div>SecureWatch
  </a>
  <div class="nav-actions">
    <span style="font-size:12px;color:var(--text-secondary);margin-right:4px;">
      <i class="bi bi-circle-fill" style="color:var(--success);font-size:7px;vertical-align:middle;"></i>
      Live
    </span>
    <span style="font-size:12px;color:var(--text-secondary);margin-right:4px;">
      <i class="bi bi-person-circle"></i> Admin
    </span>
    <a href="/audit_log" class="btn-nav"><i class="bi bi-journal-text"></i> Audit Log</a>
    <a href="/settings"  class="btn-nav"><i class="bi bi-gear"></i> Settings</a>
    <a href="/logout"    class="btn-nav btn-nav-danger"><i class="bi bi-box-arrow-right"></i> Logout</a>
  </div>
</nav>

<div class="layout">
  <aside class="sidebar">
    <div class="sidebar-label">Monitor</div>
    <a href="/dashboard"   class="sidebar-link active"><i class="bi bi-grid-1x2"></i> Dashboard</a>
    <a href="/alerts_page" class="sidebar-link"><i class="bi bi-bell"></i> Alerts</a>
    <div class="sidebar-label">Clients</div>
    <a href="#clients" class="sidebar-link"><i class="bi bi-display"></i> All Clients</a>
    <div class="sidebar-label">System</div>
    <a href="/settings"      class="sidebar-link"><i class="bi bi-toggles"></i> Features</a>
    <a href="/employee_tasks" class="sidebar-link"><i class="bi bi-list-check"></i> Task Manager</a>
    <a href="/audit_log"     class="sidebar-link"><i class="bi bi-journal-text"></i> Audit Log</a>
  </aside>

  <main class="main-content">
    <div class="page-header">
      <h1><i class="bi bi-grid-1x2" style="color:var(--accent);margin-right:8px;"></i>Overview</h1>
      <p>Real-time system monitoring — updates automatically via live connection</p>
    </div>

    <!-- Stats — IDs are updated live by SSE -->
    <div class="grid-5 mb-24">
      <div class="stat-card blue">
        <div class="stat-label">Total Clients</div>
        <div class="stat-value" id="stat-total-clients">{{total_clients}}</div>
        <i class="bi bi-display stat-icon"></i>
      </div>
      <div class="stat-card purple">
        <div class="stat-label">Total Alerts</div>
        <div class="stat-value" id="stat-total-alerts">{{total_alerts}}</div>
        <i class="bi bi-bell stat-icon"></i>
      </div>
      <div class="stat-card red">
        <div class="stat-label">High Risk</div>
        <div class="stat-value" id="stat-high-risk">{{high_risk}}</div>
        <i class="bi bi-shield-x stat-icon"></i>
      </div>
      <div class="stat-card yellow">
        <div class="stat-label">Medium Risk</div>
        <div class="stat-value" id="stat-medium-risk">{{medium_risk}}</div>
        <i class="bi bi-shield-exclamation stat-icon"></i>
      </div>
      <div class="stat-card green">
        <div class="stat-label">Low Risk</div>
        <div class="stat-value" id="stat-low-risk">{{low_risk}}</div>
        <i class="bi bi-shield-check stat-icon"></i>
      </div>
    </div>

    <!-- Activity + Recent Alerts — fed live by SSE -->
    <div class="grid-2 mb-24">
      <div class="card">
        <div class="card-header-custom">
          <div class="pulse-dot"></div> Live Activity Feed
        </div>
        <div class="card-body-custom">
          <div class="activity-feed" id="activityFeed">
            {% if activity_log %}
              {% for event in activity_log %}
              <div class="activity-item">{{event}}</div>
              {% endfor %}
            {% else %}
              <div style="color:var(--text-muted);font-family:var(--font-sans);">No activity yet.</div>
            {% endif %}
          </div>
        </div>
      </div>
      <div class="card">
        <div class="card-header-custom">
          <i class="bi bi-bell-fill" style="color:var(--danger);"></i> Recent Alerts
        </div>
        <div class="card-body-custom">
          <div class="activity-feed" id="alertFeed" style="color:#f87171;">
            {% if alerts %}
              {% for alert in alerts %}
              <div class="activity-item">{{alert}}</div>
              {% endfor %}
            {% else %}
              <div style="color:var(--text-muted);font-family:var(--font-sans);">No alerts.</div>
            {% endif %}
          </div>
        </div>
      </div>
    </div>

    <!-- Clients Table -->
    <div class="card" id="clients">
      <div class="card-header-custom" style="justify-content:space-between;">
        <span><i class="bi bi-display" style="color:var(--accent);"></i> Connected Clients</span>
        <span style="font-size:12px;color:var(--text-secondary);">{{clients|length}} total</span>
      </div>
      <div style="overflow-x:auto;">
        <table class="client-table">
          <thead>
            <tr><th>Client ID</th><th>Status</th><th>Risk Level</th><th>Risk Score</th><th>Actions</th></tr>
          </thead>
          <tbody>
            {% for client_id, status, score, level in clients %}
            <tr>
              <td><span class="font-mono" style="font-size:12px;">{{client_id}}</span></td>
              <td>
                <span class="badge-status {{'badge-online' if status=='Online' else 'badge-offline'}}">{{status}}</span>
              </td>
              <td>
                <span class="badge-status {{'badge-high' if level=='HIGH' else ('badge-medium' if level=='MEDIUM' else 'badge-low')}}">{{level}}</span>
              </td>
              <td><span class="font-mono">{{score}}</span></td>
              <td>
                <div style="display:flex;gap:6px;flex-wrap:wrap;">
                  <a href="/view_logs/{{client_id}}"        class="btn-ghost"><i class="bi bi-file-text"></i> Logs</a>
                  <a href="/download_logs/{{client_id}}"    class="btn-ghost"><i class="bi bi-download"></i> Export</a>
                  <a href="/view_screenshots/{{client_id}}" class="btn-ghost"><i class="bi bi-images"></i> Screens</a>
                  <form method="post" action="/delete_client/{{client_id}}" style="margin:0;" onsubmit="return confirm('Move to recycle?');">
                    <button class="btn-danger-custom"><i class="bi bi-trash"></i></button>
                  </form>
                </div>
              </td>
            </tr>
            {% else %}
            <tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:40px;">No clients connected yet.</td></tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </main>
</div>

""" + AI_PANEL_HTML + SSE_CLIENT_JS + """
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body></html>
""", clients=clients, activity_log=activity_log, alerts=alerts,
     total_clients=total_clients, total_alerts=total_alerts,
     high_risk=high_risk, medium_risk=medium_risk, low_risk=low_risk)


# ═══════════════════════════════════════════════════════════
# AUDIT LOG PAGE  (NEW)
# ═══════════════════════════════════════════════════════════
@app.route("/audit_log")
@require_role("admin")
def audit_log():
    entries = list(audit_collection.find().sort("timestamp", -1).limit(200))
    return render_template_string("""
<!doctype html><html><head><title>Audit Log — SecureWatch</title>
""" + SHARED_STYLES + """
</head><body>
<nav class="top-nav">
  <a href="/dashboard" class="nav-brand"><div class="shield-icon"><i class="bi bi-shield-check"></i></div>SecureWatch</a>
  <div class="nav-actions">
    <a href="/dashboard" class="btn-nav"><i class="bi bi-arrow-left"></i> Dashboard</a>
    <a href="/logout"    class="btn-nav btn-nav-danger"><i class="bi bi-box-arrow-right"></i> Logout</a>
  </div>
</nav>
<div class="layout">
  <aside class="sidebar">
    <div class="sidebar-label">Monitor</div>
    <a href="/dashboard" class="sidebar-link"><i class="bi bi-grid-1x2"></i> Dashboard</a>
    <a href="/alerts_page" class="sidebar-link"><i class="bi bi-bell"></i> Alerts</a>
    <div class="sidebar-label">System</div>
    <a href="/settings" class="sidebar-link"><i class="bi bi-toggles"></i> Features</a>
    <a href="/audit_log" class="sidebar-link active"><i class="bi bi-journal-text"></i> Audit Log</a>
  </aside>
  <main class="main-content">
    <div class="page-header">
      <h1><i class="bi bi-journal-text" style="color:var(--accent);margin-right:8px;"></i>Audit Log</h1>
      <p>All login, logout, and admin action events — last 200 entries</p>
    </div>
    <div class="card">
      <div class="card-header-custom"><i class="bi bi-list-ul"></i> Event History ({{entries|length}})</div>
      <div style="overflow-x:auto;">
        <table class="client-table">
          <thead>
            <tr><th>Time</th><th>Action</th><th>User</th><th>IP</th><th>Detail</th></tr>
          </thead>
          <tbody>
            {% for e in entries %}
            <tr>
              <td class="font-mono text-muted" style="white-space:nowrap;font-size:11px;">
                {{e.get('timestamp','').strftime('%Y-%m-%d %H:%M:%S') if e.get('timestamp') else ''}}
              </td>
              <td>
                {% set a = e.get('action','') %}
                {% if 'login' in a and 'failed' not in a %}
                  <span class="badge-status badge-low"><i class="bi bi-box-arrow-in-right"></i> {{a}}</span>
                {% elif 'failed' in a %}
                  <span class="badge-status badge-high"><i class="bi bi-x-circle"></i> {{a}}</span>
                {% elif 'logout' in a %}
                  <span class="badge-status badge-offline"><i class="bi bi-box-arrow-right"></i> {{a}}</span>
                {% else %}
                  <span class="badge-status badge-medium"><i class="bi bi-activity"></i> {{a}}</span>
                {% endif %}
              </td>
              <td class="font-mono text-sm">{{e.get('username','—')}}</td>
              <td class="font-mono" style="font-size:11px;color:var(--text-muted);">{{e.get('ip','—')}}</td>
              <td style="font-size:12px;color:var(--text-secondary);">{{e.get('detail','')}}</td>
            </tr>
            {% else %}
            <tr><td colspan="5" style="text-align:center;color:var(--text-muted);padding:40px;">No audit events yet.</td></tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </main>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body></html>
""", entries=entries)


# ═══════════════════════════════════════════════════════════
# ALERTS PAGE
# ═══════════════════════════════════════════════════════════
@app.route("/alerts_page")
@require_role("admin")
def alerts_page():
    all_alerts = list(alerts_collection.find().sort("timestamp", -1).limit(100))
    return render_template_string("""
<!doctype html><html><head><title>Alerts — SecureWatch</title>
""" + SHARED_STYLES + """
</head><body>
<nav class="top-nav">
  <a href="/dashboard" class="nav-brand"><div class="shield-icon"><i class="bi bi-shield-check"></i></div>SecureWatch</a>
  <div class="nav-actions">
    <a href="/dashboard" class="btn-nav"><i class="bi bi-arrow-left"></i> Dashboard</a>
    <a href="/logout" class="btn-nav btn-nav-danger"><i class="bi bi-box-arrow-right"></i> Logout</a>
  </div>
</nav>
<div class="layout">
  <aside class="sidebar">
    <div class="sidebar-label">Monitor</div>
    <a href="/dashboard"   class="sidebar-link"><i class="bi bi-grid-1x2"></i> Dashboard</a>
    <a href="/alerts_page" class="sidebar-link active"><i class="bi bi-bell"></i> Alerts</a>
  </aside>
  <main class="main-content">
    <div class="page-header">
      <h1><i class="bi bi-bell-fill" style="color:var(--danger);margin-right:8px;"></i>Security Alerts</h1>
      <p>All recorded security events from monitored clients</p>
    </div>
    <div class="card">
      <div class="card-header-custom"><i class="bi bi-bell"></i> Alert History ({{alerts|length}} events)</div>
      <div style="overflow-x:auto;">
        <table class="client-table">
          <thead><tr><th>Time</th><th>Message</th></tr></thead>
          <tbody>
            {% for a in alerts %}
            <tr>
              <td class="font-mono text-muted" style="white-space:nowrap;">{{a.get('timestamp','')}}</td>
              <td style="color:#f87171;"><i class="bi bi-exclamation-triangle"></i> {{a.get('message','')}}</td>
            </tr>
            {% else %}
            <tr><td colspan="2" style="text-align:center;color:var(--text-muted);padding:40px;">No alerts recorded.</td></tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </main>
</div>
""" + AI_PANEL_HTML + """
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body></html>
""", alerts=all_alerts)


# ═══════════════════════════════════════════════════════════
# SETTINGS
# ═══════════════════════════════════════════════════════════
@app.route("/settings")
@require_role("admin")
def settings():
    return render_template_string("""
<!doctype html><html><head><title>Settings — SecureWatch</title>
""" + SHARED_STYLES + """
</head><body>
<nav class="top-nav">
  <a href="/dashboard" class="nav-brand"><div class="shield-icon"><i class="bi bi-shield-check"></i></div>SecureWatch</a>
  <div class="nav-actions">
    <a href="/dashboard" class="btn-nav"><i class="bi bi-arrow-left"></i> Dashboard</a>
    <a href="/logout"    class="btn-nav btn-nav-danger"><i class="bi bi-box-arrow-right"></i> Logout</a>
  </div>
</nav>
<div class="layout">
  <aside class="sidebar">
    <div class="sidebar-label">Monitor</div>
    <a href="/dashboard" class="sidebar-link"><i class="bi bi-grid-1x2"></i> Dashboard</a>
    <div class="sidebar-label">System</div>
    <a href="/settings"      class="sidebar-link active"><i class="bi bi-toggles"></i> Features</a>
    <a href="/employee_tasks" class="sidebar-link"><i class="bi bi-list-check"></i> Task Manager</a>
  </aside>
  <main class="main-content">
    <div class="page-header">
      <h1><i class="bi bi-gear" style="color:var(--accent);margin-right:8px;"></i>Settings</h1>
      <p>Toggle monitoring features and system preferences</p>
    </div>
    <div class="card" style="max-width:600px;">
      <div class="card-header-custom"><i class="bi bi-toggles"></i> Monitoring Features</div>
      <div class="card-body-custom">

        <form method="post" action="/toggle_feature">
        <input type="hidden" name="feature" value="restricted_apps">
        <div class="toggle-row">
          <div class="toggle-info"><h6>Restricted App Detection</h6><p>Alert when monitored clients open restricted applications</p></div>
          <input class="form-check-input" type="checkbox" onchange="this.form.submit()" {% if features.restricted_apps %}checked{% endif %}>
        </div></form>

        <form method="post" action="/toggle_feature">
        <input type="hidden" name="feature" value="screenshot_capture">
        <div class="toggle-row">
          <div class="toggle-info"><h6>Screenshot Capture</h6><p>Automatically capture screenshots on security events</p></div>
          <input class="form-check-input" type="checkbox" onchange="this.form.submit()" {% if features.screenshot_capture %}checked{% endif %}>
        </div></form>

        <form method="post" action="/toggle_feature">
        <input type="hidden" name="feature" value="usb_detection">
        <div class="toggle-row">
          <div class="toggle-info"><h6>USB Device Detection</h6><p>Alert when USB devices are inserted on client machines</p></div>
          <input class="form-check-input" type="checkbox" onchange="this.form.submit()" {% if features.usb_detection %}checked{% endif %}>
        </div></form>

        <form method="post" action="/toggle_feature">
        <input type="hidden" name="feature" value="auto_refresh">
        <div class="toggle-row">
          <div class="toggle-info"><h6>Live Dashboard (SSE)</h6><p>Push real-time updates to the dashboard via server-sent events</p></div>
          <input class="form-check-input" type="checkbox" onchange="this.form.submit()" {% if features.auto_refresh %}checked{% endif %}>
        </div></form>

      </div>
    </div>

    <!-- Security Info card -->
    <div class="card" style="max-width:600px;margin-top:20px;">
      <div class="card-header-custom"><i class="bi bi-shield-lock" style="color:var(--accent);"></i> Security Hardening</div>
      <div class="card-body-custom" style="font-size:13px;display:flex;flex-direction:column;gap:10px;">
        <div style="display:flex;align-items:center;gap:8px;color:var(--success);">
          <i class="bi bi-check-circle-fill"></i> Rate limiting active — 5 attempts / 15 min lockout per IP
        </div>
        <div style="display:flex;align-items:center;gap:8px;color:var(--success);">
          <i class="bi bi-check-circle-fill"></i> Session idle timeout — 8 hours
        </div>
        <div style="display:flex;align-items:center;gap:8px;color:var(--success);">
          <i class="bi bi-check-circle-fill"></i> Audit log — all logins and actions recorded
        </div>
        <div style="display:flex;align-items:center;gap:8px;color:var(--success);">
          <i class="bi bi-check-circle-fill"></i> Credentials loaded from environment / .env file
        </div>
        <div style="display:flex;align-items:center;gap:8px;color:var(--success);">
          <i class="bi bi-check-circle-fill"></i> HttpOnly, SameSite=Lax cookies
        </div>
      </div>
    </div>

  </main>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body></html>
""", features=FEATURES)


@app.route("/toggle_feature", methods=["POST"])
@require_role("admin")
def toggle_feature():
    feature = request.form.get("feature")
    if feature in FEATURES:
        FEATURES[feature] = not FEATURES[feature]
        audit("feature_toggle", f"{feature} → {FEATURES[feature]}")
    return redirect(request.referrer or "/settings")


# ═══════════════════════════════════════════════════════════
# EMPLOYEE PORTAL  (unchanged except decorator)
# ═══════════════════════════════════════════════════════════
@app.route("/employee")
@require_role("employee")
def employee_portal():
    username   = session.get("username")
    emp        = EMPLOYEES.get(username, {})
    emp_name   = emp.get("name", username)
    department = emp.get("department", "")
    my_tasks   = list(tasks_collection.find({"assigned_to": username}).sort("created_at", -1))
    todo        = [t for t in my_tasks if t.get("status") == "todo"]
    in_progress = [t for t in my_tasks if t.get("status") == "in_progress"]
    done        = [t for t in my_tasks if t.get("status") == "done"]

    return render_template_string("""
<!doctype html><html><head><title>Employee Portal — SecureWatch</title>
""" + SHARED_STYLES + """
</head><body>
<nav class="top-nav">
  <a href="/employee" class="nav-brand"><div class="shield-icon"><i class="bi bi-person-badge"></i></div>Employee Portal</a>
  <div class="nav-actions">
    <span style="font-size:12px;color:var(--text-secondary);">
      <i class="bi bi-person-circle"></i> {{emp_name}} &nbsp;·&nbsp; {{department}}
    </span>
    <a href="/logout" class="btn-nav btn-nav-danger"><i class="bi bi-box-arrow-right"></i> Logout</a>
  </div>
</nav>
<div class="layout">
  <aside class="sidebar">
    <div class="sidebar-label">My Work</div>
    <a href="/employee"         class="sidebar-link active"><i class="bi bi-kanban"></i> My Tasks</a>
    <a href="/employee/profile" class="sidebar-link"><i class="bi bi-person"></i> My Profile</a>
    <div class="sidebar-label">Company</div>
    <a href="/employee/notices" class="sidebar-link"><i class="bi bi-megaphone"></i> Notices</a>
  </aside>
  <main class="main-content">
    <div class="page-header">
      <h1>👋 Welcome back, {{emp_name}}</h1>
      <p>{{department}} Department · {{my_tasks|length}} tasks assigned to you</p>
    </div>
    <div class="grid-3 mb-24">
      <div class="stat-card blue"><div class="stat-label">To Do</div><div class="stat-value">{{todo|length}}</div><i class="bi bi-circle stat-icon"></i></div>
      <div class="stat-card yellow"><div class="stat-label">In Progress</div><div class="stat-value">{{in_progress|length}}</div><i class="bi bi-clock stat-icon"></i></div>
      <div class="stat-card green"><div class="stat-label">Completed</div><div class="stat-value">{{done|length}}</div><i class="bi bi-check-circle stat-icon"></i></div>
    </div>
    <div class="grid-3">
      <div>
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:14px;">
          <span style="width:10px;height:10px;border-radius:50%;background:var(--text-muted);display:inline-block;"></span>
          <span style="font-weight:600;font-size:13px;">TO DO</span>
          <span style="background:var(--bg-card);border:1px solid var(--border);border-radius:20px;padding:1px 8px;font-size:11px;color:var(--text-secondary);">{{todo|length}}</span>
        </div>
        {% for task in todo %}
        <div class="task-card todo">
          <div class="task-title">{{task.title}}</div>
          <div class="task-meta" style="margin-bottom:10px;">{{task.get('description','')}}</div>
          <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px;">
            <span class="text-xs task-priority-{{task.get('priority','low')}}"><i class="bi bi-flag"></i> {{task.get('priority','low').title()}}</span>
            <span class="text-xs text-muted">Due: {{task.get('due_date','—')}}</span>
          </div>
          <div style="margin-top:10px;">
            <form method="post" action="/employee/update_task/{{task._id}}" style="margin:0;">
              <input type="hidden" name="status" value="in_progress">
              <button class="btn-ghost" style="font-size:11px;padding:5px 10px;">Start <i class="bi bi-play"></i></button>
            </form>
          </div>
        </div>
        {% else %}
        <div style="text-align:center;color:var(--text-muted);font-size:13px;padding:30px;border:1px dashed var(--border);border-radius:10px;">No tasks</div>
        {% endfor %}
      </div>
      <div>
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:14px;">
          <span style="width:10px;height:10px;border-radius:50%;background:var(--warning);display:inline-block;"></span>
          <span style="font-weight:600;font-size:13px;">IN PROGRESS</span>
          <span style="background:var(--bg-card);border:1px solid var(--border);border-radius:20px;padding:1px 8px;font-size:11px;color:var(--text-secondary);">{{in_progress|length}}</span>
        </div>
        {% for task in in_progress %}
        <div class="task-card in_progress">
          <div class="task-title">{{task.title}}</div>
          <div class="task-meta" style="margin-bottom:10px;">{{task.get('description','')}}</div>
          <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px;">
            <span class="text-xs task-priority-{{task.get('priority','low')}}"><i class="bi bi-flag"></i> {{task.get('priority','low').title()}}</span>
            <span class="text-xs text-muted">Due: {{task.get('due_date','—')}}</span>
          </div>
          <div style="margin-top:10px;display:flex;gap:6px;">
            <form method="post" action="/employee/update_task/{{task._id}}" style="margin:0;">
              <input type="hidden" name="status" value="done">
              <button class="btn-primary-custom" style="font-size:11px;padding:5px 10px;">Complete <i class="bi bi-check2"></i></button>
            </form>
            <form method="post" action="/employee/update_task/{{task._id}}" style="margin:0;">
              <input type="hidden" name="status" value="todo">
              <button class="btn-ghost" style="font-size:11px;padding:5px 10px;">Pause</button>
            </form>
          </div>
        </div>
        {% else %}
        <div style="text-align:center;color:var(--text-muted);font-size:13px;padding:30px;border:1px dashed var(--border);border-radius:10px;">No tasks</div>
        {% endfor %}
      </div>
      <div>
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:14px;">
          <span style="width:10px;height:10px;border-radius:50%;background:var(--success);display:inline-block;"></span>
          <span style="font-weight:600;font-size:13px;">DONE</span>
          <span style="background:var(--bg-card);border:1px solid var(--border);border-radius:20px;padding:1px 8px;font-size:11px;color:var(--text-secondary);">{{done|length}}</span>
        </div>
        {% for task in done %}
        <div class="task-card done" style="opacity:0.75;">
          <div class="task-title" style="text-decoration:line-through;color:var(--text-secondary);">{{task.title}}</div>
          <div class="task-meta">{{task.get('description','')}}</div>
        </div>
        {% else %}
        <div style="text-align:center;color:var(--text-muted);font-size:13px;padding:30px;border:1px dashed var(--border);border-radius:10px;">No tasks</div>
        {% endfor %}
      </div>
    </div>
  </main>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body></html>
""", emp_name=emp_name, department=department,
     my_tasks=my_tasks, todo=todo, in_progress=in_progress, done=done)


@app.route("/employee/update_task/<task_id>", methods=["POST"])
@require_role("employee")
def update_task(task_id):
    from bson import ObjectId
    new_status = request.form.get("status")
    tasks_collection.update_one({"_id": ObjectId(task_id)}, {"$set": {"status": new_status}})
    audit("task_update", f"Task {task_id} → {new_status}")
    return redirect("/employee")


@app.route("/employee/profile")
@require_role("employee")
def employee_profile():
    username = session.get("username")
    emp = EMPLOYEES.get(username, {})
    return render_template_string("""
<!doctype html><html><head><title>Profile — SecureWatch</title>
""" + SHARED_STYLES + """
</head><body>
<nav class="top-nav">
  <a href="/employee" class="nav-brand"><div class="shield-icon"><i class="bi bi-person-badge"></i></div>Employee Portal</a>
  <div class="nav-actions">
    <a href="/employee" class="btn-nav"><i class="bi bi-arrow-left"></i> Back</a>
    <a href="/logout"   class="btn-nav btn-nav-danger"><i class="bi bi-box-arrow-right"></i> Logout</a>
  </div>
</nav>
<div class="layout">
  <aside class="sidebar">
    <div class="sidebar-label">My Work</div>
    <a href="/employee"         class="sidebar-link"><i class="bi bi-kanban"></i> My Tasks</a>
    <a href="/employee/profile" class="sidebar-link active"><i class="bi bi-person"></i> My Profile</a>
    <div class="sidebar-label">Company</div>
    <a href="/employee/notices" class="sidebar-link"><i class="bi bi-megaphone"></i> Notices</a>
  </aside>
  <main class="main-content">
    <div class="page-header"><h1><i class="bi bi-person-circle" style="color:var(--accent);margin-right:8px;"></i>My Profile</h1></div>
    <div class="card" style="max-width:480px;">
      <div class="card-body-custom">
        <div style="display:flex;align-items:center;gap:16px;margin-bottom:24px;">
          <div style="width:64px;height:64px;border-radius:50%;background:linear-gradient(135deg,var(--accent),var(--accent-2));display:flex;align-items:center;justify-content:center;font-size:28px;color:white;font-weight:700;">
            {{emp.get('name','?')[0]}}
          </div>
          <div>
            <div style="font-size:18px;font-weight:700;">{{emp.get('name',username)}}</div>
            <div class="text-muted">{{emp.get('department','')}}</div>
          </div>
        </div>
        <div style="display:grid;gap:14px;">
          <div><div class="form-label">Employee ID</div><div class="font-mono" style="font-size:14px;color:var(--text-primary);">{{username}}</div></div>
          <div><div class="form-label">Email</div><div style="font-size:14px;color:var(--text-primary);">{{emp.get('email','—')}}</div></div>
          <div><div class="form-label">Department</div><div style="font-size:14px;color:var(--text-primary);">{{emp.get('department','—')}}</div></div>
        </div>
      </div>
    </div>
  </main>
</div>
</body></html>
""", emp=emp, username=username)


@app.route("/employee/notices")
@require_role("employee")
def employee_notices():
    return render_template_string("""
<!doctype html><html><head><title>Notices — SecureWatch</title>
""" + SHARED_STYLES + """
</head><body>
<nav class="top-nav">
  <a href="/employee" class="nav-brand"><div class="shield-icon"><i class="bi bi-person-badge"></i></div>Employee Portal</a>
  <div class="nav-actions">
    <a href="/employee" class="btn-nav"><i class="bi bi-arrow-left"></i> Back</a>
    <a href="/logout"   class="btn-nav btn-nav-danger"><i class="bi bi-box-arrow-right"></i> Logout</a>
  </div>
</nav>
<div class="layout">
  <aside class="sidebar">
    <div class="sidebar-label">My Work</div>
    <a href="/employee"         class="sidebar-link"><i class="bi bi-kanban"></i> My Tasks</a>
    <a href="/employee/profile" class="sidebar-link"><i class="bi bi-person"></i> My Profile</a>
    <div class="sidebar-label">Company</div>
    <a href="/employee/notices" class="sidebar-link active"><i class="bi bi-megaphone"></i> Notices</a>
  </aside>
  <main class="main-content">
    <div class="page-header">
      <h1><i class="bi bi-megaphone" style="color:var(--accent);margin-right:8px;"></i>Company Notices</h1>
      <p>Important updates from administration</p>
    </div>
    <div style="display:flex;flex-direction:column;gap:14px;max-width:680px;">
      <div class="card"><div class="card-body-custom">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
          <span class="badge-status badge-high"><i class="bi bi-pin-angle"></i> Important</span>
          <span class="text-xs text-muted">June 10, 2025</span>
        </div>
        <div style="font-weight:600;margin-bottom:6px;">Security Policy Update</div>
        <div class="text-sm text-muted">All employees are reminded that USB devices require prior approval from IT. Unauthorized USB usage will be flagged in the monitoring system.</div>
      </div></div>
      <div class="card"><div class="card-body-custom">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
          <span class="badge-status badge-low"><i class="bi bi-info-circle"></i> General</span>
          <span class="text-xs text-muted">June 8, 2025</span>
        </div>
        <div style="font-weight:600;margin-bottom:6px;">System Maintenance Window</div>
        <div class="text-sm text-muted">Scheduled maintenance on June 15 from 2AM–4AM. Some monitoring features may be temporarily unavailable.</div>
      </div></div>
    </div>
  </main>
</div>
</body></html>
""")


# ═══════════════════════════════════════════════════════════
# ADMIN: TASK MANAGER
# ═══════════════════════════════════════════════════════════
@app.route("/employee_tasks", methods=["GET", "POST"])
@require_role("admin")
def employee_tasks():
    message = ""
    if request.method == "POST":
        task = {
            "title":       request.form.get("title"),
            "description": request.form.get("description", ""),
            "assigned_to": request.form.get("assigned_to"),
            "priority":    request.form.get("priority", "medium"),
            "due_date":    request.form.get("due_date", ""),
            "status":      "todo",
            "created_at":  datetime.now(),
        }
        tasks_collection.insert_one(task)
        audit("task_created", f"Assigned '{task['title']}' to {task['assigned_to']}")
        message = "Task assigned successfully."

    all_tasks = list(tasks_collection.find().sort("created_at", -1).limit(50))
    return render_template_string("""
<!doctype html><html><head><title>Task Manager — SecureWatch</title>
""" + SHARED_STYLES + """
</head><body>
<nav class="top-nav">
  <a href="/dashboard" class="nav-brand"><div class="shield-icon"><i class="bi bi-shield-check"></i></div>SecureWatch</a>
  <div class="nav-actions">
    <a href="/dashboard" class="btn-nav"><i class="bi bi-arrow-left"></i> Dashboard</a>
    <a href="/logout"    class="btn-nav btn-nav-danger"><i class="bi bi-box-arrow-right"></i> Logout</a>
  </div>
</nav>
<div class="layout">
  <aside class="sidebar">
    <div class="sidebar-label">Monitor</div>
    <a href="/dashboard" class="sidebar-link"><i class="bi bi-grid-1x2"></i> Dashboard</a>
    <div class="sidebar-label">System</div>
    <a href="/settings"      class="sidebar-link"><i class="bi bi-toggles"></i> Features</a>
    <a href="/employee_tasks" class="sidebar-link active"><i class="bi bi-list-check"></i> Task Manager</a>
  </aside>
  <main class="main-content">
    <div class="page-header">
      <h1><i class="bi bi-list-check" style="color:var(--accent);margin-right:8px;"></i>Task Manager</h1>
      <p>Assign and track tasks for employees</p>
    </div>
    {% if message %}
    <div style="background:rgba(16,185,129,0.1);border:1px solid rgba(16,185,129,0.2);color:var(--success);padding:12px 16px;border-radius:8px;margin-bottom:20px;font-size:13px;">
      <i class="bi bi-check-circle"></i> {{message}}
    </div>
    {% endif %}
    <div class="grid-2 mb-24">
      <div class="card">
        <div class="card-header-custom"><i class="bi bi-plus-circle" style="color:var(--accent);"></i> Assign New Task</div>
        <div class="card-body-custom">
          <form method="post">
            <div class="form-group"><label class="form-label">Task Title</label><input class="form-input" name="title" placeholder="e.g. Review security logs" required></div>
            <div class="form-group"><label class="form-label">Description</label><textarea class="form-input" name="description" rows="2" placeholder="Optional details..."></textarea></div>
            <div class="form-group">
              <label class="form-label">Assign To</label>
              <select class="form-input" name="assigned_to" required>
                <option value="">Select employee...</option>
                {% for emp_id, emp_info in employees.items() %}
                <option value="{{emp_id}}">{{emp_info.name}} ({{emp_id}})</option>
                {% endfor %}
              </select>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
              <div class="form-group"><label class="form-label">Priority</label>
                <select class="form-input" name="priority"><option value="low">Low</option><option value="medium" selected>Medium</option><option value="high">High</option></select>
              </div>
              <div class="form-group"><label class="form-label">Due Date</label><input class="form-input" name="due_date" type="date"></div>
            </div>
            <button type="submit" class="btn-primary-custom" style="width:100%;justify-content:center;padding:10px;"><i class="bi bi-send"></i> Assign Task</button>
          </form>
        </div>
      </div>
      <div>
        <div class="stat-card blue mb-16"><div class="stat-label">Total Tasks</div><div class="stat-value">{{all_tasks|length}}</div><i class="bi bi-list-check stat-icon"></i></div>
        <div class="stat-card green mb-16"><div class="stat-label">Completed</div><div class="stat-value">{{all_tasks|selectattr('status','equalto','done')|list|length}}</div><i class="bi bi-check-circle stat-icon"></i></div>
        <div class="stat-card yellow"><div class="stat-label">In Progress</div><div class="stat-value">{{all_tasks|selectattr('status','equalto','in_progress')|list|length}}</div><i class="bi bi-clock stat-icon"></i></div>
      </div>
    </div>
    <div class="card">
      <div class="card-header-custom"><i class="bi bi-table"></i> All Tasks</div>
      <div style="overflow-x:auto;">
        <table class="client-table">
          <thead><tr><th>Title</th><th>Assigned To</th><th>Priority</th><th>Status</th><th>Due</th><th>Action</th></tr></thead>
          <tbody>
            {% for t in all_tasks %}
            <tr>
              <td style="font-weight:500;">{{t.title}}</td>
              <td class="font-mono text-sm">{{t.assigned_to}}</td>
              <td><span class="text-xs task-priority-{{t.get('priority','low')}}"><i class="bi bi-flag"></i> {{t.get('priority','low').title()}}</span></td>
              <td>
                {% if t.status == 'done' %}<span class="badge-status badge-low"><i class="bi bi-check2"></i> Done</span>
                {% elif t.status == 'in_progress' %}<span class="badge-status badge-medium"><i class="bi bi-clock"></i> In Progress</span>
                {% else %}<span class="badge-status badge-offline"><i class="bi bi-circle"></i> To Do</span>{% endif %}
              </td>
              <td class="text-muted">{{t.get('due_date','—')}}</td>
              <td>
                <form method="post" action="/admin/delete_task/{{t._id}}" style="margin:0;" onsubmit="return confirm('Delete this task?');">
                  <button class="btn-danger-custom"><i class="bi bi-trash"></i></button>
                </form>
              </td>
            </tr>
            {% else %}
            <tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:40px;">No tasks yet.</td></tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    </div>
  </main>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body></html>
""", all_tasks=all_tasks, employees=EMPLOYEES, message=message)


@app.route("/admin/delete_task/<task_id>", methods=["POST"])
@require_role("admin")
def admin_delete_task(task_id):
    from bson import ObjectId
    tasks_collection.delete_one({"_id": ObjectId(task_id)})
    audit("task_deleted", f"Deleted task {task_id}")
    return redirect("/employee_tasks")


# ═══════════════════════════════════════════════════════════
# AI CHAT  (unchanged logic, audit added)
# ═══════════════════════════════════════════════════════════
@app.route("/ai_chat", methods=["POST"])
def ai_chat():
    if not session.get("logged_in"):
        return jsonify({"reply": "Unauthorized"}), 401

    user_msg = request.json.get("message", "").strip()
    if not user_msg:
        return jsonify({"reply": "Please ask a question."})

    total_clients = clients_collection.count_documents({})
    total_alerts  = alerts_collection.count_documents({})
    recent_alerts  = [a.get("message", "") for a in alerts_collection.find().sort("timestamp", -1).limit(5)]
    recent_activity = list(activity_log)[:10]

    client_summaries = []
    for c in clients_collection.find().limit(10):
        cid   = c.get("client_id", "unknown")
        score = risk_data.get(cid, 0)
        level, _ = get_risk_level(score)
        last_seen = c.get("last_seen", datetime.now())
        delta  = (datetime.now() - last_seen).seconds
        status = "Online" if delta < 15 else "Offline"
        client_summaries.append(f"{cid}: {status}, Risk={level}({score})")

    system_prompt = f"""You are an expert AI security analyst for a corporate employee monitoring system called SecureWatch.
You have access to the following live system data:

SYSTEM OVERVIEW:
- Total monitored clients: {total_clients}
- Total security alerts: {total_alerts}
- Active features: {', '.join(k for k,v in FEATURES.items() if v)}

CLIENT STATUS:
{chr(10).join(client_summaries) or 'No clients connected'}

RECENT ALERTS:
{chr(10).join(recent_alerts) or 'No recent alerts'}

RECENT ACTIVITY:
{chr(10).join(recent_activity) or 'No recent activity'}

Respond as a professional security analyst. Be concise and actionable.
If asked to investigate a specific client, analyze their risk score and recent events.
Provide security recommendations when appropriate.
Keep responses under 200 words unless a detailed analysis is requested."""

    session_key = session.get("username", "anon")
    if session_key not in ai_chat_history:
        ai_chat_history[session_key] = []
    ai_chat_history[session_key].append({"role": "user", "content": user_msg})
    history = ai_chat_history[session_key][-10:]

    try:
        ai_client = anthropic.Anthropic()
        response  = ai_client.messages.create(
            model="claude-sonnet-4-6", max_tokens=512,
            system=system_prompt, messages=history,
        )
        reply = response.content[0].text
        ai_chat_history[session_key].append({"role": "assistant", "content": reply})
        return jsonify({"reply": reply})
    except Exception as e:
        print("AI error:", e)
        reply = _rule_based_response(user_msg, total_clients, total_alerts, recent_alerts, client_summaries)
        return jsonify({"reply": reply})


def _rule_based_response(msg, total_clients, total_alerts, recent_alerts, client_summaries):
    msg = msg.lower()
    if "risk" in msg or "threat" in msg:
        high_risk = sum(1 for s in client_summaries if "HIGH" in s)
        return f"Current threat assessment: {high_risk} high-risk client(s) out of {total_clients}. Recommend reviewing their logs immediately."
    elif "alert" in msg:
        return f"There are {total_alerts} total recorded alerts. Recent: {'; '.join(recent_alerts[:3]) or 'None'}."
    elif "client" in msg or "machine" in msg:
        return f"Currently monitoring {total_clients} client(s). Status: {'; '.join(client_summaries[:3]) or 'None connected'}."
    elif "recommend" in msg or "suggest" in msg or "should" in msg:
        return "Recommendations: 1) Review all HIGH risk clients immediately. 2) Disable USB on sensitive workstations. 3) Update restricted apps list. 4) Enable screenshot capture for audit trails."
    else:
        return f"SecureWatch is monitoring {total_clients} client(s) with {total_alerts} total alerts. Ask me about risk levels, alerts, specific clients, or security recommendations."


# ═══════════════════════════════════════════════════════════
# DELETE / RECYCLE
# ═══════════════════════════════════════════════════════════
@app.route("/delete_client/<client>", methods=["POST"])
@require_role("admin")
def delete_client(client):
    if ".." in client or "/" in client:
        return "Invalid client"
    audit("client_deleted", f"Moved {client} to recycle bin")
    client_folder = os.path.join(SAVE_DIRECTORY, client)
    if os.path.exists(client_folder):
        try:
            timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
            destination = os.path.join(RECYCLE_DIRECTORY, f"{client}_{timestamp}")
            shutil.move(client_folder, destination)
        except Exception as e:
            return f"Error: {e}"
    return redirect("/dashboard")


# ═══════════════════════════════════════════════════════════
# LOGS / SCREENSHOTS  (unchanged, decorator added)
# ═══════════════════════════════════════════════════════════
@app.route("/view_logs/<client>")
@require_role("admin")
def view_logs(client):
    if ".." in client or "/" in client:
        return "Invalid client"
    logs_data = logs_collection.find({"client_id": client}).sort("timestamp", -1).limit(200)
    content = ""
    for log in logs_data:
        content += f"{log.get('timestamp','')} - {log.get('logs','')}\n"
    return render_template_string("""
<!doctype html><html><head><title>Logs — {{client}}</title>
""" + SHARED_STYLES + """
<script>
function filterLogs() {
  let q = document.getElementById('searchInput').value.toLowerCase();
  let lines = document.getElementById('rawContent').innerText.split('\\n');
  document.getElementById('filteredContent').innerText = lines.filter(l => l.toLowerCase().includes(q)).join('\\n');
}
</script>
</head><body>
<nav class="top-nav">
  <a href="/dashboard" class="nav-brand"><div class="shield-icon"><i class="bi bi-shield-check"></i></div>SecureWatch</a>
  <div class="nav-actions">
    <a href="/dashboard" class="btn-nav"><i class="bi bi-arrow-left"></i> Dashboard</a>
    <a href="/download_logs/{{client}}" class="btn-primary-custom"><i class="bi bi-download"></i> Export</a>
  </div>
</nav>
<main class="main-content" style="max-width:900px;margin:0 auto;">
  <div class="page-header">
    <h1 style="font-size:16px;"><i class="bi bi-file-earmark-text" style="color:var(--accent);"></i> Logs</h1>
    <p class="font-mono">{{client}}</p>
  </div>
  <div class="card">
    <div class="card-header-custom">
      <i class="bi bi-search"></i>
      <input id="searchInput" oninput="filterLogs()" style="background:var(--bg-base);border:1px solid var(--border);color:var(--text-primary);padding:5px 10px;border-radius:5px;font-size:12px;flex:1;" placeholder="Filter logs...">
    </div>
    <div class="card-body-custom" style="padding:0;">
      <pre id="rawContent" style="display:none;">{{content}}</pre>
      <pre id="filteredContent" style="background:transparent;color:#38bdf8;font-size:12px;font-family:var(--font-mono);padding:18px;max-height:70vh;overflow-y:auto;margin:0;white-space:pre-wrap;word-break:break-all;">{{content}}</pre>
    </div>
  </div>
</main>
</body></html>
""", client=client, content=content)


@app.route("/download_logs/<client>")
@require_role("admin")
def download_logs(client):
    if ".." in client or "/" in client:
        return "Invalid client"
    log_path = os.path.join(SAVE_DIRECTORY, client, "logs.txt")
    if not os.path.exists(log_path):
        return "No logs available"
    audit("log_download", f"Downloaded logs for {client}")
    return send_file(log_path, as_attachment=True)


from urllib.parse import quote, unquote

@app.route("/view_screenshots/<path:client>")
@require_role("admin")
def view_screenshots(client):
    if ".." in client:
        return "Invalid client"
    folder = os.path.join(SAVE_DIRECTORY, client)
    if not os.path.exists(folder):
        return "Client folder not found"
    images = sorted([f for f in os.listdir(folder) if f.lower().endswith(".png")], reverse=True)
    encoded_client = quote(client)
    return render_template_string("""
<!doctype html><html><head><title>Screenshots — {{client}}</title>
""" + SHARED_STYLES + """
</head><body>
<nav class="top-nav">
  <a href="/dashboard" class="nav-brand"><div class="shield-icon"><i class="bi bi-shield-check"></i></div>SecureWatch</a>
  <div class="nav-actions"><a href="/dashboard" class="btn-nav"><i class="bi bi-arrow-left"></i> Dashboard</a></div>
</nav>
<main class="main-content">
  <div class="page-header">
    <h1><i class="bi bi-images" style="color:var(--accent);margin-right:8px;"></i>Screenshots</h1>
    <p class="font-mono">{{client}} · {{images|length}} captures</p>
  </div>
  {% if images %}
  <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:16px;">
    {% for img in images %}
    <div class="card">
      <img src="/screenshots/{{encoded_client}}/{{img}}" style="width:100%;border-radius:10px 10px 0 0;" loading="lazy">
      <div style="padding:10px 14px;font-size:11px;color:var(--text-secondary);font-family:var(--font-mono);">{{img}}</div>
    </div>
    {% endfor %}
  </div>
  {% else %}
  <div style="text-align:center;color:var(--text-muted);padding:60px;">No screenshots captured yet.</div>
  {% endif %}
</main>
</body></html>
""", client=client, encoded_client=encoded_client, images=images)


@app.route("/screenshots/<path:client>/<filename>")
def serve_screenshot(client, filename):
    client   = unquote(client)
    filename = unquote(filename)
    if ".." in client or ".." in filename:
        return "Invalid path"
    folder = os.path.join(SAVE_DIRECTORY, client)
    if not os.path.exists(folder):
        return "Not found"
    return send_from_directory(folder, filename)


# ═══════════════════════════════════════════════════════════
# LOGOUT
# ═══════════════════════════════════════════════════════════
@app.route("/logout")
def logout():
    audit("logout", "User logged out")
    activity_log.clear()
    session.clear()
    return redirect("/")


# ═══════════════════════════════════════════════════════════
# SOCKET SERVER  (unchanged — adds _push_stats call)
# ═══════════════════════════════════════════════════════════
class MonitoringServer:
    def __init__(self, host="0.0.0.0", port=5000):
        self.server_host = host
        self.server_port = port
        self.client_names = {}

    def start_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind((self.server_host, self.server_port))
        server_socket.listen(5)
        print(f"Monitoring Server listening on {self.server_host}:{self.server_port}")
        while True:
            client_socket, client_address = server_socket.accept()
            try:
                identity_data = client_socket.recv(1024).decode("utf-8")
                identity  = json.loads(identity_data)
                hostname  = identity.get("hostname", "unknown")
                username  = identity.get("username", "unknown")
                client_id = f"{hostname}_{username}"
            except Exception:
                client_id = f"{client_address[0]}_{client_address[1]}"
            self.client_names[client_socket] = client_id
            thread = threading.Thread(
                target=self.handle_client, args=(client_socket, client_address), daemon=True
            )
            thread.start()

    def handle_client(self, client_socket, client_address):
        buffer    = ""
        client_id = self.client_names.get(client_socket, f"{client_address[0]}_{client_address[1]}")
        try:
            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                buffer += data.decode("utf-8")
                while "\nEND\n" in buffer:
                    message, buffer = buffer.split("\nEND\n", 1)
                    self.process_message(message, client_id)
        finally:
            client_socket.close()

    def process_message(self, message, client_id):
        try:
            data = json.loads(message)
            clients_collection.update_one(
                {"client_id": client_id},
                {"$set": {"last_seen": datetime.now(), "system_info": data.get("system_info", {})}},
                upsert=True,
            )
            log_text   = data.get("logs",  "").lower()
            event_text = data.get("event", "").lower()

            if "restricted application detected" in log_text:
                add_activity(f"{client_id} — Restricted Application Opened")
                update_risk(client_id, log_text)
                add_alert(f"{client_id}: Restricted Application Detected")

            if "usb inserted" in log_text or "usb inserted" in event_text:
                add_activity(f"{client_id} — USB Device Inserted")
                update_risk(client_id, "usb inserted")
                add_alert(f"{client_id}: USB Device Inserted")

            timestamp     = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            client_folder = os.path.join(SAVE_DIRECTORY, client_id)
            os.makedirs(client_folder, exist_ok=True)
            log_file = os.path.join(client_folder, "logs.txt")

            with open(log_file, "a", encoding="utf-8") as f:
                f.write(f"\n{'='*30}\nReceived at: {timestamp}\n\n")
                if "system_info" in data:
                    f.write("---- SYSTEM INFO ----\n")
                    for k, v in data["system_info"].items():
                        f.write(f"{k}: {v}\n")
                    f.write("\n")
                if "logs" in data:
                    f.write("---- LOGS ----\n")
                    f.write(data["logs"])
                    f.write("\n")
                    update_risk(client_id, data["logs"])

            if event_text:
                add_activity(f"{client_id} — {event_text}")
                update_risk(client_id, event_text)

            if FEATURES["screenshot_capture"] and data.get("screenshot"):
                screenshot_bytes = base64.b64decode(data["screenshot"])
                add_activity(f"{client_id} — Screenshot captured")
                screenshot_path = os.path.join(client_folder, f"screenshot_{timestamp}.png")
                with open(screenshot_path, "wb") as img:
                    img.write(screenshot_bytes)

            logs_collection.insert_one({
                "client_id": client_id,
                "timestamp": datetime.now(),
                "logs":      data.get("logs",  ""),
                "event":     data.get("event", ""),
            })

            # Push updated stats to all open dashboards
            _push_stats()

        except Exception as e:
            print("Processing error:", e)


# ═══════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════
if __name__ == "__main__":
    server = MonitoringServer()
    threading.Thread(target=server.start_server, daemon=True).start()
    time.sleep(1)
    webbrowser.open("http://127.0.0.1:8000")
    serve(app, host="0.0.0.0", port=8000, threads=12, connection_limit=300)
