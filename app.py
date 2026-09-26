import os
import hmac
import hashlib
import json
import sqlite3
import threading
import time
import secrets
from datetime import datetime, timezone
from urllib.parse import parse_qsl

from flask import Flask, jsonify, request, render_template
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
WEBAPP_URL = os.environ.get("WEBAPP_URL", "").strip()
ADMIN_KEY = os.environ.get("ADMIN_KEY", "").strip()
DATABASE = os.environ.get("DATABASE_PATH", "data.db")
PORT = int(os.environ.get("PORT", "8080"))
MAX_BODY = int(os.environ.get("MAX_BODY_BYTES", "1048576"))

if not BOT_TOKEN:
    raise RuntimeError("Missing TELEGRAM_BOT_TOKEN")
if not WEBAPP_URL.startswith(("https://", "http://")):
    raise RuntimeError("WEBAPP_URL must include https://")

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY

_db_lock = threading.Lock()
_rate_lock = threading.Lock()
_rate = {}

SERVICES = {"uber", "doordash", "lyft"}

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def db():
    conn = sqlite3.connect(DATABASE, timeout=20)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with _db_lock:
        conn = db()
        conn.execute("""
        CREATE TABLE IF NOT EXISTS registrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_user_id TEXT,
            telegram_username TEXT,
            service TEXT NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            city TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'profile_received',
            readiness INTEGER NOT NULL DEFAULT 0,
            passport_ref TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS verification_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            registration_id INTEGER NOT NULL,
            event_type TEXT NOT NULL,
            message TEXT NOT NULL,
            severity TEXT NOT NULL DEFAULT 'info',
            metadata_json TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(registration_id) REFERENCES registrations(id)
        )""")
        conn.execute("""
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_type TEXT NOT NULL,
            ip_hash TEXT,
            user_agent TEXT,
            created_at TEXT NOT NULL
        )""")
        conn.commit()
        conn.close()

def passport():
    return "NXS-" + datetime.now(timezone.utc).strftime("%y%m%d") + "-" + secrets.token_hex(4).upper()

def validate_init_data(init_data):
    if not init_data:
        return False, {}
    try:
        parsed = dict(parse_qsl(init_data, keep_blank_values=True))
        received = parsed.pop("hash", None)
        if not received:
            return False, {}
        check = "\n".join(f"{k}={parsed[k]}" for k in sorted(parsed))
        secret = hmac.new(b"WebAppData", BOT_TOKEN.encode(), hashlib.sha256).digest()
        expected = hmac.new(secret, check.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, received):
            return False, {}
        auth = int(parsed.get("auth_date", "0"))
        if not auth or time.time() - auth > 86400:
            return False, {}
        return True, parsed
    except Exception:
        return False, {}

def telegram_user(parsed):
    try:
        u = json.loads(parsed.get("user", "{}"))
        return str(u.get("id", "")), str(u.get("username", ""))
    except Exception:
        return "", ""

def client_ip_hash():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
    return hashlib.sha256((ip + ADMIN_KEY).encode()).hexdigest()[:20]

def rate_limit(bucket, limit=30, window=60):
    key = f"{bucket}:{client_ip_hash()}"
    t = time.time()
    with _rate_lock:
        arr = [x for x in _rate.get(key, []) if t - x < window]
        if len(arr) >= limit:
            _rate[key] = arr
            return False
        arr.append(t)
        _rate[key] = arr
        return True

def add_event(reg_id, event_type, message, severity="info", metadata=None):
    with _db_lock:
        conn = db()
        conn.execute("""
          INSERT INTO verification_events
          (registration_id,event_type,message,severity,metadata_json,created_at)
          VALUES (?,?,?,?,?,?)
        """, (reg_id, event_type, message, severity,
              json.dumps(metadata or {}, separators=(",", ":")), now()))
        conn.commit()
        conn.close()

async def start(update, context: ContextTypes.DEFAULT_TYPE):
    kb = [[InlineKeyboardButton("🚀 Open NEXUS Verification",
                                web_app=WebAppInfo(url=WEBAPP_URL))]]
    await update.message.reply_text(
        "NEXUS AI\n\nOpen the verification preparation center below.",
        reply_markup=InlineKeyboardMarkup(kb)
    )

async def help_cmd(update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("Use /start to open NEXUS AI.")

@app.route("/")
def index():
    return render_template("index.html")

@app.get("/health")
def health():
    return jsonify({
        "ok": True,
        "service": "NEXUS AI",
        "version": "5.0",
        "time": now(),
        "database": os.path.exists(DATABASE)
    })

@app.get("/api/system")
def system():
    return jsonify({
        "ok": True,
        "engine": "NEXUS CORE",
        "version": "5.0",
        "modules": [
            "profile_engine",
            "consistency_engine",
            "document_quality",
            "security_layer",
            "verification_passport"
        ],
        "official_verification": "external_platform_required"
    })

@app.post("/api/register")
def register():
    if not rate_limit("register", 20, 60):
        return jsonify({"ok": False, "error": "Rate limit exceeded"}), 429

    init_data = request.headers.get("X-Telegram-Init-Data", "")
    valid, parsed = validate_init_data(init_data)
    if not valid:
        with _db_lock:
            conn = db()
            conn.execute("INSERT INTO security_events(event_type,ip_hash,user_agent,created_at) VALUES(?,?,?,?)",
                         ("invalid_telegram_auth", client_ip_hash(), request.headers.get("User-Agent","")[:300], now()))
            conn.commit(); conn.close()
        return jsonify({"ok": False, "error": "Invalid Telegram authentication"}), 401

    data = request.get_json(silent=True) or {}
    service = str(data.get("service", "")).strip().lower()
    fields = {k: str(data.get(k, "")).strip() for k in
              ("first_name","last_name","email","phone","city")}

    if service not in SERVICES:
        return jsonify({"ok": False, "error": "Invalid service"}), 400
    missing = [k for k,v in fields.items() if not v]
    if missing:
        return jsonify({"ok": False, "error": "Missing fields", "fields": missing}), 400

    email_ok = "@" in fields["email"] and "." in fields["email"].split("@")[-1]
    phone_digits = sum(c.isdigit() for c in fields["phone"])
    signals = len(missing) + (0 if email_ok else 1) + (0 if phone_digits >= 7 else 1)
    readiness = max(35, min(99, 86 - signals * 10))

    uid, username = telegram_user(parsed)
    ref = passport()
    stamp = now()

    with _db_lock:
        conn = db()
        cur = conn.execute("""
          INSERT INTO registrations
          (telegram_user_id,telegram_username,service,first_name,last_name,email,phone,city,
           status,readiness,passport_ref,created_at,updated_at)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (uid, username, service, fields["first_name"], fields["last_name"],
              fields["email"], fields["phone"], fields["city"],
              "consistency_review" if signals else "profile_ready",
              readiness, ref, stamp, stamp))
        reg_id = cur.lastrowid
        conn.commit(); conn.close()

    add_event(reg_id, "profile_created", "Profile received by NEXUS CORE.", "info",
              {"service": service})
    add_event(reg_id, "consistency_check",
              "Local structure and contact-format checks completed.",
              "warning" if signals else "success",
              {"signals": signals, "readiness": readiness})

    return jsonify({
        "ok": True,
        "registration_id": reg_id,
        "passport_ref": ref,
        "status": "consistency_review" if signals else "profile_ready",
        "readiness": readiness,
        "signals": signals
    })

@app.post("/api/registrations/<int:reg_id>/event")
def event(reg_id):
    if not rate_limit("event", 60, 60):
        return jsonify({"ok": False, "error": "Rate limit exceeded"}), 429
    init_data = request.headers.get("X-Telegram-Init-Data", "")
    valid, _ = validate_init_data(init_data)
    if not valid:
        return jsonify({"ok": False, "error": "Invalid Telegram authentication"}), 401

    data = request.get_json(silent=True) or {}
    allowed = {"profile_updated","consistency_completed","document_received",
               "document_quality_review","security_checked","ready_for_official_flow"}
    typ = str(data.get("event_type","")).strip()
    if typ not in allowed:
        return jsonify({"ok": False, "error": "Invalid event type"}), 400

    msg = str(data.get("message", "")).strip()[:300] or typ
    severity = str(data.get("severity","info")).strip()
    if severity not in {"info","success","warning"}:
        severity = "info"

    conn = db()
    exists = conn.execute("SELECT id FROM registrations WHERE id=?", (reg_id,)).fetchone()
    conn.close()
    if not exists:
        return jsonify({"ok": False, "error": "Registration not found"}), 404

    add_event(reg_id, typ, msg, severity, data.get("metadata", {}))
    if typ == "ready_for_official_flow":
        with _db_lock:
            conn = db()
            conn.execute("UPDATE registrations SET status=?,updated_at=? WHERE id=?",
                         ("ready_for_official_flow", now(), reg_id))
            conn.commit(); conn.close()
    return jsonify({"ok": True})

@app.get("/api/registrations/<int:reg_id>")
def registration(reg_id):
    init_data = request.headers.get("X-Telegram-Init-Data", "")
    valid, parsed = validate_init_data(init_data)
    if not valid:
        return jsonify({"ok": False, "error": "Invalid Telegram authentication"}), 401
    uid, _ = telegram_user(parsed)
    conn = db()
    row = conn.execute("""
      SELECT id,telegram_user_id,service,first_name,last_name,email,phone,city,status,
             readiness,passport_ref,created_at,updated_at
      FROM registrations WHERE id=?
    """,(reg_id,)).fetchone()
    if not row or (uid and row["telegram_user_id"] != uid):
        conn.close()
        return jsonify({"ok": False, "error": "Not found"}), 404
    events = conn.execute("""
      SELECT event_type,message,severity,created_at
      FROM verification_events WHERE registration_id=? ORDER BY id ASC
    """,(reg_id,)).fetchall()
    conn.close()
    return jsonify({"ok":True,"registration":dict(row),"events":[dict(x) for x in events]})

@app.get("/api/registrations")
def admin_registrations():
    if not ADMIN_KEY:
        return jsonify({"ok":False,"error":"Admin endpoint is not configured"}),403
    if not hmac.compare_digest(request.headers.get("X-Admin-Key",""), ADMIN_KEY):
        return jsonify({"ok":False,"error":"Unauthorized"}),401
    conn=db()
    rows=conn.execute("""
      SELECT id,service,first_name,last_name,email,phone,city,status,readiness,
             passport_ref,created_at,updated_at
      FROM registrations ORDER BY id DESC LIMIT 500
    """).fetchall()
    conn.close()
    return jsonify({"ok":True,"count":len(rows),"registrations":[dict(r) for r in rows]})

def run_web():
    app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False, threaded=True)

def run_bot():
    application = ApplicationBuilder().token(BOT_TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_cmd))
    print("NEXUS Telegram bot running")
    application.run_polling(close_loop=False)

if __name__ == "__main__":
    init_db()
    threading.Thread(target=run_web, daemon=True).start()
    run_bot()
