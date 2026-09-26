import os
import sqlite3
import threading
import asyncio
import hashlib
import hmac
import json
from urllib.parse import parse_qsl

from flask import Flask, request, jsonify, render_template
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
WEBAPP_URL = os.environ.get("WEBAPP_URL", "")
DB_PATH = os.environ.get("DB_PATH", "data.db")

if not BOT_TOKEN:
    raise RuntimeError("Missing TELEGRAM_BOT_TOKEN")
if not WEBAPP_URL:
    raise RuntimeError("Missing WEBAPP_URL")

app = Flask(__name__)

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS registrations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            telegram_id TEXT NOT NULL,
            username TEXT,
            service TEXT NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            city TEXT,
            status TEXT NOT NULL DEFAULT 'Information received',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def validate_webapp_data(init_data: str):
    """Validate Telegram Mini App initData using the bot token."""
    if not init_data:
        return None

    try:
        parsed = dict(parse_qsl(init_data, keep_blank_values=True))
        received_hash = parsed.pop("hash", None)
        if not received_hash:
            return None

        data_check_string = "\n".join(
            f"{k}={parsed[k]}" for k in sorted(parsed)
        )

        secret_key = hmac.new(
            b"WebAppData",
            BOT_TOKEN.encode(),
            hashlib.sha256
        ).digest()

        calculated_hash = hmac.new(
            secret_key,
            data_check_string.encode(),
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(calculated_hash, received_hash):
            return None

        user = json.loads(parsed.get("user", "{}"))
        return user
    except Exception:
        return None

@app.get("/")
def index():
    return render_template("index.html")

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/api/register")
def register():
    payload = request.get_json(silent=True) or {}

    user = validate_webapp_data(payload.get("initData", ""))
    if not user:
        return jsonify({"ok": False, "error": "Invalid Telegram session"}), 403

    service = str(payload.get("service", "")).strip()
    first_name = str(payload.get("first_name", "")).strip()
    last_name = str(payload.get("last_name", "")).strip()
    email = str(payload.get("email", "")).strip()
    phone = str(payload.get("phone", "")).strip()
    city = str(payload.get("city", "")).strip()

    allowed = {"Uber", "DoorDash", "Lyft"}
    if service not in allowed:
        return jsonify({"ok": False, "error": "Invalid service"}), 400

    if not all([first_name, last_name, email, phone]):
        return jsonify({"ok": False, "error": "Complete all required fields"}), 400

    conn = db()
    cur = conn.execute("""
        INSERT INTO registrations
        (telegram_id, username, service, first_name, last_name, email, phone, city)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        str(user.get("id")),
        user.get("username"),
        service, first_name, last_name, email, phone, city
    ))
    registration_id = cur.lastrowid
    conn.commit()
    conn.close()

    return jsonify({
        "ok": True,
        "registration_id": registration_id,
        "status": "Information received"
    })

@app.get("/api/registrations")
def registrations():
    # Protect this endpoint with an ADMIN_KEY in production.
    if request.headers.get("X-Admin-Key") != os.environ.get("ADMIN_KEY", ""):
        return jsonify({"ok": False}), 401

    conn = db()
    rows = [dict(r) for r in conn.execute(
        "SELECT id, telegram_id, username, service, first_name, last_name, email, phone, city, status, created_at "
        "FROM registrations ORDER BY id DESC LIMIT 100"
    )]
    conn.close()
    return jsonify(rows)

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [[
        InlineKeyboardButton(
            "🚀 Open Account Setup",
            web_app=WebAppInfo(url=WEBAPP_URL)
        )
    ]]
    await update.message.reply_text(
        "Welcome to Account Setup Assistant.\n\n"
        "Choose a service and complete the registration information "
        "inside Telegram. Final identity or eligibility verification "
        "must be completed through the service's official process.",
        reply_markup=InlineKeyboardMarkup(keyboard)
    )

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Use /start to open the account setup assistant."
    )

def run_bot():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    application = ApplicationBuilder().token(BOT_TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_cmd))
    application.run_polling(close_loop=False, stop_signals=None)

if __name__ == "__main__":
    init_db()
    threading.Thread(target=run_bot, daemon=True).start()

    port = int(os.environ.get("PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
