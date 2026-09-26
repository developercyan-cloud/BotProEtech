import os
import hmac
import hashlib
import json
import sqlite3
import threading
import time
from urllib.parse import parse_qsl

from flask import Flask, jsonify, request, render_template
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes


# =========================================================
# CONFIGURACIÓN
# =========================================================

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
WEBAPP_URL = os.environ.get("WEBAPP_URL", "").strip()
ADMIN_KEY = os.environ.get("ADMIN_KEY", "").strip()

DATABASE = os.environ.get("DATABASE_PATH", "data.db")

if not BOT_TOKEN:
    raise RuntimeError("Missing TELEGRAM_BOT_TOKEN")

if not WEBAPP_URL:
    raise RuntimeError("Missing WEBAPP_URL")


# =========================================================
# FLASK
# =========================================================

app = Flask(__name__)


# =========================================================
# BASE DE DATOS
# =========================================================

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute(
        """
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
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    conn.commit()
    conn.close()


# =========================================================
# VALIDACIÓN DE TELEGRAM MINI APP
# =========================================================

def validate_telegram_init_data(init_data: str) -> bool:
    """
    Valida Telegram WebApp initData utilizando el token del bot.
    """

    if not init_data:
        return False

    try:
        parsed = dict(parse_qsl(init_data, keep_blank_values=True))

        received_hash = parsed.pop("hash", None)

        if not received_hash:
            return False

        data_check_string = "\n".join(
            f"{key}={parsed[key]}"
            for key in sorted(parsed.keys())
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

        if not hmac.compare_digest(
            calculated_hash,
            received_hash
        ):
            return False

        # Validar antigüedad de auth_date
        auth_date = parsed.get("auth_date")

        if auth_date:
            try:
                auth_timestamp = int(auth_date)

                # 24 horas
                if time.time() - auth_timestamp > 86400:
                    return False

            except ValueError:
                return False

        return True

    except Exception:
        return False


# =========================================================
# TELEGRAM
# =========================================================

async def start(update, context: ContextTypes.DEFAULT_TYPE):

    keyboard = [
        [
            InlineKeyboardButton(
                "🚀 Open Account Setup",
                web_app=WebAppInfo(url=WEBAPP_URL)
            )
        ]
    ]

    reply_markup = InlineKeyboardMarkup(keyboard)

    await update.message.reply_text(
        "Welcome.\n\n"
        "Use the button below to start the account setup process.",
        reply_markup=reply_markup
    )


async def help_cmd(update, context: ContextTypes.DEFAULT_TYPE):

    await update.message.reply_text(
        "Use /start to open the account setup assistant."
    )


# =========================================================
# API / WEB
# =========================================================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify({
        "status": "ok"
    })


@app.route("/api/register", methods=["POST"])
def register():

    data = request.get_json(silent=True) or {}

    # -----------------------------------------------------
    # Validar Telegram WebApp
    # -----------------------------------------------------

    init_data = request.headers.get("X-Telegram-Init-Data", "")

    if not validate_telegram_init_data(init_data):
        return jsonify({
            "ok": False,
            "error": "Invalid Telegram authentication"
        }), 401

    # -----------------------------------------------------
    # Datos enviados por el formulario
    # -----------------------------------------------------

    service = str(data.get("service", "")).strip()
    first_name = str(data.get("first_name", "")).strip()
    last_name = str(data.get("last_name", "")).strip()
    email = str(data.get("email", "")).strip()
    phone = str(data.get("phone", "")).strip()
    city = str(data.get("city", "")).strip()

    allowed_services = {
        "uber",
        "doordash",
        "lyft"
    }

    if service.lower() not in allowed_services:
        return jsonify({
            "ok": False,
            "error": "Invalid service"
        }), 400

    if not first_name:
        return jsonify({
            "ok": False,
            "error": "First name is required"
        }), 400

    if not last_name:
        return jsonify({
            "ok": False,
            "error": "Last name is required"
        }), 400

    if not email:
        return jsonify({
            "ok": False,
            "error": "Email is required"
        }), 400

    if not phone:
        return jsonify({
            "ok": False,
            "error": "Phone is required"
        }), 400

    if not city:
        return jsonify({
            "ok": False,
            "error": "City is required"
        }), 400

    # -----------------------------------------------------
    # Obtener información del usuario de Telegram
    # -----------------------------------------------------

    parsed = dict(
        parse_qsl(
            init_data,
            keep_blank_values=True
        )
    )

    telegram_user_id = ""
    telegram_username = ""

    user_json = parsed.get("user")

    if user_json:
        try:
            telegram_user = json.loads(user_json)

            telegram_user_id = str(
                telegram_user.get("id", "")
            )

            telegram_username = str(
                telegram_user.get("username", "")
            )

        except Exception:
            pass

    # -----------------------------------------------------
    # Guardar registro
    # -----------------------------------------------------

    conn = get_db()

    cursor = conn.execute(
        """
        INSERT INTO registrations (
            telegram_user_id,
            telegram_username,
            service,
            first_name,
            last_name,
            email,
            phone,
            city
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            telegram_user_id,
            telegram_username,
            service.lower(),
            first_name,
            last_name,
            email,
            phone,
            city
        )
    )

    registration_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return jsonify({
        "ok": True,
        "registration_id": registration_id,
        "message": "Registration information received successfully."
    })


# =========================================================
# ADMINISTRACIÓN
# =========================================================

@app.route("/api/registrations", methods=["GET"])
def registrations():

    if not ADMIN_KEY:
        return jsonify({
            "ok": False,
            "error": "Admin endpoint is not configured"
        }), 403

    provided_key = request.headers.get(
        "X-Admin-Key",
        ""
    )

    if not hmac.compare_digest(
        provided_key,
        ADMIN_KEY
    ):
        return jsonify({
            "ok": False,
            "error": "Unauthorized"
        }), 401

    conn = get_db()

    rows = conn.execute(
        """
        SELECT
            id,
            telegram_user_id,
            telegram_username,
            service,
            first_name,
            last_name,
            email,
            phone,
            city,
            created_at
        FROM registrations
        ORDER BY id DESC
        """
    ).fetchall()

    conn.close()

    registrations_list = [
        dict(row)
        for row in rows
    ]

    return jsonify({
        "ok": True,
        "count": len(registrations_list),
        "registrations": registrations_list
    })


# =========================================================
# SERVIDOR FLASK
# =========================================================

def run_web():

    port = int(
        os.environ.get(
            "PORT",
            "8080"
        )
    )

    print(
        f"Flask running on port {port}"
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False,
        use_reloader=False
    )


# =========================================================
# BOT DE TELEGRAM
# =========================================================

def run_bot():

    application = (
        ApplicationBuilder()
        .token(BOT_TOKEN)
        .build()
    )

    application.add_handler(
        CommandHandler(
            "start",
            start
        )
    )

    application.add_handler(
        CommandHandler(
            "help",
            help_cmd
        )
    )

    print(
        "Bot en funcionamiento..."
    )

    application.run_polling(
        close_loop=False
    )


# =========================================================
# ARRANQUE
# =========================================================

if __name__ == "__main__":

    init_db()

    # Flask se ejecuta en segundo plano.
    web_thread = threading.Thread(
        target=run_web,
        daemon=True
    )

    web_thread.start()

    # Telegram se ejecuta en el hilo principal.
    # Esto evita el error:
    # set_wakeup_fd only works in main thread
    run_bot()
