import os
import re
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

import cv2
import numpy as np
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo, Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
WEBAPP_URL = os.environ.get("WEBAPP_URL", "").strip()
ADMIN_KEY = os.environ.get("ADMIN_KEY", "").strip()
ACCESS_CODE = os.environ.get("ACCESS_CODE", "").strip()
ACCESS_TOKEN_SECRET = os.environ.get("ACCESS_TOKEN_SECRET", "").strip() or (BOT_TOKEN + ":" + ACCESS_CODE)
DATABASE = os.environ.get("DATABASE_PATH", "data.db")
PORT = int(os.environ.get("PORT", "8080"))
MAX_BODY = int(os.environ.get("MAX_BODY_BYTES", str(12 * 1024 * 1024)))

if not BOT_TOKEN:
    raise RuntimeError("Missing TELEGRAM_BOT_TOKEN")
if not ACCESS_CODE:
    raise RuntimeError("Missing ACCESS_CODE: configure a private access code in Railway variables.")
if not WEBAPP_URL.startswith(("https://", "http://")):
    raise RuntimeError("WEBAPP_URL must include https://")

app = Flask(__name__, template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY

_db_lock = threading.Lock()
_rate_lock = threading.Lock()
_rate = {}

SERVICES = {"uber", "doordash", "lyft", "amazon", "grubhub"}

US_STATES = {
    "AL","AK","AZ","AR","CA","CO","CT","DE","FL","GA","HI","ID","IL","IN",
    "IA","KS","KY","LA","ME","MD","MA","MI","MN","MS","MO","MT","NE","NV",
    "NH","NJ","NM","NY","NC","ND","OH","OK","OR","PA","RI","SC","SD","TN",
    "TX","UT","VT","VA","WA","WV","WI","WY","DC"
}

NAME_RE = re.compile(r"^[A-Za-zÀ-ÖØ-öø-ÿ][A-Za-zÀ-ÖØ-öø-ÿ' -]{1,39}$")
CITY_RE = re.compile(r"^[A-Za-zÀ-ÖØ-öø-ÿ][A-Za-zÀ-ÖØ-öø-ÿ' .-]{1,49}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]{2,}$")

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
            telegram_user_id TEXT NOT NULL,
            telegram_username TEXT,
            service TEXT NOT NULL,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            country TEXT NOT NULL,
            state TEXT NOT NULL,
            city TEXT NOT NULL,
            face_check TEXT NOT NULL DEFAULT 'not_checked',
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
    salt = ADMIN_KEY or BOT_TOKEN
    return hashlib.sha256((ip + salt).encode()).hexdigest()[:20]

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


def issue_access_token():
    issued = str(int(time.time()))
    sig = hmac.new(ACCESS_TOKEN_SECRET.encode(), ("nexus-access:" + issued).encode(), hashlib.sha256).hexdigest()
    return issued + "." + sig

def valid_access_token(token):
    try:
        issued, sig = token.split(".", 1)
        issued_int = int(issued)
        age = time.time() - issued_int
        if age < -60 or age > 4 * 60 * 60:
            return False
        expected = hmac.new(ACCESS_TOKEN_SECRET.encode(), ("nexus-access:" + issued).encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig)
    except Exception:
        return False

def has_access():
    return valid_access_token(request.headers.get("X-Nexus-Access-Token", ""))

def access_required_response():
    if not has_access():
        return jsonify({"error": "Se requiere un código de acceso válido para continuar."}), 401
    return None

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

def clean(value, max_len=120):
    if not isinstance(value, str):
        return ""
    return " ".join(value.strip().split())[:max_len]


def validation_engine(payload):
    """Server-side deterministic quality engine. It does not identify a person."""
    checks = {}
    checks["profile"] = bool(NAME_RE.fullmatch(payload["first_name"]) and NAME_RE.fullmatch(payload["last_name"]))
    checks["contact"] = bool(EMAIL_RE.fullmatch(payload["email"]) and len(re.sub(r"\D","",payload["phone"])) in (10,11))
    checks["location"] = payload["country"] == "United States" and payload["state"] in US_STATES and bool(CITY_RE.fullmatch(payload["city"]))
    checks["face"] = payload["face_check"] == "single_face_detected"
    checks["platform"] = payload["service"] in SERVICES
    checks["integrity"] = len({payload["first_name"].casefold(),payload["last_name"].casefold(),payload["email"].casefold(),payload["city"].casefold()}) == 4
    weights={"profile":20,"contact":20,"location":15,"face":20,"platform":10,"integrity":15}
    score=sum(weights[k] for k,v in checks.items() if v)
    return {"score":score,"checks":checks,"status":"ready" if score>=90 else "review"}

def validate_payload(data):
    if not isinstance(data, dict):
        return None, "Invalid JSON body"

    service = clean(data.get("service"), 20).lower()
    first = clean(data.get("first_name"), 40)
    last = clean(data.get("last_name"), 40)
    email = clean(data.get("email"), 120).lower()
    phone = clean(data.get("phone"), 30)
    country = clean(data.get("country"), 40)
    state = clean(data.get("state"), 2).upper()
    city = clean(data.get("city"), 50)
    face_check = clean(data.get("selfie_face_check"), 40).lower()

    if service not in SERVICES:
        return None, "Unsupported platform"
    if not NAME_RE.fullmatch(first):
        return None, "Invalid first name"
    if not NAME_RE.fullmatch(last):
        return None, "Invalid last name"
    if first.casefold() == last.casefold():
        return None, "First name and last name cannot be identical"
    if not EMAIL_RE.fullmatch(email):
        return None, "Invalid email"
    digits = re.sub(r"\D", "", phone)
    if len(digits) not in (10, 11):
        return None, "Invalid US phone number"
    if len(email) > 120:
        return None, "Email too long"
    if country != "United States":
        return None, "Country must be United States"
    if state not in US_STATES:
        return None, "Invalid US state"
    if not CITY_RE.fullmatch(city):
        return None, "Invalid city"
    if face_check != "single_face_detected":
        return None, "Face check not completed"

    return {
        "service": service,
        "first_name": first,
        "last_name": last,
        "email": email,
        "phone": phone,
        "country": country,
        "state": state,
        "city": city,
        "face_check": face_check
    }, None

async def send_webapp_button(update: Update, context: ContextTypes.DEFAULT_TYPE):
    token = issue_access_token()
    base = WEBAPP_URL.split("#", 1)[0]
    separator = "&" if "?" in base else "?"
    # Fragment is not sent to the web server; the Mini App consumes it once.
    launch_url = base + separator + "launch=telegram&nexus_access=" + token
    keyboard = [[InlineKeyboardButton(
        "🚀 Abrir NEXUS AI",
        web_app=WebAppInfo(url=launch_url)
    )]]
    await context.bot.send_message(
        chat_id=update.effective_chat.id,
        text="Acceso autorizado.\n\nPulsa el botón para abrir la plataforma.",
        reply_markup=InlineKeyboardMarkup(keyboard)
    )

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    context.user_data["access_attempts"] = 0
    context.user_data["access_granted"] = False
    await update.effective_message.reply_text(
        "🔐 NEXUS AI · ACCESO RESTRINGIDO\n\nIntroduce tu código de acceso para continuar. Sin un código válido no se habilitará la plataforma."
    )

async def verify_code_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    message = update.effective_message
    supplied = (message.text or "").strip()
    attempts = int(context.user_data.get("access_attempts", 0))
    if attempts >= 5:
        await message.reply_text("Demasiados intentos. Envía /start más tarde para volver a intentarlo.")
        return
    if not hmac.compare_digest(supplied, ACCESS_CODE):
        context.user_data["access_attempts"] = attempts + 1
        await message.reply_text("Código incorrecto. Inténtalo de nuevo.")
        try:
            await message.delete()
        except Exception:
            pass
        return
    context.user_data["access_granted"] = True
    context.user_data["access_attempts"] = 0
    try:
        await message.delete()
    except Exception:
        pass
    await send_webapp_button(update, context)



@app.post("/api/access")
def access_login():
    if not rate_limit("access-code", limit=8, window=300):
        return jsonify({"error": "Demasiados intentos. Espera unos minutos e inténtalo de nuevo."}), 429
    body = request.get_json(silent=True) or {}
    supplied = body.get("code", "")
    if not isinstance(supplied, str) or not hmac.compare_digest(supplied.strip(), ACCESS_CODE):
        return jsonify({"error": "Código incorrecto. Inténtalo de nuevo."}), 401
    return jsonify({"ok": True, "token": issue_access_token(), "expires_in": 14400})

@app.get("/api/access/verify")
def access_verify():
    if not has_access():
        return jsonify({"ok": False, "error": "El acceso expiró. Introduce el código nuevamente."}), 401
    return jsonify({"ok": True, "expires_in": 14400})

@app.get("/")
def index():
    return render_template("index.html")

@app.errorhandler(413)
def request_too_large(error):
    return jsonify({"error": "La imagen o solicitud supera el límite permitido. Usa una imagen de menos de 8 MB."}), 413

@app.get("/health")
def health():
    try:
        conn = db()
        conn.execute("SELECT 1").fetchone()
        conn.close()
        database = "ok"
    except Exception:
        database = "error"
    return jsonify({
        "ok": True,
        "service": "NEXUS AI",
        "version": "6.3",
        "database": database
    })

@app.get("/api/system")
def system():
    return jsonify({
        "ok": True,
        "version": "6.3",
        "services": sorted(SERVICES),
        "country_locked": "United States",
        "face_check": "single_face_detected"
    })

@app.post("/api/face-check")
def face_check():
    gate_response = access_required_response()
    if gate_response:
        return gate_response
    """Non-identifying face presence/framing check; image is processed in memory only."""
    if not rate_limit("face-check", limit=12, window=60):
        return jsonify({"error": "Too many face checks. Please wait a moment."}), 429
    init = request.headers.get("X-Telegram-Init-Data", "")
    ok, parsed = validate_init_data(init)
    if not ok:
        return jsonify({"error": "Invalid Telegram authentication"}), 401
    file = request.files.get("selfie")
    if not file:
        return jsonify({"error": "No selfie image was received."}), 400
    raw = file.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        return jsonify({"error": "The image exceeds the 8 MB limit."}), 413
    if not raw:
        return jsonify({"error": "The selfie image is empty."}), 400
    try:
        arr = np.frombuffer(raw, dtype=np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            return jsonify({"error": "The image could not be decoded."}), 400
        h, w = img.shape[:2]
        if w < 240 or h < 240:
            return jsonify({"ok": False, "count": 0, "message": "La imagen es demasiado pequeña. Usa una foto de al menos 240 × 240 px."})
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        cascade_path = os.path.join(os.path.dirname(__file__), "assets", "haarcascade_frontalface_default.xml")
        detector = cv2.CascadeClassifier(cascade_path)
        if detector.empty():
            return jsonify({"error": "The local face detector could not be initialized."}), 500
        faces = detector.detectMultiScale(gray, scaleFactor=1.08, minNeighbors=6, minSize=(55,55), flags=cv2.CASCADE_SCALE_IMAGE)
        count = len(faces)
        if count == 0:
            return jsonify({"ok": False, "count": 0, "message": "No se detectó una cara. Usa una selfie clara mirando hacia la cámara."})
        if count > 1:
            return jsonify({"ok": False, "count": count, "message": "Se detectaron varias caras. La selfie debe mostrar una sola persona."})
        x, y, fw, fh = [int(v) for v in faces[0]]
        area = (fw * fh) / float(w * h)
        if area < 0.04:
            return jsonify({"ok": False, "count": 1, "message": "La cara aparece demasiado lejos. Acércate a la cámara y toma otra foto."})
        return jsonify({"ok": True, "count": 1, "message": "Cara detectada correctamente.", "engine": "server_local_face_quality", "stored": False})
    except Exception as exc:
        app.logger.exception("Face analysis failed")
        return jsonify({"error": "No fue posible analizar la imagen.", "detail": str(exc)[:240]}), 500

@app.post("/api/register")
def register():
    gate_response = access_required_response()
    if gate_response:
        return gate_response
    if not rate_limit("register", 20, 60):
        return jsonify({"error": "Too many requests. Try again shortly."}), 429

    init_data = request.headers.get("X-Telegram-Init-Data", "")
    valid, parsed = validate_init_data(init_data)
    if not valid:
        return jsonify({"error": "Invalid Telegram authentication"}), 401

    telegram_id, username = telegram_user(parsed)
    if not telegram_id:
        return jsonify({"error": "Telegram user information unavailable"}), 401

    payload, error = validate_payload(request.get_json(silent=True) or {})
    if error:
        return jsonify({"error": error}), 400

    validation = validation_engine(payload)
    if validation["status"] != "ready":
        return jsonify({
            "error": "Server validation requires review",
            "validation": validation
        }), 422

    with _db_lock:
        conn = db()
        created = now()
        ref = passport()
        cur = conn.execute("""
            INSERT INTO registrations
            (telegram_user_id,telegram_username,service,first_name,last_name,email,phone,
             country,state,city,face_check,status,readiness,passport_ref,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            telegram_id, username, payload["service"], payload["first_name"],
            payload["last_name"], payload["email"], payload["phone"],
            payload["country"], payload["state"], payload["city"],
            payload["face_check"], "profile_received", validation["score"], ref, created, created
        ))
        reg_id = cur.lastrowid
        conn.commit()
        conn.close()

    add_event(reg_id, "profile_received", "Profile information received", "info")
    add_event(reg_id, "field_validation", "Server-side validation passed", "info")
    add_event(reg_id, "face_check", "Local single-face check reported as passed", "info",
              {"face_check": payload["face_check"]})
    add_event(reg_id, "validation_engine", "Server validation engine passed", "info",
              validation)

    return jsonify({
        "ok": True,
        "registration_id": reg_id,
        "passport_ref": ref,
        "status": "profile_received",
        "readiness": validation["score"]
    }), 201


@app.post("/api/validate")
def validate_api():
    gate_response = access_required_response()
    if gate_response:
        return gate_response
    if not rate_limit("validate", 30, 60):
        return jsonify({"error":"Too many requests"}), 429
    valid, parsed = validate_init_data(request.headers.get("X-Telegram-Init-Data",""))
    if not valid:
        return jsonify({"error":"Invalid Telegram authentication"}), 401
    payload, error = validate_payload(request.get_json(silent=True) or {})
    if error:
        return jsonify({"ok":False,"error":error}), 400
    return jsonify({"ok":True,"validation":validation_engine(payload)})

@app.get("/api/registrations/<int:reg_id>")
def get_registration(reg_id):
    gate_response = access_required_response()
    if gate_response:
        return gate_response
    valid, parsed = validate_init_data(request.headers.get("X-Telegram-Init-Data", ""))
    if not valid:
        return jsonify({"error": "Invalid Telegram authentication"}), 401
    telegram_id, _ = telegram_user(parsed)
    conn = db()
    row = conn.execute(
        "SELECT * FROM registrations WHERE id=? AND telegram_user_id=?",
        (reg_id, telegram_id)
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Registration not found"}), 404
    data = dict(row)
    data.pop("telegram_user_id", None)
    return jsonify({"ok": True, "registration": data})

@app.post("/api/registrations/<int:reg_id>/event")
def event(reg_id):
    gate_response = access_required_response()
    if gate_response:
        return gate_response
    if not rate_limit("event", 60, 60):
        return jsonify({"error": "Too many requests"}), 429
    valid, parsed = validate_init_data(request.headers.get("X-Telegram-Init-Data", ""))
    if not valid:
        return jsonify({"error": "Invalid Telegram authentication"}), 401
    telegram_id, _ = telegram_user(parsed)
    conn = db()
    row = conn.execute(
        "SELECT id FROM registrations WHERE id=? AND telegram_user_id=?",
        (reg_id, telegram_id)
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Registration not found"}), 404
    body = request.get_json(silent=True) or {}
    event_type = clean(body.get("event_type"), 40)
    message = clean(body.get("message"), 200)
    if not event_type or not message:
        return jsonify({"error": "Invalid event"}), 400
    add_event(reg_id, event_type, message)
    return jsonify({"ok": True})

@app.get("/api/registrations")
def admin_registrations():
    key = request.headers.get("X-Admin-Key", "")
    if not ADMIN_KEY or not hmac.compare_digest(key, ADMIN_KEY):
        return jsonify({"error": "Unauthorized"}), 401
    conn = db()
    rows = conn.execute("""
        SELECT id,service,first_name,last_name,email,phone,country,state,city,
               face_check,status,readiness,passport_ref,created_at,updated_at
        FROM registrations ORDER BY id DESC LIMIT 500
    """).fetchall()
    conn.close()
    return jsonify({"ok": True, "registrations": [dict(r) for r in rows]})

def run_web():
    app.run(host="0.0.0.0", port=PORT, threaded=True)

def run_bot():
    application = ApplicationBuilder().token(BOT_TOKEN).build()
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, verify_code_message))
    application.run_polling(close_loop=False)

if __name__ == "__main__":
    init_db()
    # Flask runs in the background; Telegram polling remains on the main thread.
    web_thread = threading.Thread(target=run_web, daemon=True)
    web_thread.start()
    run_bot()
