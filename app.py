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
from urllib.parse import parse_qsl, quote
from urllib.request import Request, urlopen
from io import BytesIO
from urllib.error import URLError, HTTPError
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.enums import TA_CENTER

from flask import Flask, jsonify, request, render_template, make_response

import cv2
import numpy as np
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, WebAppInfo, Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, ContextTypes, filters

def pdf_text(value):
    """Escape user/vehicle text before placing it inside ReportLab Paragraph markup."""
    from xml.sax.saxutils import escape
    return escape("" if value is None else str(value))

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
_vehicle_cache = {}
_vehicle_cache_lock = threading.Lock()

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
        conn.execute("""
        CREATE TABLE IF NOT EXISTS vehicle_details (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            registration_id INTEGER NOT NULL UNIQUE,
            address TEXT NOT NULL,
            city TEXT NOT NULL,
            zip_code TEXT NOT NULL,
            model_year INTEGER NOT NULL,
            make TEXT NOT NULL,
            model TEXT NOT NULL,
            vin TEXT NOT NULL,
            policy_last4 TEXT NOT NULL,
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL,
            validation_score INTEGER NOT NULL,
            validation_status TEXT NOT NULL,
            decoded_json TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(registration_id) REFERENCES registrations(id)
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

def normalize_vehicle_text(value):
    return re.sub(r"[^a-z0-9]", "", str(value or "").casefold())

VIN_TRANSLITERATION = {
    "A":1,"B":2,"C":3,"D":4,"E":5,"F":6,"G":7,"H":8,
    "J":1,"K":2,"L":3,"M":4,"N":5,"P":7,"R":9,
    "S":2,"T":3,"U":4,"V":5,"W":6,"X":7,"Y":8,"Z":9,
}
VIN_WEIGHTS = [8,7,6,5,4,3,2,10,0,9,8,7,6,5,4,3,2]


def vin_check_digit(vin):
    vin = vin.upper()
    if len(vin) != 17 or not re.fullmatch(r"[A-HJ-NPR-Z0-9]{17}", vin):
        return False, None
    # NHTSA's check-digit convention is applicable to North-American VINs.
    # Many European VINs (for example WMI starting with W) legitimately do not
    # use the same check-digit scheme. Treat those as inconclusive rather than
    # falsely rejecting an otherwise decodable VIN.
    if vin[0] not in "12345":
        return None, None
    total = 0
    for char, weight in zip(vin, VIN_WEIGHTS):
        value = int(char) if char.isdigit() else VIN_TRANSLITERATION.get(char)
        if value is None:
            return False, None
        total += value * weight
    remainder = total % 11
    expected = "X" if remainder == 10 else str(remainder)
    return vin[8] == expected, expected

def infer_vin_model_year(vin):
    """Return the plausible 2010-2026 model year encoded by VIN position 10."""
    code = vin[9].upper() if len(vin) >= 10 else ""
    cycles = {
        "A": [2010, 2040], "B": [2011, 2041], "C": [2012, 2042],
        "D": [2013, 2043], "E": [2014, 2044], "F": [2015, 2045],
        "G": [2016, 2046], "H": [2017, 2047], "J": [2018, 2048],
        "K": [2019, 2049], "L": [2020, 2050], "M": [2021, 2051],
        "N": [2022, 2052], "P": [2023, 2053], "R": [2024, 2054],
        "S": [2025, 2055], "T": [2026, 2056],
    }
    vals = cycles.get(code, [])
    return next((y for y in vals if 2010 <= y <= 2026), None)


def fetch_nhtsa_vin(vin, model_year):
    key = f"{vin}:{model_year}"
    now_ts = time.time()
    with _vehicle_cache_lock:
        cached = _vehicle_cache.get(key)
        if cached and now_ts - cached[0] < 900:
            return cached[1]
    url = f"https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValuesExtended/{quote(vin, safe='')}?format=json&modelyear={int(model_year)}"
    req = Request(url, headers={"User-Agent": "NEXUS-AI-Vehicle-Validation/10.2"})
    try:
        with urlopen(req, timeout=8) as resp:
            raw = resp.read(1024 * 1024)
        payload = json.loads(raw.decode("utf-8", errors="replace"))
        results = payload.get("Results") or []
        row = results[0] if results else {}
        decoded = {
            "vin": row.get("VIN") or vin,
            "manufacturer": clean(row.get("Manufacturer"), 160),
            "make": clean(row.get("Make"), 80),
            "model": clean(row.get("Model"), 100),
            "model_year": clean(row.get("ModelYear"), 4),
            "vehicle_type": clean(row.get("VehicleType"), 100),
            "body_class": clean(row.get("BodyClass"), 120),
            "plant_country": clean(row.get("PlantCountry"), 80),
            "error_code": clean(row.get("ErrorCode"), 80),
            "error_text": clean(row.get("ErrorText"), 240),
        }
        with _vehicle_cache_lock:
            _vehicle_cache[key] = (now_ts, decoded)
        return decoded
    except (URLError, HTTPError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
        raise RuntimeError("No fue posible consultar NHTSA vPIC en este momento.") from exc


def validate_vehicle_payload(data):
    if not isinstance(data, dict):
        return None, "Solicitud inválida."
    try:
        registration_id = int(data.get("registration_id"))
    except Exception:
        return None, "Registro principal inválido."
    address = clean(data.get("address"), 160)
    city = clean(data.get("city"), 50)
    zip_code = clean(data.get("zip"), 10)
    try:
        year = int(data.get("year"))
    except Exception:
        year = 0
    make = clean(data.get("make"), 80)
    model = clean(data.get("model"), 100)
    vin = clean(data.get("vin"), 17).upper()
    policy = clean(data.get("policy_number"), 80)
    start_date = clean(data.get("start_date"), 10)
    end_date = clean(data.get("end_date"), 10)
    if not address or not CITY_RE.fullmatch(city): return None, "Dirección o ciudad inválida."
    if not re.fullmatch(r"\d{5}(?:-\d{4})?", zip_code): return None, "Código postal inválido."
    if year < 2010 or year > 2026: return None, "El año debe estar entre 2010 y 2026."
    if not re.fullmatch(r"[A-HJ-NPR-Z0-9]{17}", vin): return None, "El VIN debe contener 17 caracteres válidos."
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._/-]{2,79}", make): return None, "Marca inválida."
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._/-]{1,99}", model): return None, "Modelo inválido."
    if not policy or not re.fullmatch(r"[A-Za-z0-9 ._/#-]{3,80}", policy): return None, "Número de póliza inválido."
    try:
        start = datetime.strptime(start_date, "%Y-%m-%d").date()
        end = datetime.strptime(end_date, "%Y-%m-%d").date()
    except ValueError:
        return None, "Las fechas de la póliza no son válidas."
    if end < start: return None, "La fecha de fin no puede ser anterior a la fecha de inicio."
    check_ok, expected = vin_check_digit(vin)
    return {
        "registration_id": registration_id, "address": address, "city": city, "zip": zip_code,
        "year": year, "make": make, "model": model, "vin": vin, "policy_number": policy,
        "start_date": start_date, "end_date": end_date, "check_digit": check_ok, "expected_check_digit": expected,
        "dates": True, "address_ok": True
    }, None


def vehicle_validation_engine(payload, decoded):
    make_in = normalize_vehicle_text(payload["make"])
    model_in = normalize_vehicle_text(payload["model"])
    make_dec = normalize_vehicle_text(decoded.get("make"))
    model_dec = normalize_vehicle_text(decoded.get("model"))
    year_dec_raw = decoded.get("model_year") or ""
    try: year_dec = int(year_dec_raw)
    except Exception: year_dec = None
    decode_available = bool(make_dec or model_dec or year_dec)
    make_match = None if not make_dec else (make_in == make_dec or make_in in make_dec or make_dec in make_in)
    model_match = None if not model_dec else (model_in == model_dec or model_in in model_dec or model_dec in model_in)
    year_match = None if year_dec is None else (payload["year"] == year_dec)
    check_ok = payload["check_digit"]
    checks = {
        "vin_format": True,
        "check_digit": check_ok,
        "nhtsa_decode": decode_available,
        "year_match": year_match,
        "make_match": make_match,
        "model_match": model_match,
        "dates": payload["dates"],
        "address": payload["address_ok"],
    }
    # A missing vPIC field is inconclusive, while an explicit mismatch is a hard failure.
    weights = {"vin_format":15,"check_digit":15,"nhtsa_decode":15,"year_match":15,"make_match":15,"model_match":15,"dates":5,"address":5}
    score = 0
    for k,w in weights.items():
        if checks[k] is True:
            score += w
        elif k == "check_digit" and checks[k] is None:
            # European/other non-North-American VINs may not use NHTSA's
            # check-digit convention. Treat this check as inconclusive, not as
            # a failure, so it cannot incorrectly block a valid decodable VIN.
            score += w
    critical_mismatch = any(checks[k] is False for k in ("check_digit","year_match","make_match","model_match"))
    api_missing = not decode_available
    status = "ready" if score >= 90 and not critical_mismatch and not api_missing else "review"
    findings=[]
    if check_ok is False: findings.append(f"El dígito de control del VIN no coincide; se esperaba {payload['expected_check_digit']}.")
    elif check_ok is None: findings.append("Dígito de control no concluyente para este tipo de VIN; se validará mediante la decodificación técnica.")
    if year_match is False: findings.append(f"El VIN indica año {year_dec}, pero ingresaste {payload['year']}.")
    if make_match is False: findings.append(f"La marca ingresada ({payload['make']}) no coincide con la decodificación ({decoded.get('make') or 'sin dato'}).")
    if model_match is False: findings.append(f"El modelo ingresado ({payload['model']}) no coincide con la decodificación ({decoded.get('model') or 'sin dato'}).")
    if api_missing: findings.append("NHTSA vPIC no devolvió datos técnicos concluyentes; vuelve a intentarlo.")
    if not findings and status == "ready": findings.append("Todos los controles técnicos principales superaron el umbral.")
    return {"score": score, "checks": checks, "status": status, "findings": findings, "decoded": decoded}


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
        "version": "9.0",
        "database": database
    })

@app.get("/api/system")
def system():
    return jsonify({
        "ok": True,
        "version": "9.0",
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


@app.post("/api/vehicle/decode")
def vehicle_decode():
    """Decode a VIN as the user types; does not create or persist a vehicle record."""
    gate_response = access_required_response()
    if gate_response:
        return gate_response
    if not rate_limit("vehicle-decode", 12, 60):
        return jsonify({"error":"Demasiadas consultas de VIN. Espera un momento."}), 429
    valid, parsed = validate_init_data(request.headers.get("X-Telegram-Init-Data", ""))
    if not valid:
        return jsonify({"error":"Invalid Telegram authentication"}), 401
    body = request.get_json(silent=True) or {}
    vin = clean(body.get("vin"), 17).upper()
    if not re.fullmatch(r"[A-HJ-NPR-Z0-9]{17}", vin):
        return jsonify({"error":"VIN incompleto o con caracteres no permitidos."}), 400
    check_ok, expected = vin_check_digit(vin)
    if not check_ok:
        return jsonify({"ok":False,"valid":False,"check_digit":False,"expected_check_digit":expected,"error":"El dígito de control del VIN no coincide."}), 422
    key = f"autofill:{vin}"
    now_ts = time.time()
    with _vehicle_cache_lock:
        cached = _vehicle_cache.get(key)
        if cached and now_ts - cached[0] < 900:
            decoded = cached[1]
        else:
            decoded = None
    if decoded is None:
        inferred_year = infer_vin_model_year(vin)
        year_param = f"&modelyear={inferred_year}" if inferred_year else ""
        url = f"https://vpic.nhtsa.dot.gov/api/vehicles/DecodeVinValuesExtended/{quote(vin, safe='')}?format=json{year_param}"
        req = Request(url, headers={"User-Agent":"NEXUS-AI-Vehicle-Validation/10.2"})
        try:
            with urlopen(req, timeout=8) as resp:
                raw = resp.read(1024 * 1024)
            data = json.loads(raw.decode("utf-8", errors="replace"))
            row = (data.get("Results") or [{}])[0]
            decoded = {
                "vin": row.get("VIN") or vin,
                "manufacturer": clean(row.get("Manufacturer"), 160),
                "make": clean(row.get("Make"), 80),
                "model": clean(row.get("Model"), 100),
                "model_year": str(inferred_year or clean(row.get("ModelYear"), 4) or ""),
                "vehicle_type": clean(row.get("VehicleType"), 100),
                "body_class": clean(row.get("BodyClass"), 120),
                "plant_country": clean(row.get("PlantCountry"), 80),
                "error_code": clean(row.get("ErrorCode"), 80),
                "error_text": clean(row.get("ErrorText"), 240),
            }
            with _vehicle_cache_lock:
                _vehicle_cache[key] = (now_ts, decoded)
        except (URLError, HTTPError, TimeoutError, ValueError, json.JSONDecodeError) as exc:
            return jsonify({"error":"No fue posible consultar NHTSA vPIC en este momento."}), 503
    if not decoded.get("make") and not decoded.get("model") and not decoded.get("model_year"):
        return jsonify({"ok":False,"valid":True,"check_digit":True,"decoded":decoded,"error":"El VIN es estructuralmente válido, pero NHTSA no devolvió datos suficientes para autocompletar."}), 422
    return jsonify({
        "ok":True,"valid":True,"check_digit":True,
        "decoded":decoded,
        "source":"NHTSA vPIC"
    })


@app.post("/api/vehicle/validate")
def vehicle_validate():
    gate_response = access_required_response()
    if gate_response:
        return gate_response
    if not rate_limit("vehicle-validate", 10, 60):
        return jsonify({"error":"Demasiadas validaciones de vehículo. Espera un momento."}), 429
    valid, parsed = validate_init_data(request.headers.get("X-Telegram-Init-Data", ""))
    if not valid:
        return jsonify({"error":"Invalid Telegram authentication"}), 401
    telegram_id, _ = telegram_user(parsed)
    payload, error = validate_vehicle_payload(request.get_json(silent=True) or {})
    if error:
        return jsonify({"error":error}), 400
    conn=db()
    row=conn.execute("SELECT id FROM registrations WHERE id=? AND telegram_user_id=?",(payload["registration_id"],telegram_id)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error":"Registro no encontrado o no pertenece a esta sesión."}),404
    try:
        decode_year = infer_vin_model_year(payload["vin"]) or payload["year"]
        decoded=fetch_nhtsa_vin(payload["vin"], decode_year)
        # Some VINs decode to an older cycle (for example J -> 1988) when no
        # model year is supplied. Prefer the plausible 2010-2026 cycle when it
        # exists so the UI and validation do not report a false 30-year mismatch.
        if infer_vin_model_year(payload["vin"]):
            decoded["model_year"] = str(infer_vin_model_year(payload["vin"]))
    except RuntimeError as exc:
        return jsonify({"error":str(exc),"validation":{"status":"review","score":0,"checks":{},"findings":[str(exc)]}}),503
    validation=vehicle_validation_engine(payload,decoded)
    if validation["status"]!="ready":
        return jsonify({"ok":True,"validation":validation}),422
    policy_last4=payload["policy_number"][-4:]
    with _db_lock:
        conn=db()
        ts=now()
        conn.execute("""INSERT INTO vehicle_details
          (registration_id,address,city,zip_code,model_year,make,model,vin,policy_last4,start_date,end_date,validation_score,validation_status,decoded_json,created_at,updated_at)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
          ON CONFLICT(registration_id) DO UPDATE SET address=excluded.address,city=excluded.city,zip_code=excluded.zip_code,model_year=excluded.model_year,make=excluded.make,model=excluded.model,vin=excluded.vin,policy_last4=excluded.policy_last4,start_date=excluded.start_date,end_date=excluded.end_date,validation_score=excluded.validation_score,validation_status=excluded.validation_status,decoded_json=excluded.decoded_json,updated_at=excluded.updated_at""",
          (payload["registration_id"],payload["address"],payload["city"],payload["zip"],payload["year"],payload["make"],payload["model"],payload["vin"],policy_last4,payload["start_date"],payload["end_date"],validation["score"],validation["status"],json.dumps(decoded,separators=(",",":")),ts,ts))
        conn.execute("UPDATE registrations SET status=?,readiness=?,updated_at=? WHERE id=?",("vehicle_validated",max(100,int(validation["score"])),ts,payload["registration_id"]))
        conn.commit();conn.close()
    add_event(payload["registration_id"],"vehicle_validation","Vehicle validation passed", "info", {"score":validation["score"],"vin_last6":payload["vin"][-6:],"nhtsa":True})
    return jsonify({"ok":True,"validation":validation}),200


@app.post("/api/vehicle/document")
def vehicle_document():
    """Generate a non-official vehicle registration summary PDF from the validated record."""
    gate_response = access_required_response()
    if gate_response:
        return gate_response
    if not rate_limit("vehicle-document", 10, 60):
        return jsonify({"error": "Demasiadas solicitudes de documento. Espera un momento."}), 429
    valid, parsed = validate_init_data(request.headers.get("X-Telegram-Init-Data", ""))
    if not valid:
        return jsonify({"error": "Invalid Telegram authentication"}), 401
    telegram_id, _ = telegram_user(parsed)
    body = request.get_json(silent=True) or {}
    try:
        registration_id = int(body.get("registration_id"))
    except Exception:
        return jsonify({"error": "Registro inválido."}), 400

    conn = db()
    row = conn.execute("""SELECT r.id,r.telegram_user_id,r.service,r.first_name,r.last_name,r.email,r.phone,r.country,r.state,r.city,r.passport_ref,r.created_at,
                                v.address,v.city AS vehicle_city,v.zip_code,v.model_year,v.make,v.model,v.vin,v.policy_last4,v.start_date,v.end_date,v.validation_score,v.validation_status,v.decoded_json
                         FROM registrations r JOIN vehicle_details v ON v.registration_id=r.id
                         WHERE r.id=? AND r.telegram_user_id=? AND v.validation_status='ready'""", (registration_id, telegram_id)).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "No existe un vehículo validado para este registro."}), 404

    data = dict(row)
    try:
        decoded = json.loads(data.get("decoded_json") or "{}")
    except Exception:
        decoded = {}

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=letter, rightMargin=42, leftMargin=42, topMargin=42, bottomMargin=42, title="NEXUS AI - Registro de vehículo", author="NEXUS AI")
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="NXTitle", parent=styles["Title"], fontName="Helvetica-Bold", fontSize=20, leading=24, textColor=colors.HexColor("#4c2ca8"), alignment=TA_CENTER, spaceAfter=6))
    styles.add(ParagraphStyle(name="NXSub", parent=styles["Normal"], fontSize=9, leading=13, textColor=colors.HexColor("#667085"), alignment=TA_CENTER, spaceAfter=18))
    styles.add(ParagraphStyle(name="NXSection", parent=styles["Heading2"], fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=colors.HexColor("#302060"), spaceBefore=10, spaceAfter=7))
    styles.add(ParagraphStyle(name="NXSmall", parent=styles["Normal"], fontSize=8, leading=11, textColor=colors.HexColor("#667085")))

    story=[]
    story.append(Paragraph("NEXUS AI", styles["NXTitle"]))
    story.append(Paragraph("REGISTRO DE VEHÍCULO", styles["Heading1"]))
    story.append(Paragraph("Documento informativo generado a partir de los datos proporcionados y de la validación técnica realizada. No es un documento oficial de una aseguradora, DMV ni de la plataforma seleccionada.", styles["NXSub"]))

    def table(rows):
        t=Table(rows, colWidths=[1.75*inch, 4.6*inch], hAlign="LEFT")
        t.setStyle(TableStyle([
            ("BACKGROUND",(0,0),(0,-1),colors.HexColor("#f1eff9")),
            ("TEXTCOLOR",(0,0),(0,-1),colors.HexColor("#40346b")),
            ("TEXTCOLOR",(1,0),(1,-1),colors.HexColor("#20232b")),
            ("FONTNAME",(0,0),(0,-1),"Helvetica-Bold"),
            ("FONTNAME",(1,0),(1,-1),"Helvetica"),
            ("FONTSIZE",(0,0),(-1,-1),9),
            ("GRID",(0,0),(-1,-1),0.35,colors.HexColor("#d9d5e7")),
            ("VALIGN",(0,0),(-1,-1),"TOP"),
            ("LEFTPADDING",(0,0),(-1,-1),8), ("RIGHTPADDING",(0,0),(-1,-1),8),
            ("TOPPADDING",(0,0),(-1,-1),7), ("BOTTOMPADDING",(0,0),(-1,-1),7),
        ]))
        return t

    story.append(Paragraph("Datos del registro", styles["NXSection"]))
    story.append(table([
        ["Referencia", data["passport_ref"]], ["Plataforma", data["service"].title()],
        ["Nombre", f'{data["first_name"]} {data["last_name"]}'], ["Correo", data["email"]],
        ["Teléfono", data["phone"]], ["Estado", data["state"]], ["Ciudad", data["city"]]
    ]))

    story.append(Paragraph("Datos del vehículo", styles["NXSection"]))
    story.append(table([
        ["Dirección", data["address"]], ["Ciudad", data["vehicle_city"]], ["Código postal", data["zip_code"]],
        ["Año", str(data["model_year"])], ["Marca", data["make"]], ["Modelo", data["model"]],
        ["VIN", data["vin"]], ["Número de póliza", "••••" + str(data["policy_last4"])],
        ["Fecha de inicio", data["start_date"]], ["Fecha de fin", data["end_date"]]
    ]))

    story.append(Paragraph("Validación técnica", styles["NXSection"]))
    source_line = " · ".join([pdf_text(x) for x in [decoded.get("manufacturer"), decoded.get("make"), decoded.get("model"), decoded.get("model_year")] if x])
    story.append(table([
        ["Resultado", "VALIDACIÓN TÉCNICA SUPERADA"], ["Puntuación NEXUS", f'{data["validation_score"]}/100'],
        ["VIN", "Válido y decodificado"], ["Datos técnicos", source_line or "Sin datos adicionales"],
        ["Fuente técnica", "NHTSA vPIC"]
    ]))

    story.append(Spacer(1, 14))
    story.append(Paragraph("Privacidad", styles["NXSection"]))
    story.append(Paragraph("El SSN no se incluye en este documento. El número de póliza se muestra parcialmente para reducir la exposición de datos sensibles. La validación técnica del VIN no acredita propiedad del vehículo ni autenticidad de la póliza.", styles["NXSmall"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph(f'Generado por NEXUS AI · {pdf_text(now())} · Documento {pdf_text(data["passport_ref"])}', styles["NXSmall"]))

    try:
        doc.build(story)
        pdf=buf.getvalue()
        if not pdf.startswith(b"%PDF"):
            raise RuntimeError("El documento PDF no pudo construirse correctamente.")
    except Exception as exc:
        app.logger.exception("vehicle_document PDF generation failed")
        return jsonify({"error":"No fue posible generar el PDF.","detail":str(exc)}),500
    add_event(registration_id, "vehicle_document_generated", "Vehicle registration summary PDF generated", "info", {"score":data["validation_score"]})
    response=make_response(pdf)
    response.headers["Content-Type"]="application/pdf"
    response.headers["Content-Disposition"]=f'inline; filename="NEXUS_Vehiculo_{data["passport_ref"]}.pdf"'
    response.headers["Cache-Control"]="no-store"
    return response


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
