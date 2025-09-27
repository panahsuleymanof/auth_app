import os, re, time, secrets, requests
from datetime import timedelta
from flask import Flask, request, render_template, redirect, url_for, session
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf, CSRFError
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from argon2 import PasswordHasher, exceptions as argon2_exceptions
from email_validator import validate_email, EmailNotValidError
from pymongo import MongoClient, errors as pymongo_errors
import redis as redis_lib
from dotenv import load_dotenv

load_dotenv()

# ====== ENV ======
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/authapp")
REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")
SESSION_MINUTES = int(os.environ.get("SESSION_PERMANENT_MINUTES", "2"))
RECAPTCHA_SITE_KEY = os.environ.get("RECAPTCHA_SITE_KEY", "")
RECAPTCHA_SECRET   = os.environ.get("RECAPTCHA_SECRET", "")

# ====== APP BASE ======
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=SESSION_MINUTES),
    SESSION_REFRESH_EACH_REQUEST=True,
    WTF_CSRF_TIME_LIMIT=None,
    WTF_CSRF_METHODS=['POST', 'PUT', 'PATCH', 'DELETE'],
    MAX_CONTENT_LENGTH=1 * 1024 * 1024
)
csrf = CSRFProtect(app)

MAX_PASSWORD_LEN = 128

# ====== Redis (sessions + limiter storage) ======
redis_conn = redis_lib.from_url(REDIS_URL)
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_REDIS'] = redis_conn
Session(app)

# ====== Limiter ======
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri=REDIS_URL,
    headers_enabled=True,
    default_limits=["200 per day", "50 per hour"]
)

# ====== Password hasher ======
ph = PasswordHasher()

# ====== MongoDB ======
mongo = MongoClient(MONGO_URI)
db = mongo.get_default_database()
users = db.users
users.create_index("email", unique=True)

# Dummy password (timing safe)
DUMMY_HASH = ph.hash("S0m3R@nd0mDummyTestP@sswword!")

# ====== Helpers ======
@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf, RECAPTCHA_SITE_KEY=RECAPTCHA_SITE_KEY)

def verify_recaptcha(token, remote_ip=None):
    if not RECAPTCHA_SECRET or not token:
        return False, "reCAPTCHA konfiqurasiya olunmayıb."
    try:
        r = requests.post(
            "https://www.google.com/recaptcha/api/siteverify",
            data={"secret": RECAPTCHA_SECRET, "response": token, "remoteip": remote_ip},
            timeout=5.0
        )
        data = r.json()
    except Exception as ex:
        return False, f"reCAPTCHA server xətası: {ex}"
    return (True, None) if data.get("success") else (False, "reCAPTCHA doğrulanmadı.")

def login_rate_key():
    email = (request.form.get("email") or "").strip().lower()
    ip = get_remote_address()
    return f"{ip}|{email}" if email else ip

# ====== Idle timeout ======
@app.before_request
def enforce_idle_timeout():
    if 'user_id' not in session:
        return
    now = time.time()
    last = session.get('last_activity', now)
    if now - last > SESSION_MINUTES * 60:
        session.clear()
        return redirect(url_for('login', expired=1))
    session['last_activity'] = now

# ====== Routes ======
@app.route("/")
def index():
    return redirect(url_for("login"))

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("3 per minute; 10 per hour", methods=["POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    if RECAPTCHA_SITE_KEY and RECAPTCHA_SECRET:
        token = request.form.get("g-recaptcha-response", "")
        ok, msg = verify_recaptcha(token, request.remote_addr)
        if not ok:
            return render_template("register.html", error=msg or "reCAPTCHA doğrulanmadı."), 400

    username = (request.form.get("username") or "").strip()
    email    = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""

    if len(password) > MAX_PASSWORD_LEN:
        return render_template("register.html", error="Şifrə çox uzundur."), 400
    if not username or not email or not password:
        return render_template("register.html", error="Bütün sahələri doldurun."), 400

    try:
        validate_email(email, check_deliverability=False)
    except EmailNotValidError:
        return render_template("register.html", error="Yanlış e-mail formatı."), 400

    if (len(password) < 8 or
        not re.search(r"[A-Z]", password) or
        not re.search(r"\d", password) or
        not re.search(r"[^A-Za-z0-9]", password)):
        return render_template("register.html",
            error="Şifrə zəifdir. Minimum 8 simvol, 1 böyük hərf, 1 rəqəm və 1 xüsusi simvol tələb olunur."), 400

    password_hash = ph.hash(password)
    try:
        users.insert_one({
            "username": username,
            "email": email,
            "password_hash": password_hash,
            "created_at": time.time()
        })
    except pymongo_errors.DuplicateKeyError:
        return render_template("register.html", error="Bu e-mail ilə artıq qeydiyyat var."), 400

    return redirect(url_for('login'))

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("20 per hour", methods=["POST"])
@limiter.limit("5 per minute", methods=["POST"], key_func=login_rate_key)
def login():
    if request.method == "GET":
        if 'user_id' in session:
            return redirect(url_for('dashboard'))
        if request.args.get('expired'):
            return render_template("login.html", error="Sessiya vaxtı bitdi, yenidən daxil olun.")
        return render_template("login.html")

    if RECAPTCHA_SITE_KEY and RECAPTCHA_SECRET:
        token = request.form.get("g-recaptcha-response", "")
        ok, msg = verify_recaptcha(token, request.remote_addr)
        if not ok:
            session.clear()
            return render_template("login.html", error=msg or "reCAPTCHA doğrulanmadı."), 400

    email    = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""

    if len(password) > MAX_PASSWORD_LEN:
        return render_template("login.html", error="Şifrə çox uzundur."), 400
    if not email or not password:
        return render_template("login.html", error="E-mail və ya şifrə daxil edilməyib."), 400

    row = users.find_one({"email": email}, {"_id": 1, "username": 1, "password_hash": 1})

    user = None
    stored_hash = DUMMY_HASH
    if row:
        user = {"id": str(row["_id"]), "username": row.get("username")}
        stored_hash = row.get("password_hash", DUMMY_HASH)

    try:
        ph.verify(stored_hash, password)
        password_ok = True
    except argon2_exceptions.VerifyMismatchError:
        password_ok = False
    except Exception:
        password_ok = False

    if not (password_ok and user):
        session.clear()
        return render_template("login.html", error="E-mail və ya şifrə yanlışdır"), 401

    session.clear()
    session['user_id'] = user['id']
    session['username'] = user['username']
    session.permanent = True
    session['last_activity'] = time.time()
    return redirect(url_for('dashboard'))

@app.route("/dashboard")
def dashboard():
    if 'user_id' not in session:
        return "403 Forbidden - Dashboard yalnız uğurlu giriş sonrası görünür.", 403
    return render_template("dashboard.html", username=session.get('username', 'İstifadəçi'))

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route("/ping")
def ping():
    return "OK"

# ====== Errors ======
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template("login.html", error="CSRF doğrulaması uğursuz oldu. Səhifəni yeniləyib yenidən cəhd edin."), 400

@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template("login.html", error="Çox sayda cəhd etdiniz. Bir qədər sonra yenidən yoxlayın."), 429

# ====== Security Headers ======
@app.after_request
def add_security_headers(resp):
    resp.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
    resp.headers.setdefault("Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://www.google.com https://www.gstatic.com; "
        "frame-src https://www.google.com; "
        "img-src 'self' data: https://www.google.com https://www.gstatic.com; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'")
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    resp.headers.setdefault("Permissions-Policy", "clipboard-read=(), clipboard-write=()")
    return resp

# ====== Run ======
if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        ssl_context=("localhost+2.pem", "localhost+2-key.pem")
    )