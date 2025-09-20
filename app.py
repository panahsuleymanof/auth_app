from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import timedelta
from argon2 import PasswordHasher, exceptions as argon2_exceptions
from email_validator import validate_email, EmailNotValidError
import sqlite3, os, re, time, secrets
from dotenv import load_dotenv

load_dotenv()
DB_PATH = "users.db"

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
if not app.config.get('SECRET_KEY'):
    app.config['SECRET_KEY'] = secrets.token_hex(32)
    print("WARNING: DEV SECRET_KEY generated. Set SECRET_KEY in .env for stable sessions.")

app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=2)
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

app.config['WTF_CSRF_TIME_LIMIT'] = None
app.config['WTF_CSRF_METHODS'] = ['POST', 'PUT', 'PATCH', 'DELETE']

ph = PasswordHasher()
csrf = CSRFProtect(app)

limiter = Limiter(get_remote_address, app=app,
                  default_limits=["200 per day", "50 per hour"],
                  headers_enabled=True)

@app.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

DUMMY_PASSWORD = "S0m3R@nd0mDummyTestP@sswword!"
DUMMY_HASH = ph.hash(DUMMY_PASSWORD)

def init_db():
    if not os.path.exists(DB_PATH):
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.cursor()
            cur.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            );
            """)
            conn.commit()
        return True
    return False

@app.before_request
def enforce_idle_timeout():
    if 'user_id' not in session:
        return
    now = time.time()
    last = session.get('last_activity', now)
    if now - last > 120:
        session.clear()
        return redirect(url_for('login', expired=1))
    session['last_activity'] = now

@app.route("/")
def index():
    return redirect(url_for("login"))

@limiter.limit("3 per minute; 10 per hour", methods=["POST"])
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    username = (request.form.get("username") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""

    if not username or not email or not password:
        flash("Bütün sahələri doldurun.", "error")
        return redirect(url_for('register'))

    try:
        validate_email(email, check_deliverability=False)
    except EmailNotValidError:
        flash("Yanlış e-mail formatı.", "error")
        return redirect(url_for('register'))

    if (
        len(password) < 8 or
        not re.search(r"[A-Z]", password) or
        not re.search(r"\d", password) or
        not re.search(r"[^A-Za-z0-9]", password)
    ):
        flash("Şifrə zəifdir. Minimum 8 simvol, 1 böyük hərf, 1 rəqəm və 1 xüsusi simvol tələb olunur.", "error")
        return redirect(url_for('register'))

    password_hash = ph.hash(password)

    try:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, password_hash)
            )
            conn.commit()
    except sqlite3.IntegrityError:
        flash("Bu e-mail ilə artıq qeydiyyat var.", "error")
        return redirect(url_for('register'))

    flash("Uğurla qeydiyyat tamamlandı. İndi daxil olun.", "success")
    return redirect(url_for('login'))

@limiter.limit("5 per minute", methods=["POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        if request.args.get('expired'):
            flash("Sessiya vaxtı bitdi, yenidən daxil olun.", "error")
        return render_template("login.html")

    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""

    if not email or not password:
        flash("E-mail və ya şifrə daxil edilməyib.", "error")
        return redirect(url_for('login'))

    with sqlite3.connect(DB_PATH) as conn:
        cur = conn.cursor()
        cur.execute("SELECT id, username, password_hash FROM users WHERE email = ?", (email,))
        row = cur.fetchone()

    user = None
    stored_hash = DUMMY_HASH
    if row:
        user = {"id": row[0], "username": row[1]}
        stored_hash = row[2]

    try:
        ph.verify(stored_hash, password)
        password_ok = True
    except argon2_exceptions.VerifyMismatchError:
        password_ok = False
    except Exception:
        password_ok = False

    if not (password_ok and user):
        flash("E-mail və ya şifrə yanlışdır", "error")
        return redirect(url_for('login'))

    session['user_id'] = user['id']
    session['username'] = user['username']
    session.permanent = True
    session['last_activity'] = time.time()
    return redirect(url_for('dashboard'))

@app.route("/dashboard", methods=["GET"])
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

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash("CSRF doğrulaması uğursuz oldu. Səhifəni yeniləyib yenidən cəhd edin.", "error")
    return redirect(url_for('login'))

@app.errorhandler(429)
def ratelimit_handler(e):
    flash("Çox sayda cəhd etdiniz. Bir dəqiqədən sonra yenidən yoxlayın.", "error")
    return redirect(url_for('login'))

if __name__ == "__main__":
    created = init_db()
    print("Database yaradıldı." if created else "Database var.")
    app.run(
        host="127.0.0.1",
        port=5000,
        ssl_context=("localhost+2.pem", "localhost+2-key.pem")
    )