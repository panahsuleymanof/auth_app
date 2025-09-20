# Auth App — Secure Login & Register System

A simple authentication system built with **Flask**, designed for learning and local testing.  
Includes **TLS (HTTPS)**, **CSRF protection**, **Argon2 password hashing**, **rate limiting**, and secure session management.

---

## 🔧 Requirements
- Python 3.10+
- `pip`
- `mkcert` (for local HTTPS certificates, optional but recommended)

---

## 📂 Project Structure
```
app.py             # Main application
templates/         # HTML templates (login, register, dashboard, base)
.env               # Local secrets (NOT committed)
.env.example       # Example of required env variables
requirements.txt   # Python dependencies
```

---

## 🚀 Setup & Run

1. **Clone & install dependencies**
```bash
git clone <your-repo-url>
cd <your-repo>
python3 -m venv venv
source venv/bin/activate   # macOS/Linux
# venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

2. **Setup `.env`**
- Copy the example:
  ```bash
  cp .env.example .env
  ```
- Generate a secret key:
  ```bash
  python -c "import secrets; print(secrets.token_hex(32))"
  ```
- Put it inside `.env`:
  ```ini
  SECRET_KEY=your_generated_secret_here
  ```

⚠️ `.env` is ignored by Git. Each user must generate their own key.

3. **(Optional) Generate local TLS certificates with mkcert**
```bash
mkcert -install
mkcert localhost 127.0.0.1
# Produces: localhost+2.pem and localhost+2-key.pem
```

4. **Run the app**
```bash
python app.py
```
Then open: [https://127.0.0.1:5000](https://127.0.0.1:5000)

---

## 🔑 Features
- **TLS (HTTPS)** — encrypted traffic with mkcert certificates
- **CSRF Protection** — all forms require CSRF token
- **Password Hashing** — Argon2 for secure password storage
- **Rate Limiting** — login/register attempts are limited per user/IP
- **Secure Cookies** — `HttpOnly`, `Secure`, `SameSite=Lax`
- **Idle Session Timeout** — auto logout after inactivity
- **User Enumeration Protection** — dummy hash to prevent timing attacks

---

## 📌 Notes
- Do **not** commit `.env` or certificate files.
- Provide `.env.example` so others know required variables.
- On first run, if `.env` is missing, the app generates a temporary secret key but warns sessions will be unstable.
- For production use: always set a strong `SECRET_KEY`, real TLS certs, and `DEBUG=False`.
