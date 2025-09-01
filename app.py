import os
import secrets
import datetime
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
from itsdangerous import URLSafeSerializer
from dotenv import load_dotenv
import requests
import openai

# Load environment variables from .env file if present
load_dotenv()

# --- Config ---
app = Flask(__name__)
app.secret_key = os.getenv("APP_SECRET", "change-me")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///nexora.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
login = LoginManager(app)
login.login_view = "login"

# --- Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=False)
    name = db.Column(db.String, default="")
    plan = db.Column(db.String, default="Starter")
    password = db.Column(db.String, default="")  # store hash in production
    brand = db.Column(db.String, default="")
    logo_url = db.Column(db.String, default="")
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    name = db.Column(db.String)
    email = db.Column(db.String)
    company = db.Column(db.String)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


@login.user_loader
def load_user(uid):
    return User.query.get(int(uid))

# --- External keys ---
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
BREVO_API_KEY = os.getenv("BREVO_API_KEY")
ZAP_SECRET = os.getenv("ZAP_SECRET")  # must match Zapier "secret"

openai.api_key = OPENAI_API_KEY

# --- Utils ---
s = URLSafeSerializer(app.secret_key)


def magic_link_for(email: str) -> str:
    """Create a signed URL for onboarding/claiming an account."""
    token = s.dumps({"email": email, "ts": datetime.datetime.utcnow().isoformat()})
    return url_for("claim", token=token, _external=True)

# --- Routes ---

@app.route("/")
def home():
    """Landing page. Redirect to dashboard if authenticated."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("landing.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Simple login form: only requires email address."""
    if request.method == "POST":
        email = request.form["email"].strip().lower()
        user = User.query.filter_by(email=email).first()
        if user:
            login_user(user)
            return redirect(url_for("dashboard"))
        flash("No account found. Check your welcome email for setup link.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    """Logout user and return to home."""
    logout_user()
    return redirect(url_for("home"))


@app.route("/claim/<token>", methods=["GET", "POST"])
def claim(token):
    """Claim account via magic link. Set brand and logo then log in."""
    try:
        data = s.loads(token)
        email = data["email"].lower()
    except Exception:
        return "Invalid or expired link.", 400
    user = User.query.filter_by(email=email).first()
    if not user:
        return "Account not found.", 404
    if request.method == "POST":
        user.brand = request.form.get("brand", "")
        user.logo_url = request.form.get("logo_url", "")
        db.session.commit()
        login_user(user)
        return redirect(url_for("dashboard"))
    return render_template("onboarding.html", email=email)


@app.route("/dashboard")
@login_required
def dashboard():
    """Authenticated user dashboard showing contacts and composer."""
    contacts = (
        Contact.query.filter_by(user_id=current_user.id)
        .order_by(Contact.created_at.desc())
        .all()
    )
    return render_template("dashboard.html", contacts=contacts)


@app.route("/compose", methods=["POST"])
@login_required
def compose():
    """Generate AI-drafted email or SMS text via OpenAI."""
    kind = request.form.get("kind", "email")  # email or sms
    brief = request.form["brief"]
    system = "You are a marketing assistant. Draft concise, high-converting copy."
    if kind == "sms":
        system += " Keep it under 160 characters. Include clear CTA. No emojis unless asked."
    try:
        resp = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[{"role": "system", "content": system}, {"role": "user", "content": brief}],
            max_tokens=300,
            temperature=0.7,
        )
        text = resp["choices"][0]["message"]["content"].strip()
    except Exception as e:
        text = f"(Error generating copy: {e})"
    return jsonify({"text": text})


@app.route("/send-email", methods=["POST"])
@login_required
def send_email():
    """Send an email via Brevo transactional API to all contacts."""
    subject = request.form["subject"]
    body_html = request.form["body_html"]
    # Build list of recipient dictionaries
    tos = [
        {"email": c.email, "name": c.name or ""}
        for c in Contact.query.filter_by(user_id=current_user.id)
    ]
    if not tos:
        return jsonify({"ok": False, "error": "No contacts"}), 400
    r = requests.post(
        "https://api.brevo.com/v3/smtp/email",
        headers={"api-key": BREVO_API_KEY, "Content-Type": "application/json"},
        json={
            "sender": {
                "name": current_user.brand or "Nexora AI",
                "email": os.getenv("SENDER_EMAIL", "[email protected]"),
            },
            "to": tos,
            "subject": subject,
            "htmlContent": body_html,
        },
    )
    return jsonify({"ok": r.status_code in (200, 201), "status": r.text})


@app.route("/contacts/add", methods=["POST"])
@login_required
def add_contact():
    """Add a new contact for the current user."""
    name = request.form.get("name", "")
    email = request.form.get("email", "").lower()
    company = request.form.get("company", "")
    if not email:
        return jsonify({"ok": False, "error": "Email required"}), 400
    c = Contact(user_id=current_user.id, name=name, email=email, company=company)
    db.session.add(c)
    db.session.commit()
    return jsonify({"ok": True})


# --- Zapier: create-user endpoint ---
@app.route("/api/create-user", methods=["POST"])
def api_create_user():
    """Endpoint to create or fetch a user via Zapier and return a magic link."""
    data = request.get_json(force=True)
    if data.get("secret") != ZAP_SECRET:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    email = data["email"].strip().lower()
    name = data.get("name", "")
    plan = data.get("plan", "Starter")
    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email, name=name, plan=plan)
        db.session.add(user)
        db.session.commit()
    return jsonify({"ok": True, "claim_link": magic_link_for(email)})


# --- Bootstrap DB ---
with app.app_context():
    db.create_all()


if __name__ == "__main__":
    app.run(debug=True)