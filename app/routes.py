from flask import Blueprint, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from .models import AnalysisLog, User, db
from .predictor import analyze_request


main_bp = Blueprint("main", __name__)


def serialize_analysis(record):
    return {
        "id": record.id,
        "attack_type": record.attack_type,
        "status": record.status,
        "severity": record.severity,
        "confidence": round(record.confidence * 100),
        "blocked": record.blocked,
        "recommended_action": record.recommended_action,
        "request_excerpt": (
            record.request_text[:120] + "..." if len(record.request_text) > 120 else record.request_text
        ),
        "created_at": record.created_at.strftime("%Y-%m-%d %H:%M:%S"),
    }


def build_dashboard_summary(user_id):
    records = (
        AnalysisLog.query.filter_by(user_id=user_id)
        .order_by(AnalysisLog.created_at.desc())
        .all()
    )
    total = len(records)
    blocked = sum(1 for item in records if item.blocked)
    attacks = sum(1 for item in records if item.status in {"Attack", "Suspicious"})
    safe = sum(1 for item in records if item.status == "Safe")
    high_severity = sum(1 for item in records if item.severity in {"Critical", "High"})

    return {
        "total_scans": total,
        "attacks_detected": attacks,
        "safe_requests": safe,
        "requests_blocked": blocked,
        "high_severity": high_severity,
        "recent_analyses": [serialize_analysis(item) for item in records[:6]],
    }


@main_bp.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    return redirect(url_for("main.login"))


@main_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not username or not email or not password:
            flash("All fields are required.", "error")
            return render_template("register.html")

        if User.query.filter(
            (User.username == username) | (User.email == email)
        ).first():
            flash("Username or email already exists.", "error")
            return render_template("register.html")

        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
        )
        db.session.add(user)
        db.session.commit()

        flash("Registration successful. Please sign in.", "success")
        return redirect(url_for("main.login"))

    return render_template("register.html")


@main_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))

    if request.method == "POST":
        identity = request.form.get("identity", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter(
            (User.username == identity) | (User.email == identity.lower())
        ).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash("Welcome back. You are now signed in.", "success")
            return redirect(url_for("main.dashboard"))

        flash("Invalid credentials. Please try again.", "error")

    return render_template("login.html")


@main_bp.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for("main.login"))


@main_bp.route("/dashboard")
@login_required
def dashboard():
    summary = build_dashboard_summary(current_user.id)
    return render_template("dashboard.html", summary=summary)


@main_bp.route("/predict", methods=["POST"])
@login_required
def predict():
    payload = request.get_json(silent=True) or {}
    request_text = payload.get("request_text", "").strip()

    if not request_text:
        return jsonify({"error": "request_text is required."}), 400

    result = analyze_request(request_text)
    log = AnalysisLog(
        user_id=current_user.id,
        request_text=request_text,
        attack_type=result["attack_type"],
        status=result["status"],
        severity=result["severity"],
        confidence=result["confidence"],
        blocked=result["blocked"],
        recommended_action=result["recommended_action"],
    )
    db.session.add(log)
    db.session.commit()

    response = {
        **result,
        "history_item": serialize_analysis(log),
        "summary": build_dashboard_summary(current_user.id),
    }
    return jsonify(response), 200
