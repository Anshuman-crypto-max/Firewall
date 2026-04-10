import os
from pathlib import Path

from flask import Flask, jsonify, redirect, request, url_for
from flask_cors import CORS

from .models import db, login_manager
from .security import SECURITY_HEADERS, monitor_current_request


BASE_DIR = Path(__file__).resolve().parent.parent


def create_app():
    default_db_path = BASE_DIR / "instance" / "attack_detector.db"
    render_disk_path = os.getenv("RENDER_DISK_PATH")
    if render_disk_path:
        default_db_path = Path(render_disk_path) / "attack_detector.db"

    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
    )

    app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "DATABASE_URL",
        f"sqlite:///{default_db_path}",
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    CORS(app)

    db.init_app(app)
    login_manager.init_app(app)

    @login_manager.unauthorized_handler
    def unauthorized():
        if request.path == "/predict":
            return jsonify({"error": "Authentication required."}), 401
        return redirect(url_for(login_manager.login_view))

    from .routes import main_bp

    app.register_blueprint(main_bp)

    @app.before_request
    def inspect_incoming_traffic():
        monitored = monitor_current_request()
        if not monitored:
            return None

        verdict, event = monitored
        if verdict["blocked"]:
            return (
                jsonify(
                    {
                        "error": "Request blocked by the real-time attack detection firewall.",
                        "event_id": event.id,
                        "attack_type": verdict["attack_type"],
                        "severity": verdict["severity"],
                        "recommended_action": verdict["recommended_action"],
                    }
                ),
                403,
            )
        return None

    @app.after_request
    def apply_security_headers(response):
        for header_name, header_value in SECURITY_HEADERS.items():
            response.headers.setdefault(header_name, header_value)
        return response

    with app.app_context():
        instance_dir = BASE_DIR / "instance"
        instance_dir.mkdir(exist_ok=True)
        if render_disk_path:
            Path(render_disk_path).mkdir(parents=True, exist_ok=True)
        db.create_all()

    return app


# Export a WSGI app for gunicorn (gunicorn app:app)
app = create_app()
