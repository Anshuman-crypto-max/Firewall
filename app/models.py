from flask_login import LoginManager, UserMixin
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "main.login"
login_manager.login_message_category = "info"
login_manager.login_message = "Please sign in to access the dashboard."


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now(), nullable=False)
    analyses = db.relationship("AnalysisLog", backref="user", lazy=True)

    def __repr__(self):
        return f"<User {self.username}>"


class AnalysisLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    request_text = db.Column(db.Text, nullable=False)
    attack_type = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    blocked = db.Column(db.Boolean, nullable=False, default=False)
    recommended_action = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now(), nullable=False)

    def __repr__(self):
        return f"<AnalysisLog {self.attack_type} {self.status}>"


class SecurityEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    source = db.Column(db.String(20), nullable=False, default="live")
    method = db.Column(db.String(10), nullable=False)
    path = db.Column(db.String(255), nullable=False)
    endpoint = db.Column(db.String(120), nullable=True)
    client_ip = db.Column(db.String(64), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    attack_type = db.Column(db.String(120), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    blocked = db.Column(db.Boolean, nullable=False, default=False)
    recommended_action = db.Column(db.String(255), nullable=False)
    request_excerpt = db.Column(db.Text, nullable=False)
    detection_mode = db.Column(db.String(80), nullable=False, default="Real-Time Inspection")
    created_at = db.Column(db.DateTime, server_default=db.func.now(), nullable=False)

    def __repr__(self):
        return f"<SecurityEvent {self.method} {self.path} {self.attack_type}>"


class LoginAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(64), nullable=False, index=True)
    username = db.Column(db.String(120), nullable=True)
    success = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now(), nullable=False, index=True)

    def __repr__(self):
        return f"<LoginAttempt {self.ip_address} {self.username} {self.success}>"


class BlockedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(64), nullable=False, unique=True, index=True)
    reason = db.Column(db.String(255), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now(), nullable=False)

    def __repr__(self):
        return f"<BlockedIP {self.ip_address} until {self.expires_at}>"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
