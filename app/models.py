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


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
