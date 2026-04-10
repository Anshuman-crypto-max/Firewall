from __future__ import annotations

import csv
import time
from datetime import datetime, timedelta
from pathlib import Path

from flask import current_app
from sqlalchemy import and_

from .models import BlockedIP, LoginAttempt, db


FAILED_LIMIT = 5
WINDOW_SECONDS = 30
BLOCK_MINUTES = 5
RAPID_INTERVAL_SECONDS = 1.0
CAPTCHA_THRESHOLD = 3


def _now() -> datetime:
    return datetime.utcnow()


def get_client_ip(request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def is_blocked(ip_address: str) -> bool:
    blocked = BlockedIP.query.filter_by(ip_address=ip_address).first()
    if not blocked:
        return False
    if blocked.expires_at <= _now():
        db.session.delete(blocked)
        db.session.commit()
        return False
    return True


def block_ip(ip_address: str, reason: str) -> BlockedIP:
    expiry = _now() + timedelta(minutes=BLOCK_MINUTES)
    blocked = BlockedIP.query.filter_by(ip_address=ip_address).first()
    if blocked:
        blocked.expires_at = expiry
        blocked.reason = reason
    else:
        blocked = BlockedIP(ip_address=ip_address, reason=reason, expires_at=expiry)
        db.session.add(blocked)
    db.session.commit()
    return blocked


def record_attempt(ip_address: str, username: str | None, success: bool) -> LoginAttempt:
    attempt = LoginAttempt(
        ip_address=ip_address,
        username=(username or "")[:120],
        success=success,
    )
    db.session.add(attempt)
    db.session.commit()
    return attempt


def _recent_attempts(ip_address: str, window_seconds: int = WINDOW_SECONDS) -> list[LoginAttempt]:
    cutoff = _now() - timedelta(seconds=window_seconds)
    return (
        LoginAttempt.query.filter(
            and_(
                LoginAttempt.ip_address == ip_address,
                LoginAttempt.created_at >= cutoff,
            )
        )
        .order_by(LoginAttempt.created_at.desc())
        .all()
    )


def detect_bruteforce(ip_address: str) -> dict:
    attempts = _recent_attempts(ip_address)
    failed_attempts = [a for a in attempts if not a.success]
    usernames = {a.username for a in attempts if a.username}
    rapid_fire = False

    if len(attempts) >= 2:
        latest = attempts[0].created_at
        previous = attempts[1].created_at
        rapid_fire = (latest - previous).total_seconds() < RAPID_INTERVAL_SECONDS

    flags = []
    reason = None

    if len(failed_attempts) > FAILED_LIMIT:
        flags.append("too_many_failures")
        reason = "More than 5 failed login attempts in 30 seconds."

    if len(usernames) >= 3:
        flags.append("username_spray")
        reason = reason or "Multiple different usernames attempted rapidly."

    if rapid_fire:
        flags.append("rapid_fire")
        reason = reason or "Login attempts are too frequent."

    return {
        "flags": flags,
        "reason": reason,
        "failed_count": len(failed_attempts),
        "unique_usernames": len(usernames),
        "captcha_required": len(failed_attempts) >= CAPTCHA_THRESHOLD,
    }


def apply_backoff_delay(failed_count: int) -> float:
    if failed_count <= 0:
        return 0.0
    delay = min(2.0, 0.3 * (2 ** min(failed_count - 1, 3)))
    time.sleep(delay)
    return delay


def log_attempt_to_csv(ip_address: str, username: str | None, success: bool, reason: str | None = None) -> None:
    try:
        base_dir = Path(current_app.root_path).parent
        csv_path = base_dir / "instance" / "login_attempts.csv"
        csv_path.parent.mkdir(exist_ok=True)
        is_new_file = not csv_path.exists()
        with csv_path.open("a", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            if is_new_file:
                writer.writerow(["timestamp", "ip_address", "username", "success", "reason"])
            writer.writerow([_now().isoformat(), ip_address, username or "", success, reason or ""])
    except Exception:
        current_app.logger.exception("Failed to write login attempt CSV log")
