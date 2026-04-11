from __future__ import annotations

from urllib.parse import unquote, urlparse

from flask import current_app, request
from flask_login import current_user

from .models import SecurityEvent, db
from .predictor import analyze_request, preprocess_request


EXEMPT_ENDPOINTS = {
    "static",
    "main.index",
    "main.login",
    "main.register",
    "main.logout",
    "main.dashboard",
    "main.predict",
    "main.scan_security",
    "main.security_events",
    "main.security_admin",
    "main.analytics_endpoints",
    "main.analytics_time",
}

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": "default-src 'self'; style-src 'self' https://fonts.googleapis.com 'unsafe-inline'; font-src 'self' https://fonts.gstatic.com; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
}


def extract_endpoint_from_url(url: str) -> str:
    value = (url or "").strip()
    if not value:
        return "/"

    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        return parsed.path or "/"

    if value.startswith("/"):
        parsed_path = urlparse(value).path
        return parsed_path or "/"

    return "/"


def should_inspect_request(req) -> bool:
    if req.endpoint in EXEMPT_ENDPOINTS:
        return False

    if req.path.startswith("/static/"):
        return False

    if req.method == "GET" and not req.query_string:
        return False

    return True


def build_request_text(req) -> str:
    body = req.get_data(cache=True, as_text=True)[:2000]
    query_string = req.query_string.decode("utf-8", errors="ignore")
    interesting_headers = [
        ("Host", req.host),
        ("Content-Type", req.headers.get("Content-Type", "")),
        ("Origin", req.headers.get("Origin", "")),
        ("Referer", req.headers.get("Referer", "")),
        ("User-Agent", req.headers.get("User-Agent", "")),
        ("X-CSRF-Token", req.headers.get("X-CSRF-Token", "")),
        ("Cookie", req.headers.get("Cookie", "")),
    ]

    lines = [f"{req.method} {req.full_path.rstrip('?')} HTTP/1.1"]
    for name, value in interesting_headers:
        if value:
            lines.append(f"{name}: {value}")

    if query_string:
        lines.append(f"Query: {unquote(query_string)}")

    if body:
        lines.append("")
        lines.append(body)

    return "\n".join(lines).strip()


def inspect_live_request(req) -> dict:
    request_text = build_request_text(req)
    processed = preprocess_request(request_text)
    request_meta = {
        "mode": "live",
        "path": req.path,
        "method": req.method,
        "host": req.host,
        "origin": req.headers.get("Origin", ""),
        "referer": req.headers.get("Referer", ""),
        "has_session_cookie": "session=" in (req.headers.get("Cookie", "").lower()),
    }
    verdict = analyze_request(processed["raw"], request_meta=request_meta)
    verdict["request_excerpt"] = processed["raw"][:180] + ("..." if len(processed["raw"]) > 180 else "")
    current_app.logger.debug(
        "Live preprocess: method=%s url=%s headers=%s body=%s",
        processed["method"],
        processed["url"],
        processed["headers"][:120],
        processed["body"][:120],
    )
    return verdict


def persist_security_event(verdict: dict, req, source: str = "live", user_id: int | None = None) -> SecurityEvent:
    event_path = verdict.get("target_endpoint") or req.path
    event = SecurityEvent(
        user_id=user_id,
        source=source,
        method=req.method,
        path=event_path,
        endpoint=req.endpoint,
        client_ip=req.headers.get("X-Forwarded-For", req.remote_addr),
        user_agent=(req.headers.get("User-Agent", "") or "")[:255],
        attack_type=verdict["attack_type"],
        status=verdict["status"],
        severity=verdict["severity"],
        confidence=verdict["confidence"],
        blocked=verdict["blocked"],
        recommended_action=verdict["recommended_action"],
        request_excerpt=verdict.get("request_excerpt", ""),
        detection_mode=verdict.get("detection_mode", "Real-Time Inspection"),
    )
    db.session.add(event)
    db.session.commit()
    return event


def _attack_events_query(user_id: int | None = None):
    query = SecurityEvent.query.filter(SecurityEvent.status == "Attack")
    if user_id is not None:
        query = query.filter(SecurityEvent.user_id == user_id)
    return query


def most_attacked_endpoints(limit: int = 5, user_id: int | None = None) -> dict[str, int]:
    rows = (
        _attack_events_query(user_id=user_id)
        .with_entities(SecurityEvent.path, db.func.count(SecurityEvent.id).label("attack_count"))
        .group_by(SecurityEvent.path)
        .order_by(db.func.count(SecurityEvent.id).desc())
        .limit(limit)
        .all()
    )
    return {path or "/": int(count) for path, count in rows}


def peak_attack_times(user_id: int | None = None) -> dict[str, int]:
    rows = (
        _attack_events_query(user_id=user_id)
        .with_entities(
            db.func.strftime("%H", SecurityEvent.created_at).label("attack_hour"),
            db.func.count(SecurityEvent.id),
        )
        .group_by("attack_hour")
        .all()
    )
    hour_counts = {str(int(hour)): int(count) for hour, count in rows if hour is not None}
    return {str(hour): hour_counts.get(str(hour), 0) for hour in range(24)}


def build_attack_analytics(user_id: int | None = None) -> dict:
    endpoint_counts = most_attacked_endpoints(user_id=user_id)
    hour_counts = peak_attack_times(user_id=user_id)
    top_endpoint = max(endpoint_counts.items(), key=lambda item: item[1], default=("/", 0))
    peak_hour = max(hour_counts.items(), key=lambda item: item[1], default=("0", 0))

    return {
        "endpoints": endpoint_counts,
        "time": hour_counts,
        "most_targeted_endpoint": {"endpoint": top_endpoint[0], "count": top_endpoint[1]},
        "peak_attack_hour": {"hour": peak_hour[0], "count": peak_hour[1]},
    }


def monitor_current_request() -> tuple[dict, SecurityEvent] | None:
    if not should_inspect_request(request):
        return None

    verdict = inspect_live_request(request)
    user_id = current_user.id if current_user.is_authenticated else None
    event = persist_security_event(verdict, request, source="live", user_id=user_id)
    return verdict, event


def generate_vulnerability_scan(flask_app) -> dict:
    findings = []
    config = flask_app.config
    routes = sorted(
        {
            f"{','.join(sorted(rule.methods - {'HEAD', 'OPTIONS'}))} {rule.rule}"
            for rule in flask_app.url_map.iter_rules()
            if not rule.rule.startswith("/static/")
        }
    )

    if config.get("SECRET_KEY") == "dev-secret-change-me":
        findings.append(
            {
                "title": "Default Flask secret key detected",
                "severity": "High",
                "impact": "Session signing is weak and predictable in production.",
                "recommendation": "Set a strong SECRET_KEY environment variable before deployment.",
            }
        )

    findings.append(
        {
            "title": "No anti-CSRF token validation on HTML forms",
            "severity": "High",
            "impact": "Authenticated state-changing requests can be forged from another site.",
            "recommendation": "Add CSRF token generation and verification to login, registration, and privileged POST routes.",
        }
    )

    if "CORS" in {extension.__class__.__name__ for extension in flask_app.extensions.values()}:
        findings.append(
            {
                "title": "CORS is enabled application-wide",
                "severity": "Medium",
                "impact": "Broad cross-origin access can increase exposure if credentials or admin APIs are added later.",
                "recommendation": "Restrict allowed origins and methods to the minimum needed by the frontend.",
            }
        )

    findings.append(
        {
            "title": "No rate limiting on authentication and analysis endpoints",
            "severity": "Medium",
            "impact": "Attackers can brute-force credentials or flood the detector with automated traffic.",
            "recommendation": "Add per-IP rate limiting for login, registration, and real-time analysis endpoints.",
        }
    )

    severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
    highest_severity = max((severity_order[item["severity"]] for item in findings), default=1)
    overall_risk = {4: "Critical", 3: "High", 2: "Medium", 1: "Low"}[highest_severity]

    return {
        "scan_target": current_app.config.get("SERVER_NAME") or "local-flask-application",
        "overall_risk": overall_risk,
        "total_findings": len(findings),
        "findings": findings,
        "inspected_routes": routes,
        "security_headers": SECURITY_HEADERS,
    }


def build_security_summary(user_id: int) -> dict:
    records = (
        SecurityEvent.query.filter_by(user_id=user_id)
        .order_by(SecurityEvent.created_at.desc())
        .all()
    )
    total = len(records)
    blocked = sum(1 for item in records if item.blocked)
    attacks = sum(1 for item in records if item.status in {"Attack", "Suspicious"})
    safe = sum(1 for item in records if item.status == "Safe")
    high_severity = sum(1 for item in records if item.severity in {"Critical", "High"})
    sources = {}
    for item in records:
        sources[item.source] = sources.get(item.source, 0) + 1

    return {
        "total_scans": total,
        "attacks_detected": attacks,
        "safe_requests": safe,
        "requests_blocked": blocked,
        "high_severity": high_severity,
        "live_requests": sources.get("live", 0),
        "manual_analyses": sources.get("manual", 0),
        "recent_events": [
            {
                "id": item.id,
                "source": item.source,
                "attack_type": item.attack_type,
                "status": item.status,
                "severity": item.severity,
                "confidence": round(item.confidence * 100),
                "blocked": item.blocked,
                "method": item.method,
                "path": item.path,
                "request_excerpt": item.request_excerpt,
                "created_at": item.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            }
            for item in records[:8]
        ],
    }
