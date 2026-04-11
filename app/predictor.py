from __future__ import annotations

import csv
import pickle
import re
from datetime import datetime, timezone
from pathlib import Path
import pandas as pd
from urllib.parse import unquote, urlparse

from scipy.sparse import hstack

from .url_features import build_feature_matrix


ATTACK_PATTERNS = [
    {
        "type": "SQL Injection",
        "severity": "Critical",
        "recommended_action": "Block the request, sanitize database inputs, and review query parameter handling.",
        "patterns": [
            r"(\bunion\b\s+\bselect\b)",
            r"(\bor\b\s+1=1)",
            r"('.*--)",
            r"(\bdrop\b\s+\btable\b)",
            r"(\binformation_schema\b)",
        ],
        "confidence": 0.95,
        "prevention": [
            "Use parameterized SQL queries.",
            "Validate and normalize untrusted input.",
            "Add WAF rules for common SQL injection signatures.",
        ],
    },
    {
        "type": "Cross-Site Scripting (XSS)",
        "severity": "High",
        "recommended_action": "Block the payload, encode output, and audit any unsanitized HTML rendering paths.",
        "patterns": [
            r"<script\b",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"alert\s*\(",
        ],
        "confidence": 0.92,
        "prevention": [
            "Escape output in templates.",
            "Use a strong Content Security Policy.",
            "Strip dangerous tags and inline event handlers.",
        ],
    },
    {
        "type": "Command Injection",
        "severity": "Critical",
        "recommended_action": "Block the request immediately and inspect any shell command execution paths in the backend.",
        "patterns": [
            r"(;|\|\|)\s*(cat|ls|whoami|curl|wget|powershell|cmd|bash)\b",
            r"`.+`",
            r"\$\(.*\)",
        ],
        "confidence": 0.91,
        "prevention": [
            "Avoid shell invocation for user-controlled values.",
            "Use allowlists for permitted commands.",
            "Run command-executing services with least privilege.",
        ],
    },
    {
        "type": "Directory Traversal",
        "severity": "High",
        "recommended_action": "Reject the request and validate filesystem path handling before serving files.",
        "patterns": [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%252e%252e%255c",
        ],
        "confidence": 0.88,
        "prevention": [
            "Normalize paths before file access.",
            "Restrict reads to fixed base directories.",
            "Block encoded traversal sequences at the edge.",
        ],
    },
    {
        "type": "Cross-Site Request Forgery (CSRF)",
        "severity": "High",
        "recommended_action": "Challenge the request, verify anti-CSRF protection, and review origin validation.",
        "patterns": [
            r"\bx-csrf-token\b",
            r"\bcsrf\b",
            r"origin:\s*https?://[^\s]+",
            r"referer:\s*https?://[^\s]+",
        ],
        "confidence": 0.84,
        "prevention": [
            "Use synchronizer or double-submit CSRF tokens.",
            "Set SameSite cookies where appropriate.",
            "Validate Origin and Referer headers on sensitive actions.",
        ],
    },
    {
        "type": "Reconnaissance / Vulnerability Scanning",
        "severity": "Medium",
        "recommended_action": "Rate limit the source, monitor for repeated probes, and review exposed endpoints.",
        "patterns": [
            r"\b(nikto|sqlmap|nmap|acunetix|nessus|dirbuster)\b",
            r"/wp-admin",
            r"/phpmyadmin",
            r"/\.env",
            r"/server-status",
        ],
        "confidence": 0.8,
        "prevention": [
            "Hide unnecessary endpoints from public exposure.",
            "Rate limit repeated probing patterns.",
            "Alert on tool fingerprints and path enumeration attempts.",
        ],
    },
]

SEVERITY_SCORE = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}


def convert_url_to_http(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError("Invalid URL format")

    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    return "\n".join(
        [
            f"GET {path} HTTP/1.1",
            f"Host: {parsed.netloc}",
            "User-Agent: Mozilla/5.0",
            "Accept: */*",
        ]
    )


def preprocess_request(request_text: str) -> dict:
    raw_input = (request_text or "").strip()
    url_converted = False
    url_error = None

    if raw_input.lower().startswith(("http://", "https://")):
        try:
            raw = convert_url_to_http(raw_input)
            url_converted = True
        except ValueError as exc:
            url_error = str(exc)
            raw = ""
    else:
        raw = raw_input

    if not raw:
        return {
            "raw": "",
            "normalized": "",
            "method": "",
            "url": "",
            "headers": "",
            "body": "",
            "url_converted": url_converted,
            "url_error": url_error,
        }

    lines = [line.strip() for line in raw.splitlines()]
    lines = [line for line in lines if line != ""]
    joined = "\n".join(lines)

    method = ""
    url = ""
    headers = []
    body_lines = []

    if lines:
        first_line = lines[0]
        parts = first_line.split()
        if parts:
            if parts[0].upper() in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                method = parts[0].upper()
                if len(parts) > 1:
                    url = parts[1]
        for line in lines[1:]:
            if ":" in line and not body_lines:
                headers.append(line)
            else:
                body_lines.append(line)

    normalized = joined.lower()
    return {
        "raw": raw,
        "normalized": normalized,
        "method": method,
        "url": url,
        "host": _extract_host(headers),
        "headers": "\n".join(headers).lower(),
        "body": "\n".join(body_lines).lower(),
        "url_converted": url_converted,
        "url_error": url_error,
    }


def _extract_host(headers: list[str]) -> str:
    for header in headers:
        if header.lower().startswith("host:"):
            return header.split(":", 1)[1].strip()
    return ""


def _load_url_model():
    model_path = Path(__file__).resolve().parent.parent / "models" / "url_classifier.pkl"
    if not model_path.exists():
        return None
    with model_path.open("rb") as handle:
        return pickle.load(handle)


URL_MODEL = _load_url_model()


def _rule_based_url_verdict(url: str) -> dict | None:
    lowered = unquote(url or "").lower()
    xss_signatures = [signature for signature in ["<script", "javascript:"] if signature in lowered]
    if xss_signatures:
        return _url_result(
            status="Attack",
            confidence=0.98,
            attack_type="Cross-Site Scripting (XSS)",
            detection_mode="URL Rule Fallback",
            matched_signatures=xss_signatures,
        )
    sqli_signatures = [signature for signature in ["or 1=1", "union select", "'--"] if signature in lowered]
    if sqli_signatures:
        return _url_result(
            status="Attack",
            confidence=0.98,
            attack_type="SQL Injection",
            detection_mode="URL Rule Fallback",
            matched_signatures=sqli_signatures,
        )
    return None


def _build_url_vector(url: str, artifact: dict):
    handcrafted = build_feature_matrix(pd.Series([url]))
    expected_columns = artifact.get("feature_columns") or list(handcrafted.columns)
    handcrafted = handcrafted.reindex(columns=expected_columns, fill_value=0.0)
    numeric = artifact["scaler"].transform(handcrafted)
    text = artifact["vectorizer"].transform(pd.Series([url]).astype(str).str.lower())
    return hstack([numeric, text]).tocsr()


def _attack_probability(model, X) -> float:
    attack_index = list(model.classes_).index(1)
    return float(model.predict_proba(X)[0][attack_index])


def _url_result(
    status: str,
    confidence: float,
    attack_type: str,
    detection_mode: str,
    matched_signatures: list[str] | None = None,
) -> dict:
    is_attack = status == "Attack"
    return {
        "type": attack_type,
        "attack_type": attack_type,
        "confidence": confidence,
        "status": status,
        "severity": "High" if is_attack else "Low",
        "blocked": is_attack,
        "recommended_action": "Block and investigate the URL origin." if is_attack else "Allow and monitor.",
        "matched_signatures": matched_signatures or [],
        "prevention_tips": [
            "Inspect URL reputation and hosting provider.",
            "Enable URL filtering at the edge for known malicious domains.",
        ],
        "detection_mode": detection_mode,
        "message": "URL classification completed.",
    }


def _log_url_prediction(url: str, result: dict, prob_attack: float) -> None:
    log_path = Path(__file__).resolve().parent.parent / "instance" / "url_predictions.csv"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    file_exists = log_path.exists()
    with log_path.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["timestamp", "url", "status", "type", "confidence", "prob_attack", "detection_mode"],
        )
        if not file_exists:
            writer.writeheader()
        writer.writerow(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "url": url,
                "status": result.get("status"),
                "type": result.get("type") or result.get("attack_type"),
                "confidence": round(float(result.get("confidence", 0.0)), 6),
                "prob_attack": round(prob_attack, 6),
                "detection_mode": result.get("detection_mode"),
            }
        )


def classify_url(url: str) -> dict | None:
    rule_result = _rule_based_url_verdict(url)
    if rule_result:
        _log_url_prediction(url, rule_result, rule_result["confidence"])
        return rule_result

    if not URL_MODEL:
        return None

    model = URL_MODEL["model"]
    X_url = _build_url_vector(url, URL_MODEL)
    prob_attack = _attack_probability(model, X_url)
    configured_threshold = URL_MODEL.get("threshold", 0.3)
    threshold_file = Path(__file__).resolve().parent.parent / "instance" / "url_threshold.txt"
    threshold = float(threshold_file.read_text().strip()) if threshold_file.exists() else float(configured_threshold)
    status = "Attack" if prob_attack >= threshold else "Safe"
    result = _url_result(
        status=status,
        confidence=prob_attack if status == "Attack" else 1 - prob_attack,
        attack_type="Malicious URL" if status == "Attack" else "Safe URL",
        detection_mode=f"URL ML Classifier ({URL_MODEL.get('model_name', 'model')})",
    )
    _log_url_prediction(url, result, prob_attack)
    return result


def _calculate_anomaly_score(text: str, request_meta: dict | None = None) -> tuple[float, list[str]]:
    lowered = text.lower()
    score = 0.0
    reasons = []

    if len(text) > 1200:
        score += 0.08
        reasons.append("Oversized request payload")

    suspicious_char_count = sum(lowered.count(token) for token in ["<", ">", "'", "\"", ";", "../", "%2e"])
    if suspicious_char_count >= 4:
        score += 0.1
        reasons.append("High density of special characters and encoded control tokens")

    if lowered.count("http") >= 3:
        score += 0.05
        reasons.append("Multiple outbound URL references in a single request")

    if request_meta:
        method = (request_meta.get("method") or "").upper()
        origin = (request_meta.get("origin") or "").lower()
        host = (request_meta.get("host") or "").lower()
        has_session_cookie = request_meta.get("has_session_cookie", False)
        if method in {"POST", "PUT", "PATCH", "DELETE"} and has_session_cookie and origin and host and host not in origin:
            score += 0.24
            reasons.append("Cross-site state-changing request with active session cookie")

    return min(score, 0.45), reasons


def analyze_request(request_text: str, request_meta: dict | None = None) -> dict:
    parsed = preprocess_request(request_text)
    normalized = parsed["normalized"]
    if not normalized:
        return {
            "attack_type": "Invalid Input",
            "confidence": 0.0,
            "status": "Safe",
            "severity": "Low",
            "blocked": False,
            "recommended_action": "Provide a raw HTTP request before analysis.",
            "matched_signatures": [],
            "prevention_tips": [],
            "request_excerpt": "",
            "detection_mode": "Interactive Payload Analysis",
            "message": "Request text is empty.",
        }

    lowered = normalized
    if parsed.get("url"):
        if parsed["url"].startswith(("http://", "https://")):
            url_candidate = parsed["url"]
        elif parsed.get("host"):
            url_candidate = f"http://{parsed['host']}{parsed['url']}"
        else:
            url_candidate = ""
        if url_candidate:
            ml_result = classify_url(url_candidate)
            if ml_result:
                ml_result["request_excerpt"] = (parsed["raw"][:180] + ("..." if len(parsed["raw"]) > 180 else ""))
                return ml_result
    findings = []
    prevention_tips = []
    matched_signatures = []

    for rule in ATTACK_PATTERNS:
        rule_matches = [
            pattern for pattern in rule["patterns"] if re.search(pattern, lowered, flags=re.IGNORECASE)
        ]
        if not rule_matches:
            continue

        findings.append(rule)
        matched_signatures.extend(rule_matches)
        prevention_tips.extend(rule["prevention"])

    anomaly_score, anomaly_reasons = _calculate_anomaly_score(normalized, request_meta=request_meta)
    excerpt = normalized[:180] + ("..." if len(normalized) > 180 else "")
    detection_mode = "Real-Time HTTP Firewall" if (request_meta or {}).get("mode") == "live" else "Interactive Payload Analysis"

    if findings:
        highest_rule = max(findings, key=lambda item: (SEVERITY_SCORE[item["severity"]], item["confidence"]))
        confidence = min(highest_rule["confidence"] + anomaly_score, 0.99)
        blocked = SEVERITY_SCORE[highest_rule["severity"]] >= 3 or confidence >= 0.9
        status = "Attack" if blocked else "Suspicious"
        attack_type = highest_rule["type"] if len(findings) == 1 else "Multiple Attack Indicators"
        message = "The request matched known attack signatures and was scored as hostile by the detection engine."
        if anomaly_reasons:
            message += f" Additional risk factors: {', '.join(anomaly_reasons)}."

        return {
            "attack_type": attack_type,
            "confidence": confidence,
            "status": status,
            "severity": highest_rule["severity"],
            "blocked": blocked,
            "recommended_action": highest_rule["recommended_action"],
            "matched_signatures": matched_signatures,
            "prevention_tips": list(dict.fromkeys(prevention_tips)),
            "request_excerpt": excerpt,
            "detection_mode": detection_mode,
            "message": message,
        }

    baseline_confidence = 0.68 + anomaly_score
    if baseline_confidence >= 0.82:
        return {
            "attack_type": "Behavioral Anomaly",
            "confidence": baseline_confidence,
            "status": "Suspicious",
            "severity": "Medium",
            "blocked": False,
            "recommended_action": "Allow cautiously, increase monitoring, and review the request context for abuse patterns.",
            "matched_signatures": anomaly_reasons,
            "prevention_tips": [
                "Keep request logging enabled for later forensic review.",
                "Apply baseline validation and authentication controls.",
                "Introduce anomaly thresholds and rate limiting for repeated probes.",
            ],
            "request_excerpt": excerpt,
            "detection_mode": detection_mode,
            "message": "No hard signature matched, but the request exhibited anomalous behavior patterns.",
        }

    return {
        "attack_type": "No Threat Detected",
        "confidence": baseline_confidence,
        "status": "Safe",
        "severity": "Low",
        "blocked": False,
        "recommended_action": "Allow the request, continue monitoring, and retain the event for audit review.",
        "matched_signatures": [],
        "prevention_tips": [
            "Keep request logging enabled for later forensic review.",
            "Apply baseline validation and authentication controls.",
        ],
        "request_excerpt": excerpt,
        "detection_mode": detection_mode,
        "message": "No known attack signature was found in the request.",
    }
