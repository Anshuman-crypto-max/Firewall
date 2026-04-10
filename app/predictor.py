from __future__ import annotations

import re


ATTACK_PATTERNS = [
    {
        "type": "SQL Injection",
        "patterns": [
            r"(\bunion\b\s+\bselect\b)",
            r"(\bor\b\s+1=1)",
            r"('.*--)",
            r"(\bdrop\b\s+\btable\b)",
        ],
        "confidence": 0.95,
    },
    {
        "type": "Cross-Site Scripting (XSS)",
        "patterns": [
            r"<script\b",
            r"javascript:",
            r"onerror\s*=",
            r"alert\s*\(",
        ],
        "confidence": 0.92,
    },
    {
        "type": "Command Injection",
        "patterns": [
            r"(;|\|\|)\s*(cat|ls|whoami|curl|wget|powershell|cmd)\b",
            r"`.+`",
            r"\$\(.*\)",
        ],
        "confidence": 0.9,
    },
    {
        "type": "Directory Traversal",
        "patterns": [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%252e%252e%255c",
        ],
        "confidence": 0.88,
    },
]


def analyze_request(request_text: str) -> dict:
    normalized = (request_text or "").strip()
    if not normalized:
        return {
            "attack_type": "Invalid Input",
            "confidence": 0.0,
            "status": "Safe",
            "message": "Request text is empty.",
        }

    lowered = normalized.lower()
    for rule in ATTACK_PATTERNS:
        for pattern in rule["patterns"]:
            if re.search(pattern, lowered, flags=re.IGNORECASE):
                return {
                    "attack_type": rule["type"],
                    "confidence": rule["confidence"],
                    "status": "Attack",
                    "message": "Suspicious payload matched the heuristic detector.",
                }

    confidence = 0.82 if len(normalized) > 20 else 0.74
    return {
        "attack_type": "No Threat Detected",
        "confidence": confidence,
        "status": "Safe",
        "message": "No known attack signature was found in the request.",
    }
