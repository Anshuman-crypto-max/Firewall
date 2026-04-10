from __future__ import annotations

import re


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
        ],
        "confidence": 0.95,
        "prevention": [
            "Use parameterized SQL queries.",
            "Validate and normalize untrusted input.",
            "Add WAF rules for common SQLi signatures.",
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
            r"alert\s*\(",
        ],
        "confidence": 0.92,
        "prevention": [
            "Escape output in templates.",
            "Use a strong Content Security Policy.",
            "Strip dangerous tags and inline handlers.",
        ],
    },
    {
        "type": "Command Injection",
        "severity": "Critical",
        "recommended_action": "Block the request immediately and inspect any shell command execution paths in the backend.",
        "patterns": [
            r"(;|\|\|)\s*(cat|ls|whoami|curl|wget|powershell|cmd)\b",
            r"`.+`",
            r"\$\(.*\)",
        ],
        "confidence": 0.9,
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
            r"origin:\s*https?://[^\\s]+",
            r"referer:\s*https?://[^\\s]+",
            r"\bcsrf\b",
            r"\bx-csrf-token\b",
            r"\bset-cookie:.*samesite=none\b",
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
            r"\b(nikto|sqlmap|nmap|acunetix|nessus)\b",
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


def analyze_request(request_text: str) -> dict:
    normalized = (request_text or "").strip()
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
            "message": "Request text is empty.",
        }

    lowered = normalized.lower()
    matched_signatures = []
    for rule in ATTACK_PATTERNS:
        for pattern in rule["patterns"]:
            if re.search(pattern, lowered, flags=re.IGNORECASE):
                matched_signatures.append(pattern)

        if matched_signatures:
            blocked = rule["severity"] in {"Critical", "High"}
            status = "Attack" if blocked or rule["confidence"] >= 0.8 else "Suspicious"
            excerpt = normalized[:180] + ("..." if len(normalized) > 180 else "")
            return {
                "attack_type": rule["type"],
                "confidence": rule["confidence"],
                "status": status,
                "severity": rule["severity"],
                "blocked": blocked,
                "recommended_action": rule["recommended_action"],
                "matched_signatures": matched_signatures,
                "prevention_tips": rule["prevention"],
                "request_excerpt": excerpt,
                "message": "Suspicious payload matched the detection engine and generated an actionable security verdict.",
            }

    confidence = 0.82 if len(normalized) > 20 else 0.74
    return {
        "attack_type": "No Threat Detected",
        "confidence": confidence,
        "status": "Safe",
        "severity": "Low",
        "blocked": False,
        "recommended_action": "Allow the request, continue monitoring, and retain the event for audit analytics.",
        "matched_signatures": [],
        "prevention_tips": [
            "Keep request logging enabled for later forensic review.",
            "Apply baseline validation and authentication controls.",
        ],
        "request_excerpt": normalized[:180] + ("..." if len(normalized) > 180 else ""),
        "message": "No known attack signature was found in the request.",
    }
