from __future__ import annotations

import math
import re
from collections import Counter
from typing import Iterable
from urllib.parse import urlparse

import pandas as pd


SUSPICIOUS_KEYWORDS = [
    "login",
    "admin",
    "verify",
    "secure",
    "update",
    "account",
    "free",
    "bonus",
]

SPECIAL_CHARACTERS = ["?", "=", "&", "%", "-"]
IP_ADDRESS_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def calculate_entropy(value: str) -> float:
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _domain_parts(netloc: str) -> list[str]:
    host = netloc.split("@")[-1].split(":")[0].lower()
    return [part for part in host.split(".") if part]


def extract_url_features(url: str) -> dict[str, float]:
    full = (url or "").strip().lower()
    parsed = urlparse(full if re.match(r"^[a-z][a-z0-9+.-]*://", full) else f"http://{full}")
    domain = parsed.hostname or parsed.netloc or ""
    path = parsed.path or ""
    parts = _domain_parts(domain)
    letters = sum(ch.isalpha() for ch in full)
    digits = sum(ch.isdigit() for ch in full)
    suspicious_keyword_hits = {keyword: int(keyword in full) for keyword in SUSPICIOUS_KEYWORDS}

    return {
        "url_length": len(full),
        "num_dots": full.count("."),
        "num_slashes": full.count("/"),
        "num_question_marks": full.count("?"),
        "num_equals": full.count("="),
        "num_ampersands": full.count("&"),
        "num_percent": full.count("%"),
        "num_hyphens": full.count("-"),
        "num_special_chars": sum(full.count(ch) for ch in SPECIAL_CHARACTERS),
        "has_ip_address": int(bool(IP_ADDRESS_PATTERN.match(domain))),
        "num_subdomains": max(len(parts) - 2, 0),
        "suspicious_keyword_count": sum(suspicious_keyword_hits.values()),
        "digit_to_letter_ratio": digits / max(letters, 1),
        "url_entropy": calculate_entropy(full),
        "domain_length": len(domain),
        "path_length": len(path),
        "domain_to_path_ratio": len(domain) / max(len(path), 1),
        **{f"kw_{keyword}": hit for keyword, hit in suspicious_keyword_hits.items()},
    }


def build_feature_matrix(urls: Iterable[str]) -> pd.DataFrame:
    return pd.DataFrame([extract_url_features(str(url)) for url in urls]).fillna(0.0)
