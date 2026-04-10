from __future__ import annotations

import argparse
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse, parse_qs

import joblib
import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE, RandomOverSampler
from imblearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler


SUSPICIOUS_KEYWORDS = [
    "login",
    "admin",
    "verify",
    "free",
    "update",
    "secure",
    "account",
    "token",
    "pay",
    "bank",
    "confirm",
    "signin",
    "reset",
]


def extract_url_features(url: str) -> dict[str, float]:
    parsed = urlparse(url)
    path = parsed.path or ""
    query = parsed.query or ""
    netloc = parsed.netloc or ""
    full = url.lower()
    special_chars = sum(full.count(ch) for ch in ["@", "?", "&", "=", "-", "_", "%", "."])

    query_params = parse_qs(query)
    suspicious_hits = sum(1 for keyword in SUSPICIOUS_KEYWORDS if keyword in full)

    return {
        "length": len(full),
        "host_length": len(netloc),
        "path_length": len(path),
        "query_length": len(query),
        "num_digits": sum(ch.isdigit() for ch in full),
        "num_dots": full.count("."),
        "num_slashes": full.count("/"),
        "num_special": special_chars,
        "num_query_params": len(query_params),
        "has_login": int("login" in full),
        "has_admin": int("admin" in full),
        "has_verify": int("verify" in full),
        "has_free": int("free" in full),
        "has_update": int("update" in full),
        "has_secure": int("secure" in full),
        "has_account": int("account" in full),
        "has_token": int("token" in full),
        "has_pay": int("pay" in full),
        "has_bank": int("bank" in full),
        "has_confirm": int("confirm" in full),
        "suspicious_word_count": suspicious_hits,
        "tld_length": len(parsed.netloc.split(".")[-1]) if "." in parsed.netloc else 0,
    }


def build_feature_matrix(urls: Iterable[str]) -> pd.DataFrame:
    rows = [extract_url_features(url) for url in urls]
    return pd.DataFrame(rows)


def train_model(data_path: Path, model_path: Path, model_type: str) -> None:
    df = pd.read_csv(data_path)
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("Dataset must contain 'url' and 'label' columns.")

    df["label"] = df["label"].str.strip().str.lower().map({"safe": 0, "attack": 1})
    df = df.dropna(subset=["label", "url"])

    print("Class distribution:")
    print(df["label"].value_counts())

    X = build_feature_matrix(df["url"].astype(str))
    y = df["label"].astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    if model_type == "logistic":
        classifier = LogisticRegression(
            max_iter=500,
            class_weight={0: 1, 1: 5},
        )
        sampler = _build_sampler(y_train)
        pipeline = Pipeline(
            steps=[
                ("scaler", StandardScaler()),
                ("sampler", sampler),
                ("model", classifier),
            ]
        )
    else:
        classifier = RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            class_weight="balanced",
        )
        sampler = _build_sampler(y_train)
        pipeline = Pipeline(
            steps=[
                ("sampler", sampler),
                ("model", classifier),
            ]
        )

    pipeline.fit(X_train, y_train)
    preds = pipeline.predict(X_test)
    probs = pipeline.predict_proba(X_test)[:, 1]

    print("\nClassification report:")
    print(classification_report(y_test, preds, target_names=["Safe", "Attack"]))
    print("\nConfusion matrix:")
    print(confusion_matrix(y_test, preds))
    print("\nSample probabilities (first 10):")
    print(np.round(probs[:10], 3))

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(
        {
            "pipeline": pipeline,
            "feature_columns": list(X.columns),
            "model_type": model_type,
        },
        model_path,
    )
    print(f"\nSaved model to {model_path}")

    _debug_examples(pipeline, X.columns)


def _build_sampler(y_train: pd.Series):
    value_counts = y_train.value_counts()
    minority = value_counts.min()
    if minority < 2:
        return RandomOverSampler(random_state=42)
    k_neighbors = min(5, minority - 1)
    return SMOTE(random_state=42, k_neighbors=k_neighbors)


def _debug_examples(pipeline, feature_columns: Iterable[str]) -> None:
    examples = [
        "https://example.com",
        "https://example.com/login?user=admin' OR 1=1 --",
        "http://urlfiltering.paloaltonetworks.com/test-phishing",
    ]
    example_features = build_feature_matrix(examples)
    example_features = example_features[list(feature_columns)]
    probs = pipeline.predict_proba(example_features)[:, 1]
    preds = pipeline.predict(example_features)
    print("\nDebug predictions:")
    for url, prob, pred in zip(examples, probs, preds):
        label = "Attack" if pred == 1 else "Safe"
        print(f"{url} => {label} (prob_attack={prob:.3f})")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train URL classification model.")
    parser.add_argument("--data", default="data/url_dataset.csv", help="Path to dataset CSV.")
    parser.add_argument("--model-out", default="models/url_classifier.pkl", help="Path to save model.")
    parser.add_argument("--model-type", choices=["logistic", "rf"], default="rf")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    train_model(Path(args.data), Path(args.model_out), args.model_type)
