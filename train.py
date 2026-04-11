from __future__ import annotations

import argparse
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from imblearn.over_sampling import RandomOverSampler, SMOTE
from scipy.sparse import hstack
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, f1_score, recall_score
from sklearn.model_selection import GridSearchCV, StratifiedKFold, train_test_split
from sklearn.preprocessing import StandardScaler

from app.url_features import build_feature_matrix

try:
    from xgboost import XGBClassifier
except ImportError:  # pragma: no cover - optional dependency
    XGBClassifier = None


ATTACK_THRESHOLD = 0.30


def build_combined_features(
    urls: pd.Series,
    vectorizer: TfidfVectorizer,
    scaler: StandardScaler,
    fit: bool = False,
):
    handcrafted = build_feature_matrix(urls)
    numeric = scaler.fit_transform(handcrafted) if fit else scaler.transform(handcrafted)
    text = vectorizer.fit_transform(urls.astype(str).str.lower()) if fit else vectorizer.transform(urls.astype(str).str.lower())
    return hstack([numeric, text]).tocsr(), list(handcrafted.columns)


def _build_sampler(y_train: pd.Series):
    value_counts = y_train.value_counts()
    minority = int(value_counts.min())
    if minority < 2:
        return RandomOverSampler(random_state=42)
    return SMOTE(random_state=42, k_neighbors=min(5, minority - 1))


def _candidate_models() -> dict[str, tuple[object, dict[str, list]]]:
    models: dict[str, tuple[object, dict[str, list]]] = {
        "logistic_regression": (
            LogisticRegression(max_iter=2000, class_weight="balanced", random_state=42),
            {
                "C": [0.1, 1.0, 3.0],
                "solver": ["liblinear"],
            },
        ),
        "random_forest": (
            RandomForestClassifier(random_state=42, class_weight="balanced", n_jobs=1),
            {
                "n_estimators": [100, 300],
                "max_depth": [None, 8, 16],
                "min_samples_leaf": [1, 2],
            },
        ),
    }

    if XGBClassifier is not None:
        models["xgboost"] = (
            XGBClassifier(
                objective="binary:logistic",
                eval_metric="logloss",
                random_state=42,
                n_jobs=1,
                scale_pos_weight=1,
            ),
            {
                "n_estimators": [100, 300],
                "max_depth": [3, 5],
                "learning_rate": [0.03, 0.1],
            },
        )
    else:
        print("XGBoost is not installed; skipping XGBoost candidate.")

    return models


def _attack_probabilities(model, X) -> np.ndarray:
    attack_index = list(model.classes_).index(1)
    return model.predict_proba(X)[:, attack_index]


def _threshold_predictions(probs: np.ndarray, threshold: float) -> np.ndarray:
    return (probs >= threshold).astype(int)


def train_model(data_path: Path, model_path: Path, threshold: float) -> None:
    df = pd.read_csv(data_path)
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("Dataset must contain 'url' and 'label' columns.")

    df = df.dropna(subset=["url", "label"]).copy()
    df["url"] = df["url"].astype(str).str.strip()
    df["label"] = df["label"].astype(str).str.strip().str.lower().map({"safe": 0, "attack": 1, "malicious": 1})
    df = df.dropna(subset=["label"])
    y = df["label"].astype(int)
    urls = df["url"]

    print("Class distribution:")
    print(y.value_counts().rename(index={0: "Safe", 1: "Attack"}))

    X_train_urls, X_test_urls, y_train, y_test = train_test_split(
        urls,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y,
    )

    vectorizer = TfidfVectorizer(analyzer="char", ngram_range=(2, 5), min_df=1)
    scaler = StandardScaler(with_mean=False)
    X_train, feature_columns = build_combined_features(X_train_urls, vectorizer, scaler, fit=True)
    X_test, _ = build_combined_features(X_test_urls, vectorizer, scaler, fit=False)

    sampler = _build_sampler(y_train)
    X_res, y_res = sampler.fit_resample(X_train, y_train)
    cv_splits = min(3, int(pd.Series(y_res).value_counts().min()))
    cv = StratifiedKFold(n_splits=max(cv_splits, 2), shuffle=True, random_state=42)

    results = []
    for name, (estimator, grid) in _candidate_models().items():
        search = GridSearchCV(
            estimator=estimator,
            param_grid=grid,
            scoring="f1",
            cv=cv,
            n_jobs=1,
            error_score="raise",
        )
        search.fit(X_res, y_res)
        probs = _attack_probabilities(search.best_estimator_, X_test)
        preds = _threshold_predictions(probs, threshold)
        result = {
            "name": name,
            "model": search.best_estimator_,
            "best_params": search.best_params_,
            "f1": f1_score(y_test, preds, zero_division=0),
            "attack_recall": recall_score(y_test, preds, pos_label=1, zero_division=0),
            "probs": probs,
            "preds": preds,
        }
        results.append(result)
        print(f"\n{name} best params: {search.best_params_}")
        print(f"{name} test attack recall @ threshold {threshold:.2f}: {result['attack_recall']:.3f}")
        print(f"{name} test F1 @ threshold {threshold:.2f}: {result['f1']:.3f}")

    best = max(results, key=lambda item: (item["f1"], item["attack_recall"]))
    print(f"\nSelected model: {best['name']}")
    print("\nClassification report:")
    print(classification_report(y_test, best["preds"], target_names=["Safe", "Attack"], zero_division=0))
    print("\nConfusion matrix:")
    print(confusion_matrix(y_test, best["preds"]))
    print("\nSample probabilities:")
    print(np.round(best["probs"], 3))

    artifact = {
        "model": best["model"],
        "model_name": best["name"],
        "vectorizer": vectorizer,
        "scaler": scaler,
        "feature_columns": feature_columns,
        "threshold": threshold,
        "label_map": {"Safe": 0, "Attack": 1},
        "best_params": best["best_params"],
    }
    model_path.parent.mkdir(parents=True, exist_ok=True)
    with model_path.open("wb") as handle:
        pickle.dump(artifact, handle)
    print(f"\nSaved model, vectorizer, and scaler to {model_path}")

    _debug_examples(artifact)


def _debug_examples(artifact: dict) -> None:
    examples = pd.Series(
        [
            "https://www.wikipedia.org/wiki/Machine_learning",
            "https://accounts.google.com/signin",
            "http://example.com/login.php?user=admin' OR 1=1--",
            "http://bad.example.com/search?q=<script>alert(1)</script>",
            "http://free-bonus-account-verify.example.net/update",
        ]
    )
    X_examples, _ = build_combined_features(examples, artifact["vectorizer"], artifact["scaler"], fit=False)
    probs = _attack_probabilities(artifact["model"], X_examples)
    preds = _threshold_predictions(probs, artifact["threshold"])
    print("\nGeneralization smoke tests:")
    for url, prob, pred in zip(examples, probs, preds):
        label = "Attack" if pred == 1 else "Safe"
        print(f"{url} => {label} (prob_attack={prob:.3f})")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train production-style malicious URL classifier.")
    parser.add_argument("--data", default="data/url_dataset.csv", help="Path to dataset CSV.")
    parser.add_argument("--model-out", default="models/url_classifier.pkl", help="Path to save pickle artifact.")
    parser.add_argument("--threshold", type=float, default=ATTACK_THRESHOLD, help="Attack threshold for predict_proba output.")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    train_model(Path(args.data), Path(args.model_out), args.threshold)
