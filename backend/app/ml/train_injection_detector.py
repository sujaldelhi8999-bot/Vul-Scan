"""Training CLI for the injection detector.

Usage:
    python -m app.ml.train_injection_detector [--samples 5000] [--seed 42]

Trains a char-level TF-IDF + RandomForest binary classifier on generated
benign/SQLi/XSS payloads and persists artifacts into the ML model directory
(``ML_MODEL_DIR`` or ``app/ml/models``). Set ML_ENABLED=true to load them.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any


def main(
    samples: int = 5000, seed: int = 42, output: str | None = None
) -> dict[str, Any]:
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics import classification_report
    from sklearn.model_selection import train_test_split

    from app.ml.base import ModelRegistry
    from app.ml.dataset import build_injection_dataset

    rows = build_injection_dataset(n=samples, seed=seed)
    texts = [r["payload"] for r in rows]
    labels = [r["label"] for r in rows]

    vectorizer = TfidfVectorizer(ngram_range=(1, 3), max_features=5000, analyzer="char")
    features = vectorizer.fit_transform(texts)

    x_train, x_test, y_train, y_test = train_test_split(
        features, labels, test_size=0.2, random_state=seed, stratify=labels
    )

    classifier = RandomForestClassifier(
        n_estimators=200, max_depth=20, random_state=seed
    )
    classifier.fit(x_train, y_train)

    y_pred = classifier.predict(x_test)
    report = classification_report(y_test, y_pred, output_dict=True)

    vectorizer_path = ModelRegistry.put("injection_vectorizer", vectorizer)
    detector_path = ModelRegistry.put("injection_detector", classifier)

    return {
        "report": report,
        "samples": len(rows),
        "models": {
            "injection_vectorizer": str(vectorizer_path),
            "injection_detector": str(detector_path),
        },
    }


def _cli() -> int:
    parser = argparse.ArgumentParser(description="Train the ML injection detector")
    parser.add_argument("--samples", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--json", action="store_true", help="Emit results as JSON")
    args = parser.parse_args()

    result = main(samples=args.samples, seed=args.seed)
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        report = result["report"]
        print(f"Trained on {result['samples']} samples")
        print(f"Accuracy: {report.get('accuracy', 0):.4f}")
        print(f"Precision: {report['weighted avg']['precision']:.4f}")
        print(f"Recall: {report['weighted avg']['recall']:.4f}")
        print(f"F1: {report['weighted avg']['f1-score']:.4f}")
        for name, path in result["models"].items():
            print(f"{name}: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(_cli())
