"""AI detection core — a from-scratch logistic-regression classifier.

Written in pure Python on purpose:
  * nothing to install, so the confusion matrix reproduces anywhere, and
  * we own every weight, so each decision gets an **evidence-backed
    explanation** (weight x feature value per signal) — not just a confidence
    score. That directly satisfies the handout's XAI requirement.

The classifier, scaler, metrics and explanation all live here so the detection
story can be defended end-to-end from one file.
"""
from __future__ import annotations

import json
import math
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

from .features import FEATURE_NAMES, FEATURE_DESCRIPTIONS, vector_from_dict


# --------------------------------------------------------------------------- #
# standardisation
# --------------------------------------------------------------------------- #
class StandardScaler:
    def __init__(self):
        self.means: list[float] = []
        self.stds: list[float] = []

    def fit(self, X: list[list[float]]) -> "StandardScaler":
        n, d = len(X), len(X[0])
        self.means = [sum(row[j] for row in X) / n for j in range(d)]
        self.stds = []
        for j in range(d):
            var = sum((row[j] - self.means[j]) ** 2 for row in X) / n
            self.stds.append(math.sqrt(var) or 1.0)
        return self

    def transform_one(self, x: list[float]) -> list[float]:
        return [(x[j] - self.means[j]) / self.stds[j] for j in range(len(x))]

    def transform(self, X: list[list[float]]) -> list[list[float]]:
        return [self.transform_one(x) for x in X]


def _sigmoid(z: float) -> float:
    if z < -60:
        return 0.0
    if z > 60:
        return 1.0
    return 1.0 / (1.0 + math.exp(-z))


# --------------------------------------------------------------------------- #
# logistic regression
# --------------------------------------------------------------------------- #
class LogisticRegression:
    def __init__(self, lr: float = 0.1, epochs: int = 500, l2: float = 1e-3):
        self.lr = lr
        self.epochs = epochs
        self.l2 = l2
        self.w: list[float] = []
        self.b: float = 0.0

    def fit(self, X: list[list[float]], y: list[int]) -> "LogisticRegression":
        n, d = len(X), len(X[0])
        self.w = [0.0] * d
        self.b = 0.0
        for _ in range(self.epochs):
            gw = [0.0] * d
            gb = 0.0
            for xi, yi in zip(X, y):
                pred = _sigmoid(sum(self.w[j] * xi[j] for j in range(d)) + self.b)
                err = pred - yi
                for j in range(d):
                    gw[j] += err * xi[j]
                gb += err
            for j in range(d):
                self.w[j] -= self.lr * (gw[j] / n + self.l2 * self.w[j])
            self.b -= self.lr * (gb / n)
        return self

    def proba_one(self, x: list[float]) -> float:
        return _sigmoid(sum(self.w[j] * x[j] for j in range(len(x))) + self.b)


# --------------------------------------------------------------------------- #
# metrics
# --------------------------------------------------------------------------- #
@dataclass
class ConfusionMatrix:
    tp: int
    tn: int
    fp: int
    fn: int

    @property
    def accuracy(self) -> float:
        total = self.tp + self.tn + self.fp + self.fn
        return (self.tp + self.tn) / total if total else 0.0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def false_positive_rate(self) -> float:
        return self.fp / (self.fp + self.tn) if (self.fp + self.tn) else 0.0

    def report(self) -> dict:
        return {
            "confusion_matrix": asdict(self),
            "accuracy": round(self.accuracy, 4),
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
        }


# --------------------------------------------------------------------------- #
# detector = scaler + model + explanation
# --------------------------------------------------------------------------- #
@dataclass
class Detection:
    is_attack: bool
    score: float
    threshold: float
    top_evidence: list[dict]   # XAI: [{feature, value, contribution, description}]


class Detector:
    def __init__(self, threshold: float = 0.5):
        self.scaler = StandardScaler()
        self.model = LogisticRegression()
        self.threshold = threshold

    def train(self, rows: list[dict]) -> "Detector":
        X = [vector_from_dict(r) for r in rows]
        y = [int(r["label"]) for r in rows]
        self.scaler.fit(X)
        self.model.fit(self.scaler.transform(X), y)
        return self

    def _explain(self, scaled: list[float], raw: dict) -> list[dict]:
        contribs = []
        for j, name in enumerate(FEATURE_NAMES):
            contribs.append({
                "feature": name,
                "value": round(float(raw.get(name, 0.0)), 3),
                "contribution": round(self.model.w[j] * scaled[j], 4),
                "description": FEATURE_DESCRIPTIONS[name],
            })
        contribs.sort(key=lambda c: abs(c["contribution"]), reverse=True)
        return contribs[:4]

    def predict(self, features: dict) -> Detection:
        x = vector_from_dict(features)
        scaled = self.scaler.transform_one(x)
        score = self.model.proba_one(scaled)
        return Detection(
            is_attack=score >= self.threshold,
            score=round(score, 4),
            threshold=self.threshold,
            top_evidence=self._explain(scaled, features),
        )

    def evaluate(self, test_rows: list[dict]) -> ConfusionMatrix:
        tp = tn = fp = fn = 0
        for r in test_rows:
            pred = self.predict(r).is_attack
            actual = bool(r["label"])
            if pred and actual:
                tp += 1
            elif pred and not actual:
                fp += 1
            elif not pred and actual:
                fn += 1
            else:
                tn += 1
        return ConfusionMatrix(tp=tp, tn=tn, fp=fp, fn=fn)

    # persistence (so the live pipeline loads a trained model)
    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps({
            "threshold": self.threshold,
            "scaler": {"means": self.scaler.means, "stds": self.scaler.stds},
            "model": {"w": self.model.w, "b": self.model.b},
            "features": FEATURE_NAMES,
        }, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "Detector":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        det = cls(threshold=data["threshold"])
        det.scaler.means = data["scaler"]["means"]
        det.scaler.stds = data["scaler"]["stds"]
        det.model.w = data["model"]["w"]
        det.model.b = data["model"]["b"]
        return det
