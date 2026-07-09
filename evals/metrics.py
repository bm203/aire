"""Shared metric helpers: confusion matrix and latency summaries."""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field


def _safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


@dataclass
class ConfusionMatrix:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    def add(self, *, predicted: bool, actual: bool) -> None:
        if actual and predicted:
            self.tp += 1
        elif actual and not predicted:
            self.fn += 1
        elif not actual and predicted:
            self.fp += 1
        else:
            self.tn += 1

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    @property
    def precision(self) -> float:
        return _safe_div(self.tp, self.tp + self.fp)

    @property
    def recall(self) -> float:
        return _safe_div(self.tp, self.tp + self.fn)

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return _safe_div(2 * p * r, p + r)

    @property
    def false_positive_rate(self) -> float:
        return _safe_div(self.fp, self.fp + self.tn)

    @property
    def accuracy(self) -> float:
        return _safe_div(self.tp + self.tn, self.total)

    def as_dict(self) -> dict[str, float | int]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "total": self.total,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "accuracy": round(self.accuracy, 4),
        }


@dataclass
class LatencySamples:
    """Collects per-item durations (milliseconds) and summarizes them."""

    samples_ms: list[float] = field(default_factory=list)

    def record(self, duration_ms: float) -> None:
        self.samples_ms.append(duration_ms)

    def _pct(self, q: float) -> float:
        if not self.samples_ms:
            return 0.0
        ordered = sorted(self.samples_ms)
        idx = min(len(ordered) - 1, int(q * len(ordered)))
        return ordered[idx]

    def as_dict(self) -> dict[str, float | int]:
        if not self.samples_ms:
            return {"count": 0}
        return {
            "count": len(self.samples_ms),
            "mean_ms": round(statistics.fmean(self.samples_ms), 4),
            "median_ms": round(statistics.median(self.samples_ms), 4),
            "p95_ms": round(self._pct(0.95), 4),
            "max_ms": round(max(self.samples_ms), 4),
        }
