"""Session risk scoring: a simple, transparent weighted model.

Deliberately not machine learning — an auditor must be able to recompute the
score by hand from the findings table. Score = sum of severity weights over
recorded findings and policy violations (policy warns count half).
"""

from __future__ import annotations

from enum import StrEnum

from aire.core.types import Severity

DEFAULT_WEIGHTS: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 1.0,
    Severity.MEDIUM: 3.0,
    Severity.HIGH: 7.0,
    Severity.CRITICAL: 15.0,
}

#: Policy results with verdict "warn" contribute at this fraction of weight.
WARN_FACTOR = 0.5


class RiskLevel(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


_THRESHOLDS: list[tuple[float, RiskLevel]] = [
    (15.0, RiskLevel.CRITICAL),
    (7.0, RiskLevel.HIGH),
    (3.0, RiskLevel.MEDIUM),
    (0.0, RiskLevel.LOW),
]


def score_to_level(score: float) -> RiskLevel:
    if score <= 0:
        return RiskLevel.NONE
    for threshold, level in _THRESHOLDS:
        if score >= threshold:
            return level
    return RiskLevel.LOW


def weight_for(severity: Severity | str, *, warn: bool = False) -> float:
    weight = DEFAULT_WEIGHTS[Severity(severity)]
    return weight * WARN_FACTOR if warn else weight
