"""Data models and enumerations for PromptGuard."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


# ──────────────────────────────────────────────────────────────────────────────
# Enumerations
# ──────────────────────────────────────────────────────────────────────────────


class RiskLevel(str, Enum):
    """Categorised risk level returned by the classifier."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Intent(str, Enum):
    """Detected intent of the analysed prompt."""

    QUESTION = "question"
    INSTRUCTION = "instruction"
    CONVERSATION = "conversation"
    JAILBREAK = "jailbreak"
    INJECTION = "injection"
    UNKNOWN = "unknown"


class Sentiment(str, Enum):
    """Detected sentiment of the analysed prompt."""

    POSITIVE = "positive"
    NEUTRAL = "neutral"
    NEGATIVE = "negative"


class SanitizationStrategy(str, Enum):
    """Strategy controlling how aggressively a prompt is sanitised."""

    CONSERVATIVE = "conservative"  # Apply all pattern groups
    BALANCED = "balanced"          # Critical + encoding + context patterns
    MINIMAL = "minimal"            # Critical patterns only


# ──────────────────────────────────────────────────────────────────────────────
# Data classes
# ──────────────────────────────────────────────────────────────────────────────


@dataclass
class RiskScore:
    """Result of a single-prompt security analysis.

    Attributes:
        is_malicious: ``True`` when the model probability exceeds the
            configured threshold.
        probability: Malicious probability in ``[0.0, 1.0]`` from the model.
        risk_level: Coarse-grained :class:`RiskLevel` derived from
            *probability*.
        confidence: Distance from the decision boundary, scaled to
            ``[0.0, 1.0]``.
        explanation: Human-readable summary with evidence.
        metadata: Optional dict containing per-analyser results (sentiment,
            intent, keywords, attack_patterns) when ``enable_analysis=True``.
    """

    is_malicious: bool
    probability: float
    risk_level: RiskLevel
    confidence: float
    explanation: str
    metadata: Optional[Dict[str, Any]] = None

    def __str__(self) -> str:
        """Return a concise string representation."""
        status = "MALICIOUS" if self.is_malicious else "BENIGN"
        return (
            f"RiskScore(status={status}, "
            f"probability={self.probability:.3f}, "
            f"risk_level={self.risk_level.value})"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dictionary."""
        return {
            "is_malicious": self.is_malicious,
            "probability": self.probability,
            "risk_level": self.risk_level.value,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "metadata": self.metadata or {},
        }


@dataclass
class SanitizationResult:
    """Outcome of a single prompt sanitisation operation.

    Attributes:
        original: The original (pre-sanitisation) prompt text.
        sanitized: The cleaned prompt text.
        was_modified: ``True`` when *sanitized* differs from *original*.
        removed_patterns: Fragments of text that were matched and removed or
            replaced.
        strategy: The :class:`SanitizationStrategy` that was applied.
        confidence: Estimated confidence that the sanitised prompt is safe
            (``[0.0, 1.0]``).
        risk_reduction: Estimated reduction in risk (``[0.0, 1.0]``).
    """

    original: str
    sanitized: str
    was_modified: bool
    removed_patterns: List[str]
    strategy: SanitizationStrategy
    confidence: float
    risk_reduction: float

    def __str__(self) -> str:
        """Return a concise string representation."""
        status = "MODIFIED" if self.was_modified else "UNCHANGED"
        return (
            f"SanitizationResult(status={status}, "
            f"patterns_removed={len(self.removed_patterns)}, "
            f"strategy={self.strategy.value})"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dictionary."""
        return {
            "original": self.original,
            "sanitized": self.sanitized,
            "was_modified": self.was_modified,
            "removed_patterns": self.removed_patterns,
            "strategy": self.strategy.value,
            "confidence": self.confidence,
            "risk_reduction": self.risk_reduction,
        }


@dataclass
class SanitizeResponse:
    """Typed result returned by :meth:`PromptGuard.sanitize`.

    Attributes:
        sanitization: Detailed sanitisation outcome.
        original_analysis: :class:`RiskScore` for the original prompt.
        sanitized_analysis: :class:`RiskScore` for the sanitised prompt, or
            ``None`` when *analyze_after* was ``False`` or the prompt was not
            modified.
        risk_before: Malicious probability of the original prompt.
        risk_after: Malicious probability after sanitisation, or ``None``.
        risk_reduction: Difference ``risk_before - risk_after`` (or ``0.0``
            when the prompt was unchanged).
    """

    sanitization: SanitizationResult
    original_analysis: RiskScore
    sanitized_analysis: Optional[RiskScore]
    risk_before: float
    risk_after: Optional[float]
    risk_reduction: float
