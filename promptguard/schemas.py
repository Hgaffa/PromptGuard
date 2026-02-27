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
    """Result of a single-prompt security analysis."""

    is_malicious: bool
    """``True`` when the model probability exceeds the configured threshold."""
    probability: float
    """Malicious probability in ``[0.0, 1.0]`` from the model."""
    risk_level: RiskLevel
    """Coarse-grained :class:`RiskLevel` derived from *probability*."""
    confidence: float
    """Distance from the decision boundary, scaled to ``[0.0, 1.0]``."""
    explanation: str
    """Human-readable summary with evidence."""
    metadata: Optional[Dict[str, Any]] = None
    """Optional per-analyser detail (sentiment, intent, keywords, attack_patterns)."""

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
    """Outcome of a single prompt sanitisation operation."""

    original: str
    """The original (pre-sanitisation) prompt text."""
    sanitized: str
    """The cleaned prompt text."""
    was_modified: bool
    """``True`` when *sanitized* differs from *original*."""
    removed_patterns: List[str]
    """Fragments of text that were matched and removed or replaced."""
    strategy: SanitizationStrategy
    """The :class:`SanitizationStrategy` that was applied."""
    confidence: float
    """Estimated confidence that the sanitised prompt is safe (``[0.0, 1.0]``)."""
    risk_reduction: float
    """Estimated reduction in risk (``[0.0, 1.0]``)."""

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
    """Typed result returned by :meth:`PromptGuard.sanitize`."""

    sanitization: SanitizationResult
    """Detailed sanitisation outcome."""
    original_analysis: RiskScore
    """:class:`RiskScore` for the original prompt."""
    sanitized_analysis: Optional[RiskScore]
    """:class:`RiskScore` for the sanitised prompt, or ``None`` when *analyze_after* was ``False``."""
    risk_before: float
    """Malicious probability of the original prompt."""
    risk_after: Optional[float]
    """Malicious probability after sanitisation, or ``None``."""
    risk_reduction: float
    """Difference ``risk_before - risk_after`` (``0.0`` when unchanged)."""
