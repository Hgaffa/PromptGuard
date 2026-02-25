"""Data models for PromptGuard analysis results."""

from typing import Optional, Dict, Any
from dataclasses import dataclass
from enum import Enum


class RiskLevel(str, Enum):
    """Risk level classification."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Intent(str, Enum):
    """Prompt intent classification."""
    QUESTION = "question"
    INSTRUCTION = "instruction"
    CONVERSATION = "conversation"
    JAILBREAK = "jailbreak"
    INJECTION = "injection"
    UNKNOWN = "unknown"


class Sentiment(str, Enum):
    """Sentiment classification."""
    POSITIVE = "positive"
    NEUTRAL = "neutral"
    NEGATIVE = "negative"

class SanitizationStrategy(str, Enum):
    """Sanitization strategy levels."""
    CONSERVATIVE = "conservative"
    BALANCED = "balanced"
    MINIMAL = "minimal"


@dataclass
class RiskScore:
    """
    Result of prompt security analysis.

    Attributes:
        is_malicious: Whether the prompt is classified as malicious
        probability: Probability that the prompt is malicious (0.0 to 1.0)
        risk_level: Categorized risk level (low/medium/high)
        confidence: Model confidence in the prediction
        explanation: Human-readable explanation of the classification
        metadata: Additional analysis metadata (sentiment, intent, keywords, etc.)
    """
    is_malicious: bool
    probability: float
    risk_level: RiskLevel
    confidence: float
    explanation: str
    metadata: Optional[Dict[str, Any]] = None

    def __str__(self) -> str:
        """String representation of risk score."""
        status = "MALICIOUS" if self.is_malicious else "BENIGN"
        return (
            f"RiskScore(status={status}, "
            f"probability={self.probability:.3f}, "
            f"risk_level={self.risk_level.value})"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "is_malicious": self.is_malicious,
            "probability": self.probability,
            "risk_level": self.risk_level.value,
            "confidence": self.confidence,
            "explanation": self.explanation,
            "metadata": self.metadata or {}
        }
