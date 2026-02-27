"""Configuration management for PromptGuard."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class PromptGuardConfig:
    """Configuration for the PromptGuard classifier."""

    model_name: str = "arkaean/promptguard-distilbert"
    """HuggingFace model identifier."""
    threshold: float = 0.5
    """Classification threshold (default: ``0.5``)."""
    device: Optional[str] = "auto"
    """Inference device: ``'cuda'``, ``'cpu'``, or ``'auto'``."""
    max_length: int = 512
    """Maximum token sequence length for the tokenizer."""
    batch_size: int = 32
    """Default batch size for :meth:`~promptguard.PromptGuard.analyze_batch`."""

    def __post_init__(self):
        """Validate configuration after initialization."""
        if not 0.0 <= self.threshold <= 1.0:
            raise ValueError(
                f"Threshold must be between 0 and 1, got {self.threshold}")

        if self.max_length <= 0:
            raise ValueError(
                f"max_length must be positive, got {self.max_length}")

        if self.batch_size <= 0:
            raise ValueError(
                f"batch_size must be positive, got {self.batch_size}")
