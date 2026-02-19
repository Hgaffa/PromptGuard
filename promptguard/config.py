"""Configuration management for PromptGuard."""

from dataclasses import dataclass
from typing import Optional


@dataclass
class PromptGuardConfig:
    """
    Configuration for PromptGuard classifier.

    Attributes:
        model_name: HuggingFace model identifier
        threshold: Classification threshold (default: 0.5)
        device: Device to run inference on ('cuda', 'cpu', or 'auto')
        max_length: Maximum sequence length for tokenization
        batch_size: Batch size for batch predictions
    """
    model_name: str = "arkaean/promptguard-distilbert"
    threshold: float = 0.5
    device: Optional[str] = "auto"
    max_length: int = 512
    batch_size: int = 32

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
