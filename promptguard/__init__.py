"""
PromptGuard: Production-ready library for detecting malicious LLM prompts.
"""

__version__ = "0.1.0"
__author__ = "Hasanain Ghafoor"
__email__ = "hgaffa@gmail.com"

from .core import PromptGuard
from .schemas import RiskScore, RiskLevel
from .config import PromptGuardConfig
from .exceptions import (
    PromptGuardError,
    ModelLoadError,
    ValidationError,
    ConfigurationError,
    InferenceError,
)

# Public API
__all__ = [
    "PromptGuard",
    "RiskScore",
    "RiskLevel",
    "PromptGuardConfig",
    "PromptGuardError",
    "ModelLoadError",
    "ValidationError",
    "ConfigurationError",
    "InferenceError",
]
