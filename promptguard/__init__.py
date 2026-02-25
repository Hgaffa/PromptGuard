"""
PromptGuard: Production-ready library for detecting malicious LLM prompts.
"""

__version__ = "0.1.0"
__author__ = "Your Name"
__email__ = "your.email@example.com"

# Import main classes
from .core import PromptGuard
from .schemas import RiskScore, RiskLevel, Intent, Sentiment  # Added Intent, Sentiment
from .config import PromptGuardConfig
from .cache import PromptCache
from .exceptions import (
    PromptGuardError,
    ModelLoadError,
    ValidationError,
    ConfigurationError,
    InferenceError,
)

# Import analyzers
from .analyzers import (
    SentimentAnalyzer,
    IntentClassifier,
    KeywordExtractor,
    AttackPatternDetector
)

# Import utilities
from .utils import (
    summarize_results,
    filter_by_risk_level,
    get_most_dangerous,
    export_to_csv,
    results_to_dataframe
)

# Import logging config
from .logging_config import setup_logging, disable_transformers_logging

# Define public API
__all__ = [
    # Core
    "PromptGuard",
    "RiskScore",
    "RiskLevel",
    "Intent",
    "Sentiment",
    "PromptGuardConfig",

    # Cache
    "PromptCache",

    # Analyzers
    "SentimentAnalyzer",
    "IntentClassifier",
    "KeywordExtractor",
    "AttackPatternDetector",

    # Exceptions
    "PromptGuardError",
    "ModelLoadError",
    "ValidationError",
    "ConfigurationError",
    "InferenceError",

    # Utils
    "summarize_results",
    "filter_by_risk_level",
    "get_most_dangerous",
    "export_to_csv",
    "results_to_dataframe",

    # Logging
    "setup_logging",
    "disable_transformers_logging",
]
