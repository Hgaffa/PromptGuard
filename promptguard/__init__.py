"""PromptGuard: production-ready library for detecting malicious LLM prompts."""

__version__ = "0.1.2"
__author__ = "Hasanain Ghafoor"
__email__ = "hgaffa@gmail.com"

# Core
from .core import PromptGuard

# Schemas — enums and data classes (single source of truth)
from .schemas import (
    RiskLevel,
    RiskScore,
    Intent,
    Sentiment,
    SanitizationStrategy,
    SanitizationResult,
    SanitizeResponse,
)

# Configuration
from .config import PromptGuardConfig

# Cache
from .cache import PromptCache

# Exceptions
from .exceptions import (
    PromptGuardError,
    ModelLoadError,
    ValidationError,
    ConfigurationError,
    InferenceError,
)

# Analysers
from .analyzers import (
    SentimentAnalyzer,
    IntentClassifier,
    KeywordExtractor,
    AttackPatternDetector,
)

# Sanitisers
from .sanitizers import PromptSanitizer, AdvancedSanitizer

# Utilities
from .utils import (
    summarize_results,
    filter_by_risk_level,
    get_most_dangerous,
    export_to_csv,
    results_to_dataframe,
)

# Logging helpers
from .logging_config import setup_logging, disable_transformers_logging

__all__ = [
    # Core
    "PromptGuard",
    # Schemas
    "RiskScore",
    "RiskLevel",
    "Intent",
    "Sentiment",
    "SanitizationStrategy",
    "SanitizationResult",
    "SanitizeResponse",
    # Config
    "PromptGuardConfig",
    # Cache
    "PromptCache",
    # Exceptions
    "PromptGuardError",
    "ModelLoadError",
    "ValidationError",
    "ConfigurationError",
    "InferenceError",
    # Analysers
    "SentimentAnalyzer",
    "IntentClassifier",
    "KeywordExtractor",
    "AttackPatternDetector",
    # Sanitisers
    "PromptSanitizer",
    "AdvancedSanitizer",
    # Utilities
    "summarize_results",
    "filter_by_risk_level",
    "get_most_dangerous",
    "export_to_csv",
    "results_to_dataframe",
    # Logging
    "setup_logging",
    "disable_transformers_logging",
]
