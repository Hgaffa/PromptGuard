"""Type stubs for the promptguard public API."""

from typing import Any, Dict, List, Optional, Tuple

from .schemas import (
    Intent,
    RiskLevel,
    RiskScore,
    SanitizationResult,
    SanitizationStrategy,
    SanitizeResponse,
    Sentiment,
)
from .config import PromptGuardConfig
from .cache import PromptCache
from .exceptions import (
    ConfigurationError,
    InferenceError,
    ModelLoadError,
    PromptGuardError,
    ValidationError,
)
from .analyzers import (
    AttackPatternDetector,
    IntentClassifier,
    KeywordExtractor,
    SentimentAnalyzer,
)
from .sanitizers import AdvancedSanitizer, PromptSanitizer

__version__: str
__author__: str
__email__: str

__all__ = [
    "PromptGuard",
    # Schemas
    "RiskScore",
    "RiskLevel",
    "Intent",
    "Sentiment",
    "SanitizationStrategy",
    "SanitizationResult",
    "SanitizeResponse",
    # Config / Cache
    "PromptGuardConfig",
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
    # Logging
    "setup_logging",
    "disable_transformers_logging",
]


class PromptGuard:
    """Main classifier for detecting malicious prompts."""

    threshold: float
    device: str
    enable_analysis: bool
    enable_sanitization: bool

    def __init__(
        self,
        model_name: str = ...,
        threshold: float = ...,
        device: Optional[str] = ...,
        use_cache: bool = ...,
        cache_size: int = ...,
        cache_ttl: Optional[int] = ...,
        enable_analysis: bool = ...,
        enable_sanitization: bool = ...,
        **kwargs: Any,
    ) -> None: ...

    def analyze(self, prompt: str) -> RiskScore: ...

    def analyze_batch(
        self,
        prompts: List[str],
        batch_size: Optional[int] = ...,
        show_progress: bool = ...,
    ) -> List[Optional[RiskScore]]: ...

    def classify(
        self,
        prompt: str,
        threshold: Optional[float] = ...,
    ) -> bool: ...

    def classify_batch(
        self,
        prompts: List[str],
        threshold: Optional[float] = ...,
        show_progress: bool = ...,
    ) -> List[Optional[bool]]: ...

    def sanitize(
        self,
        prompt: str,
        strategy: SanitizationStrategy = ...,
        analyze_after: bool = ...,
    ) -> SanitizeResponse: ...

    def sanitize_if_malicious(
        self,
        prompt: str,
        strategy: SanitizationStrategy = ...,
    ) -> Tuple[str, bool]: ...

    def clear_cache(self) -> None: ...
    def cache_stats(self) -> Optional[Dict[str, Any]]: ...


def summarize_results(
    results: List[Optional[RiskScore]],
) -> Dict[str, Any]: ...


def filter_by_risk_level(
    results: List[Optional[RiskScore]],
    level: str,
) -> List[RiskScore]: ...


def get_most_dangerous(
    results: List[Optional[RiskScore]],
    top_n: int = ...,
) -> List[RiskScore]: ...


def export_to_csv(
    results: List[Optional[RiskScore]],
    prompts: List[str],
    filepath: str,
) -> None: ...


def setup_logging(level: str = ...) -> None: ...
def disable_transformers_logging() -> None: ...
