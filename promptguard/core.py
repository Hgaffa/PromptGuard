"""Core PromptGuard classifier."""
import logging
from typing import Any, Dict, List, Optional, Tuple
from tqdm import tqdm
import torch
from .analyzers import (
    SentimentAnalyzer,
    IntentClassifier,
    KeywordExtractor,
    AttackPatternDetector,
)
from .sanitizers import PromptSanitizer
from .models import ModelLoader
from .schemas import (
    RiskScore,
    RiskLevel,
    Intent,
    SanitizationStrategy,
    SanitizeResponse,
)
from .exceptions import ValidationError, InferenceError
from .cache import PromptCache
from .config import PromptGuardConfig

logger = logging.getLogger(__name__)


class PromptGuard:
    """
    Main PromptGuard classifier for detecting malicious prompts.
    """

    def __init__(
        self,
        model_name: str = "arkaean/promptguard-distilbert",
        threshold: float = 0.5,
        device: Optional[str] = "auto",
        use_cache: bool = True,
        cache_size: int = 10000,
        cache_ttl: Optional[int] = 3600,
        enable_analysis: bool = True,
        enable_sanitization: bool = True,
        **kwargs
    ):
        """Initialise the PromptGuard classifier.

        Args:
            model_name: HuggingFace Hub model identifier.
            threshold: Malicious classification threshold in ``[0.0, 1.0]``.
                Prompts with a model probability at or above this value are
                classified as malicious.
            device: Device for model inference — ``"cuda"``, ``"cpu"``, or
                ``"auto"`` (selects CUDA when available).
            use_cache: Enable in-memory LRU caching of analysis results.
            cache_size: Maximum number of entries held in the cache.
            cache_ttl: Cache entry time-to-live in seconds.  Pass ``None`` to
                disable expiry.
            enable_analysis: When ``True`` (default), enables supplementary
                sentiment, intent, keyword, and attack-pattern analysis that
                enriches :class:`~promptguard.schemas.RiskScore` metadata.
            enable_sanitization: When ``True`` (default), enables the
                :meth:`sanitize` and :meth:`sanitize_if_malicious` methods.
            **kwargs: Additional options forwarded to
                :class:`~promptguard.config.PromptGuardConfig`.
        """
        # Create configuration
        self.config = PromptGuardConfig(
            model_name=model_name,
            threshold=threshold,
            device=device,
            **kwargs
        )

        # Initialize cache
        self.use_cache = use_cache
        if use_cache:
            self.cache = PromptCache(
                max_size=cache_size, ttl_seconds=cache_ttl)
            logger.info("Caching enabled")
        else:
            self.cache = None
            logger.info("Caching disabled")

        # Initialize analyzers
        self.enable_analysis = enable_analysis
        if enable_analysis:
            self.sentiment_analyzer = SentimentAnalyzer()
            self.intent_classifier = IntentClassifier()
            self.keyword_extractor = KeywordExtractor()
            self.attack_detector = AttackPatternDetector()
            logger.info("Analysis features enabled")
        else:
            logger.info("Analysis features disabled")

        self.enable_sanitization = enable_sanitization
        if enable_sanitization:
            self.sanitizer = PromptSanitizer()
            logger.info("Sanitization features enabled")
        else:
            self.sanitizer = None
            logger.info("Sanitization features disabled")

        # Initialize model loader
        self.model_loader = ModelLoader(self.config)

        # Load model and tokenizer
        self.model, self.tokenizer = self.model_loader.load()

        logger.info("PromptGuard initialized with model: %s", model_name)

    def sanitize(
        self,
        prompt: str,
        strategy: SanitizationStrategy = SanitizationStrategy.BALANCED,
        analyze_after: bool = True,
    ) -> SanitizeResponse:
        """Sanitise a potentially malicious prompt.

        Args:
            prompt: Prompt to sanitise.
            strategy: Sanitisation strategy to apply.
            analyze_after: When ``True`` (default), the sanitised prompt is
                re-analysed and the result stored in
                :attr:`SanitizeResponse.sanitized_analysis`.

        Returns:
            A :class:`~promptguard.schemas.SanitizeResponse` with the
            sanitisation outcome and before/after risk scores.

        Raises:
            ValueError: When sanitisation is not enabled on this instance.
        """
        if not self.enable_sanitization or self.sanitizer is None:
            raise ValueError("Sanitization is not enabled")

        original_analysis = self.analyze(prompt)
        sanitization = self.sanitizer.sanitize(prompt, strategy)

        sanitized_analysis = None
        if analyze_after and sanitization.was_modified:
            sanitized_analysis = self.analyze(sanitization.sanitized)

        risk_after = sanitized_analysis.probability if sanitized_analysis else None
        risk_reduction = original_analysis.probability - (
            risk_after if risk_after is not None else original_analysis.probability
        )

        return SanitizeResponse(
            sanitization=sanitization,
            original_analysis=original_analysis,
            sanitized_analysis=sanitized_analysis,
            risk_before=original_analysis.probability,
            risk_after=risk_after,
            risk_reduction=risk_reduction,
        )

    def sanitize_if_malicious(
        self,
        prompt: str,
        strategy: SanitizationStrategy = SanitizationStrategy.BALANCED
    ) -> Tuple[str, bool]:
        """
        Sanitize prompt only if it's detected as malicious.

        Args:
            prompt: Prompt to check and potentially sanitize
            strategy: Sanitization strategy if needed

        Returns:
            Tuple of (potentially_sanitized_prompt, was_sanitized)
        """
        if not self.enable_sanitization or self.sanitizer is None:
            raise ValueError("Sanitization is not enabled")

        # Check if malicious
        analysis = self.analyze(prompt)

        if analysis.is_malicious:
            # Sanitize
            sanitization = self.sanitizer.sanitize(prompt, strategy)
            return sanitization.sanitized, True
        else:
            # Return unchanged
            return prompt, False

    def _perform_analysis(
        self,
        prompt: str,
        probability: float,
        is_batch: bool = False
    ) -> RiskScore:
        """
        Perform analysis on a single prompt (shared by analyze and analyze_batch).

        Args:
            prompt: The prompt text
            probability: Malicious probability from model
            is_batch: Whether this is from batch processing

        Returns:
            Complete RiskScore with all analysis
        """
        # Classify
        is_malicious = probability >= self.config.threshold

        # Determine risk level
        risk_level = self._get_risk_level(probability)

        # Calculate confidence
        confidence = abs(probability - 0.5) * 2

        # Perform additional analysis if enabled
        metadata = {
            "model": self.config.model_name,
            "threshold": self.config.threshold,
            "prompt_length": len(prompt)
        }

        if is_batch:
            metadata['batch_processed'] = True

        if self.enable_analysis:
            # Sentiment analysis
            sentiment_result = self.sentiment_analyzer.analyze(prompt)
            metadata['sentiment'] = sentiment_result

            # Intent classification
            intent_result = self.intent_classifier.classify(prompt)
            metadata['intent'] = intent_result

            # Extract keywords if malicious or suspicious
            if is_malicious or probability > 0.3:
                keywords = self.keyword_extractor.extract(prompt)
                metadata['keywords'] = keywords

                # Detect attack patterns
                attack_patterns = self.attack_detector.detect(prompt)
                metadata['attack_patterns'] = attack_patterns

        # Generate enhanced explanation
        explanation = self._generate_explanation(
            prompt, probability, is_malicious, metadata if self.enable_analysis else None
        )

        return RiskScore(
            is_malicious=is_malicious,
            probability=float(probability),
            risk_level=risk_level,
            confidence=float(confidence),
            explanation=explanation,
            metadata=metadata
        )

    def analyze(self, prompt: str) -> RiskScore:
        """
        Analyze a single prompt for malicious content.
        """
        # Validate input
        if not isinstance(prompt, str) or not prompt.strip():
            raise ValidationError("Prompt must be a non-empty string")

        # Check cache first
        if self.use_cache and self.cache is not None:
            cached_result = self.cache.get(prompt)
            if cached_result is not None:
                logger.debug("Returning cached result")
                return cached_result

        try:
            # Get probability
            probability = self._predict_single(prompt)

            # Perform analysis (now uses shared method)
            result = self._perform_analysis(
                prompt, probability, is_batch=False)

            # Cache result
            if self.use_cache and self.cache is not None:
                self.cache.set(prompt, result)

            return result

        except Exception as e:
            if isinstance(e, (ValidationError, InferenceError)):
                raise
            error_msg = f"Failed to analyze prompt: {str(e)}"
            logger.error(error_msg)
            raise InferenceError(error_msg) from e

    def clear_cache(self):
        """
        Clear the analysis cache
        """
        if self.cache is not None:
            self.cache.clear()
            logger.info("Cache cleared")
        else:
            logger.warning("Caching is not enabled")

    def cache_stats(self) -> Optional[Dict[str, Any]]:
        """
        Get cache statistics
        """
        if self.cache is not None:
            return self.cache.stats()
        return None

    def _predict_single(self, prompt: str) -> float:
        """
        Get probability for a single prompt.
        """
        # Tokenize
        inputs = self.tokenizer(
            prompt,
            truncation=True,
            max_length=self.config.max_length,
            padding=True,
            return_tensors="pt"
        )

        # Move to device
        inputs = {k: v.to(self.model_loader.device) for k, v in inputs.items()}

        # Predict
        with torch.no_grad():
            outputs = self.model(**inputs)
            probabilities = torch.softmax(outputs.logits, dim=1)
            malicious_prob = probabilities[0, 1].item()

        return malicious_prob

    def _get_risk_level(self, probability: float) -> RiskLevel:
        """
        Determine risk level based on probability.
        """
        if probability < 0.3:
            return RiskLevel.LOW
        elif probability < 0.7:
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.HIGH

    def _generate_explanation(
        self,
        prompt: str,
        probability: float,
        is_malicious: bool,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Generate human-readable explanation with evidence.

        Args:
            prompt: The analyzed prompt
            probability: Malicious probability
            is_malicious: Classification result
            metadata: Additional analysis metadata

        Returns:
            Explanation string
        """
        if is_malicious:
            explanation_parts = []

            # Base explanation
            if probability > 0.9:
                explanation_parts.append(
                    f"This prompt is highly likely to be malicious "
                    f"({probability:.1%} confidence)."
                )
            elif probability > 0.7:
                explanation_parts.append(
                    f"This prompt appears to be malicious "
                    f"({probability:.1%} confidence)."
                )
            else:
                explanation_parts.append(
                    f"This prompt is classified as malicious "
                    f"({probability:.1%} confidence)."
                )

            # Add evidence from metadata
            if metadata:
                evidence = []

                # Intent evidence
                if 'intent' in metadata:
                    intent_data = metadata['intent']
                    if intent_data['intent'] in [Intent.JAILBREAK, Intent.INJECTION]:
                        evidence.append(
                            f"Detected {intent_data['intent'].value} attempt")

                # Attack patterns
                if 'attack_patterns' in metadata:
                    attack_data = metadata['attack_patterns']
                    if attack_data['has_attack_patterns']:
                        attack_types = ', '.join(attack_data['attack_types'])
                        evidence.append(f"Attack patterns: {attack_types}")

                # Keywords
                if 'keywords' in metadata and metadata['keywords']:
                    keywords_str = ', '.join(
                        f"'{kw}'" for kw in metadata['keywords'][:3])
                    evidence.append(f"Suspicious keywords: {keywords_str}")

                # Sentiment
                if 'sentiment' in metadata:
                    sentiment_data = metadata['sentiment']
                    if sentiment_data['is_aggressive']:
                        evidence.append("Aggressive tone detected")

                if evidence:
                    explanation_parts.append(
                        " Evidence: " + "; ".join(evidence) + ".")

            return " ".join(explanation_parts)
        else:
            # Benign explanation
            explanation = (
                f"This prompt appears benign "
                f"({(1-probability):.1%} confidence). "
                f"No significant security concerns detected."
            )

            # Add intent info if available
            if metadata and 'intent' in metadata:
                intent_data = metadata['intent']
                explanation += f" Intent: {intent_data['description']}"

            return explanation

    def classify(self, prompt: str, threshold: Optional[float] = None) -> bool:
        """
        Simple binary classification.
        """
        result = self.analyze(prompt)

        if threshold is not None:
            return result.probability >= threshold

        return result.is_malicious

    def analyze_batch(
        self,
        prompts: List[str],
        batch_size: Optional[int] = None,
        show_progress: bool = True
    ) -> List[Optional[RiskScore]]:
        """
        Analyze multiple prompts efficiently in batches,
        using cache when enabled.
        """

        if not prompts:
            raise ValidationError("Prompts list cannot be empty")

        if not isinstance(prompts, list):
            raise ValidationError("Prompts must be a list of strings")

        batch_size = batch_size or self.config.batch_size

        final_results: List[Optional[RiskScore]] = [None] * len(prompts)

        # Track prompts that need inference
        uncached_prompts = []
        uncached_indices = []

        for i, prompt in enumerate(prompts):
            if not isinstance(prompt, str) or len(prompt.strip()) == 0:
                logger.warning("Skipping invalid prompt at index %i", i)
                continue

            # Check cache
            if self.use_cache and self.cache is not None:
                cached = self.cache.get(prompt)
                if cached is not None:
                    final_results[i] = cached
                    continue

            # Needs prediction
            uncached_prompts.append(prompt)
            uncached_indices.append(i)

        if not uncached_prompts:
            return final_results

        # Create progress iterator
        if show_progress:
            batches = tqdm(
                range(0, len(uncached_prompts), batch_size),
                desc="Analyzing prompts",
                unit="batch"
            )
        else:
            batches = range(0, len(uncached_prompts), batch_size)

        for i in batches:
            batch_prompts = uncached_prompts[i:i + batch_size]
            batch_probs = self._predict_batch(batch_prompts)

            for j, prob in enumerate(batch_probs):
                prompt = batch_prompts[j]
                original_index = uncached_indices[i + j]

                # Use shared analysis method (NOW INCLUDES ALL FEATURES!)
                result = self._perform_analysis(prompt, prob, is_batch=True)

                # Store result
                final_results[original_index] = result

                # Cache it
                if self.use_cache and self.cache is not None:
                    self.cache.set(prompt, result)

        return final_results

    def _predict_batch(self, prompts: List[str]) -> List[float]:
        """
        Get probabilities for a batch of prompts
        """

        # Tokenize batch
        inputs = self.tokenizer(
            prompts,
            truncation=True,
            max_length=self.config.max_length,
            padding=True,
            return_tensors="pt"
        )

        # Move to device
        inputs = {k: v.to(self.model_loader.device) for k, v in inputs.items()}

        # Predict
        with torch.no_grad():
            outputs = self.model(**inputs)
            probabilities = torch.softmax(outputs.logits, dim=1)
            malicious_probs = probabilities[:, 1].cpu().numpy()

        return malicious_probs.tolist()

    def classify_batch(
        self,
        prompts: List[str],
        threshold: Optional[float] = None,
        show_progress: bool = False
    ) -> List[Optional[bool]]:
        """
        Simple binary classification for multiple prompts
        """

        results = self.analyze_batch(prompts, show_progress=show_progress)
        threshold = threshold or self.config.threshold

        return [
            result.probability >= threshold if result is not None else None
            for result in results
        ]

    @property
    def device(self) -> str:
        """Get the device being used for inference."""
        return self.model_loader.device

    @property
    def threshold(self) -> float:
        """Get current classification threshold."""
        return self.config.threshold

    @threshold.setter
    def threshold(self, value: float):
        """Set classification threshold."""
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"Threshold must be between 0 and 1, got {value}")
        self.config.threshold = value
        logger.info("Threshold updated to: %f", value)
