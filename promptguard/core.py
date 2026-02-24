"""Core PromptGuard classifier."""
import logging
from typing import Union, List, Optional, Iterator
from tqdm import tqdm
import torch
from .cache import PromptCache
import numpy as np

from .config import PromptGuardConfig
from .models import ModelLoader
from .schemas import RiskScore, RiskLevel
from .exceptions import ValidationError, InferenceError

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
        **kwargs
    ):
        """
        Initialize PromptGuard classifier.
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

        # Initialize model loader
        self.model_loader = ModelLoader(self.config)

        # Load model and tokenizer
        self.model, self.tokenizer = self.model_loader.load()

        logger.info("PromptGuard initialized with model: %s", model_name)

    def analyze(self, prompt: str) -> RiskScore:
        """
        Analyze a single prompt for malicious content.
        """
        # Validate input
        if not prompt or not isinstance(prompt, str):
            raise ValidationError("Prompt must be a non-empty string")

        if len(prompt.strip()) == 0:
            raise ValidationError("Prompt cannot be empty or whitespace only")

        # Check cache first
        if self.use_cache and self.cache is not None:
            cached_result = self.cache.get(prompt)
            if cached_result is not None:
                logger.debug("Returning cached result")
                return cached_result

        try:
            # Get probability
            probability = self._predict_single(prompt)

            # Classify
            is_malicious = probability >= self.config.threshold

            # Determine risk level
            risk_level = self._get_risk_level(probability)

            # Calculate confidence
            # Confidence is how far the probability is from the decision boundary (0.5)
            confidence = abs(probability - 0.5) * 2  # Scale to 0-1

            # Generate explanation
            explanation = self._generate_explanation(
                prompt, probability, is_malicious)

            result = RiskScore(
                is_malicious=is_malicious,
                probability=float(probability),
                risk_level=risk_level,
                confidence=float(confidence),
                explanation=explanation,
                metadata={
                    "model": self.config.model_name,
                    "threshold": self.config.threshold,
                    "prompt_length": len(prompt)
                }
            )

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

    def cache_stats(self) -> Optional[dict[str, any]]:
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
        is_malicious: bool
    ) -> str:
        """
        Generate human-readable explanation.
        """
        if is_malicious:
            if probability > 0.9:
                return (
                    f"This prompt is highly likely to be malicious "
                    f"({probability:.1%} confidence). It shows strong "
                    f"indicators of prompt injection or jailbreak attempts."
                )
            elif probability > 0.7:
                return (
                    f"This prompt appears to be malicious "
                    f"({probability:.1%} confidence). It contains "
                    f"patterns associated with prompt manipulation."
                )
            else:
                return (
                    f"This prompt is classified as malicious "
                    f"({probability:.1%} confidence). Consider reviewing "
                    f"it for potential security issues."
                )
        else:
            return (
                f"This prompt appears benign "
                f"({(1-probability):.1%} confidence). "
                f"No significant security concerns detected."
            )

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
    ) -> List[RiskScore]:
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

                is_malicious = prob >= self.config.threshold
                risk_level = self._get_risk_level(prob)
                confidence = abs(prob - 0.5) * 2
                explanation = self._generate_explanation(
                    prompt, prob, is_malicious
                )

                result = RiskScore(
                    is_malicious=is_malicious,
                    probability=float(prob),
                    risk_level=risk_level,
                    confidence=float(confidence),
                    explanation=explanation,
                    metadata={
                        "model": self.config.model_name,
                        "threshold": self.config.threshold,
                        "prompt_length": len(prompt),
                        "batch_processed": True
                    }
                )

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
