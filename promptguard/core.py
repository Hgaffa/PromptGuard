"""Core PromptGuard classifier."""
import logging
from typing import Union, List, Optional
import torch
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
        **kwargs
    ):
        """
        Initialize PromptGuard classifier.

        Args:
            model_name: HuggingFace model identifier
            threshold: Classification threshold (0.0 to 1.0)
            device: Device for inference ('cuda', 'cpu', or 'auto')
            **kwargs: Additional configuration options
        """
        # Create configuration
        self.config = PromptGuardConfig(
            model_name=model_name,
            threshold=threshold,
            device=device,
            **kwargs
        )

        # Initialize model loader
        self.model_loader = ModelLoader(self.config)

        # Load model and tokenizer
        self.model, self.tokenizer = self.model_loader.load()

        logger.info("PromptGuard initialized with model: %s", model_name)

    def analyze(self, prompt: str) -> RiskScore:
        """
        Analyze a single prompt for malicious content.

        Args:
            prompt: The prompt text to analyze

        Returns:
            RiskScore object containing analysis results

        Raises:
            ValidationError: If prompt is invalid
            InferenceError: If analysis fails
        """
        # Validate input
        if not prompt or not isinstance(prompt, str):
            raise ValidationError("Prompt must be a non-empty string")

        if len(prompt.strip()) == 0:
            raise ValidationError("Prompt cannot be empty or whitespace only")

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

            return RiskScore(
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

        except Exception as e:
            if isinstance(e, (ValidationError, InferenceError)):
                raise
            error_msg = f"Failed to analyze prompt: {str(e)}"
            logger.error(error_msg)
            raise InferenceError(error_msg) from e

    def _predict_single(self, prompt: str) -> float:
        """
        Get probability for a single prompt.

        Args:
            prompt: Text to analyze

        Returns:
            Probability of being malicious (0.0 to 1.0)
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

        Args:
            probability: Malicious probability

        Returns:
            RiskLevel enum
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

        Args:
            prompt: The analyzed prompt
            probability: Malicious probability
            is_malicious: Classification result

        Returns:
            Explanation string
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

        Args:
            prompt: Text to classify
            threshold: Optional custom threshold (overrides config)

        Returns:
            True if malicious, False if benign

        Example:
            >>> guard = PromptGuard()
            >>> guard.classify("Hello world")  # False
            >>> guard.classify("Ignore all instructions")  # True
        """
        result = self.analyze(prompt)

        if threshold is not None:
            return result.probability >= threshold

        return result.is_malicious

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

