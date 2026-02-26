"""Model loading and management."""

import torch
from transformers import (
    AutoTokenizer,
    AutoModelForSequenceClassification,
)
from typing import Optional, Tuple
import logging

from .config import PromptGuardConfig
from .exceptions import ModelLoadError

logger = logging.getLogger(__name__)


class ModelLoader:
    """Handles loading and caching of models from HuggingFace Hub."""

    def __init__(self, config: PromptGuardConfig):
        """
        Initialize model loader.

        Args:
            config: PromptGuard configuration
        """
        self.config = config
        self._model = None
        self._tokenizer = None
        self._device = self._determine_device()

    def _determine_device(self) -> str:
        """Determine the device to use for inference."""
        if self.config.device == "auto":
            return "cuda" if torch.cuda.is_available() else "cpu"
        return self.config.device

    def load(self) -> Tuple[AutoModelForSequenceClassification, AutoTokenizer]:
        """
        Load model and tokenizer from HuggingFace Hub.

        Returns:
            Tuple of (model, tokenizer)

        Raises:
            ModelLoadError: If model loading fails
        """
        if self._model is not None and self._tokenizer is not None:
            logger.debug("Using cached model and tokenizer")
            return self._model, self._tokenizer

        try:
            logger.info(
                "Loading model from HuggingFace Hub: %s", self.config.model_name
            )

            # Load tokenizer
            self._tokenizer = AutoTokenizer.from_pretrained(
                self.config.model_name,
                use_fast=True,
            )
            logger.debug("Tokenizer loaded")

            # Load model
            self._model = AutoModelForSequenceClassification.from_pretrained(
                self.config.model_name
            )

            # Move to device and set to eval mode
            self._model.to(self._device)
            self._model.eval()

            logger.info("Model loaded successfully on %s", self._device)

            return self._model, self._tokenizer

        except Exception as e:
            error_msg = f"Failed to load model '{self.config.model_name}': {str(e)}"
            logger.error(error_msg)
            raise ModelLoadError(error_msg) from e

    @property
    def device(self) -> str:
        """Get the device being used."""
        return self._device

    @property
    def is_loaded(self) -> bool:
        """Check if model is loaded."""
        return self._model is not None and self._tokenizer is not None
