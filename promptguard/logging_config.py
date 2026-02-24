"""Logging configuration for PromptGuard."""

import logging
import sys
from typing import Optional


def setup_logging(
    level: str = "INFO",
    format_string: Optional[str] = None,
    include_timestamp: bool = True
):
    """
    Configure logging for PromptGuard.
    """
    # Default format
    if format_string is None:
        if include_timestamp:
            format_string = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        else:
            format_string = "%(name)s - %(levelname)s - %(message)s"

    # Configure root logger
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format=format_string,
        handlers=[logging.StreamHandler(sys.stdout)]
    )

    # Set level for promptguard logger
    logger = logging.getLogger("promptguard")
    logger.setLevel(getattr(logging, level.upper()))

    logger.info("Logging configured at %s level", level)


def disable_transformers_logging():
    """Suppress verbose transformers library logging."""
    logging.getLogger("transformers").setLevel(logging.ERROR)
    logging.getLogger("transformers.modeling_utils").setLevel(logging.ERROR)


def get_logger(name: str) -> logging.Logger:
    """
    Get a logger for a PromptGuard module.
    """
    return logging.getLogger(f"promptguard.{name}")
