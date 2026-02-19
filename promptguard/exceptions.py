"""Custom exceptions for PromptGuard."""


class PromptGuardError(Exception):
    """Base exception for PromptGuard errors."""
    pass


class ModelLoadError(PromptGuardError):
    """Raised when model fails to load."""
    pass


class ValidationError(PromptGuardError):
    """Raised when input validation fails."""
    pass


class ConfigurationError(PromptGuardError):
    """Raised when configuration is invalid."""
    pass


class InferenceError(PromptGuardError):
    """Raised when inference fails."""
    pass
