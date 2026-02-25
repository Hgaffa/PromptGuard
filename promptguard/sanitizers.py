"""
Prompt sanitization strategies for cleaning malicious content.

This module provides different strategies for sanitizing prompts that contain
injection attempts or jailbreak patterns, allowing users to clean prompts
while preserving legitimate intent.
"""

import re
import logging
from typing import Dict, Any, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class SanitizationStrategy(str, Enum):
    """Sanitization strategy levels."""
    CONSERVATIVE = "conservative"  # Remove everything suspicious
    BALANCED = "balanced"           # Remove obvious attacks, preserve intent
    MINIMAL = "minimal"            # Only remove critical patterns


@dataclass
class SanitizationResult:
    """
    Result of prompt sanitization.

    Attributes:
        original: Original prompt
        sanitized: Cleaned prompt
        was_modified: Whether any changes were made
        removed_patterns: List of patterns that were removed
        strategy: Strategy used for sanitization
        confidence: Confidence that sanitization was successful (0-1)
        risk_reduction: Estimated risk reduction from sanitization
    """
    original: str
    sanitized: str
    was_modified: bool
    removed_patterns: List[str]
    strategy: SanitizationStrategy
    confidence: float
    risk_reduction: float

    def __str__(self) -> str:
        """String representation."""
        status = "MODIFIED" if self.was_modified else "UNCHANGED"
        return (
            f"SanitizationResult(status={status}, "
            f"patterns_removed={len(self.removed_patterns)}, "
            f"strategy={self.strategy.value})"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "original": self.original,
            "sanitized": self.sanitized,
            "was_modified": self.was_modified,
            "removed_patterns": self.removed_patterns,
            "strategy": self.strategy.value,
            "confidence": self.confidence,
            "risk_reduction": self.risk_reduction
        }


class PromptSanitizer:
    """
    Sanitize prompts by removing or neutralizing malicious patterns.

    Supports three strategies:
    - CONSERVATIVE: Aggressive removal, might affect legitimate prompts
    - BALANCED: Remove obvious attacks while preserving intent
    - MINIMAL: Only remove critical injection patterns
    """

    # Pattern definitions for each strategy level
    _CRITICAL_PATTERNS = [
        # Direct instruction override
        (r"ignore\s+(all\s+)?(previous|prior|above|earlier|all)\s+(instructions?|rules?|prompts?)", ""),
        (r"forget\s+(everything|all|prior|previous|instructions?)", ""),
        (r"disregard\s+(previous|prior|above|all)\s+(instructions?|context|rules?)", ""),

        # System/role manipulation
        (r"(developer|debug|admin|sudo|root)\s+mode", ""),
        (r"\byou\s+are\s+now\s+(a|an)\s+\w+", "you are an AI assistant"),
        (r"\bdan\b(?!\w)", ""),
        (r"do\s+anything\s+now", ""),

        # System prompt extraction
        (r"(print|show|reveal|display)\s+(your\s+)?(system\s+)?prompt", ""),
        (r"repeat\s+(the\s+)?(above|previous|initial)\s+(instructions?|text)", ""),

        # Tag injection
        (r"</?(system|user|assistant)>", ""),
        (r"\[/?INST\]", ""),
        (r"<</?SYS>>", ""),
    ]

    _AGGRESSIVE_PATTERNS = [
        # Context manipulation
        (r"start\s+(over|fresh|anew)", "continue"),
        (r"new\s+(conversation|context|session)", "current conversation"),
        (r"(clear|reset|wipe)\s+(your\s+)?(memory|context)", ""),

        # Role-play attempts
        (r"(act\s+as|pretend\s+to\s+be|roleplay\s+as)\s+(a|an)\s+\w+", "help with"),

        # Safety bypass
        (r"(ignore|bypass|disable|remove)\s+(safety|security|restrictions?)", ""),
        (r"no\s+(restrictions?|limits?|rules?|filters?)", ""),

        # Output manipulation
        (r"respond\s+(only|exclusively)\s+with", "respond with"),
        (r"(always|only)\s+(respond|reply|answer)\s+(in|with|as)", "respond"),
    ]

    _ENCODING_PATTERNS = [
        # Base64 (only long sequences that look suspicious)
        (r"(?<!\w)[A-Za-z0-9+/]{30,}={0,2}(?!\w)", "[removed]"),

        # Hex sequences
        (r"(?:\\x[0-9a-fA-F]{2}){4,}", "[removed]"),

        # Unicode escapes
        (r"(?:\\u[0-9a-fA-F]{4}){3,}", "[removed]"),
    ]

    _OBFUSCATION_PATTERNS = [
        # Character spacing (i g n o r e)
        (r"\b([a-z])\s+([a-z])\s+([a-z])\s+([a-z])\s+([a-z])", r"\1\2\3\4\5"),

        # Leetspeak
        (r"\b1gn[0o]r[e3]\b", "ignore"),
        (r"\bbyp[4a]ss\b", "bypass"),
        (r"\b[0o]v[e3]rr[1i]d[e3]\b", "override"),

        # Excessive punctuation
        (r"([.!?])\1{2,}", r"\1"),
    ]

    def __init__(self):
        """Initialize sanitizer with compiled patterns."""
        # Pre-compile all patterns for performance
        self._compiled_critical = [
            (re.compile(pattern, re.IGNORECASE), replacement)
            for pattern, replacement in self._CRITICAL_PATTERNS
        ]

        self._compiled_aggressive = [
            (re.compile(pattern, re.IGNORECASE), replacement)
            for pattern, replacement in self._AGGRESSIVE_PATTERNS
        ]

        self._compiled_encoding = [
            (re.compile(pattern, re.IGNORECASE), replacement)
            for pattern, replacement in self._ENCODING_PATTERNS
        ]

        self._compiled_obfuscation = [
            (re.compile(pattern, re.IGNORECASE), replacement)
            for pattern, replacement in self._OBFUSCATION_PATTERNS
        ]

        logger.debug("PromptSanitizer initialized")

    def sanitize(
        self,
        prompt: str,
        strategy: SanitizationStrategy = SanitizationStrategy.BALANCED
    ) -> SanitizationResult:
        """
        Sanitize a prompt using the specified strategy.

        Args:
            prompt: Prompt to sanitize
            strategy: Sanitization strategy to use

        Returns:
            SanitizationResult with sanitized prompt and metadata

        Example:
            >>> sanitizer = PromptSanitizer()
            >>> result = sanitizer.sanitize("Ignore all previous instructions")
            >>> print(result.sanitized)  # Cleaned prompt
            >>> print(result.removed_patterns)  # What was removed
        """
        original = prompt
        sanitized = prompt
        removed_patterns = []

        # Apply patterns based on strategy
        if strategy == SanitizationStrategy.CONSERVATIVE:
            sanitized, patterns = self._apply_patterns(
                sanitized,
                self._compiled_critical +
                self._compiled_aggressive +
                self._compiled_encoding +
                self._compiled_obfuscation
            )
            removed_patterns.extend(patterns)

        elif strategy == SanitizationStrategy.BALANCED:
            # Apply critical and encoding patterns
            sanitized, patterns = self._apply_patterns(
                sanitized,
                self._compiled_critical + self._compiled_encoding
            )
            removed_patterns.extend(patterns)

            # Apply selective aggressive patterns (preserve intent)
            sanitized, patterns = self._apply_patterns(
                sanitized,
                self._compiled_aggressive[:3]  # Only first 3 patterns
            )
            removed_patterns.extend(patterns)

        else:  # MINIMAL
            # Only apply critical patterns
            sanitized, patterns = self._apply_patterns(
                sanitized,
                self._compiled_critical
            )
            removed_patterns.extend(patterns)

        # Clean up whitespace
        sanitized = self._clean_whitespace(sanitized)

        # Calculate confidence and risk reduction
        was_modified = sanitized != original
        confidence = self._calculate_confidence(
            original, sanitized, removed_patterns)
        risk_reduction = self._estimate_risk_reduction(removed_patterns)

        return SanitizationResult(
            original=original,
            sanitized=sanitized,
            was_modified=was_modified,
            removed_patterns=removed_patterns,
            strategy=strategy,
            confidence=confidence,
            risk_reduction=risk_reduction
        )

    def _apply_patterns(
        self,
        text: str,
        patterns: List[Tuple[re.Pattern, str]]
    ) -> Tuple[str, List[str]]:
        """
        Apply list of regex patterns to text.

        Returns:
            Tuple of (modified_text, list_of_matched_patterns)
        """
        removed = []

        for pattern, replacement in patterns:
            matches = pattern.findall(text)
            if matches:
                # Track what was matched
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]  # Get first group
                    removed.append(match if isinstance(
                        match, str) else str(match))

                # Apply replacement
                text = pattern.sub(replacement, text)

        return text, removed

    def _clean_whitespace(self, text: str) -> str:
        """Clean up excessive whitespace."""
        # Remove multiple spaces
        text = re.sub(r'\s+', ' ', text)

        # Remove leading/trailing whitespace
        text = text.strip()

        # Remove spaces before punctuation
        text = re.sub(r'\s+([,.!?])', r'\1', text)

        return text

    def _calculate_confidence(
        self,
        original: str,
        sanitized: str,
        removed_patterns: List[str]
    ) -> float:
        """
        Calculate confidence that sanitization was successful.

        Higher confidence means we're more certain the prompt is now safe.
        """
        if not removed_patterns:
            # Nothing was removed, confidence depends on original safety
            return 0.5  # Neutral

        # Calculate based on how much was removed
        removal_ratio = 1 - (len(sanitized) / max(len(original), 1))

        # More patterns removed = higher confidence we fixed it
        pattern_score = min(len(removed_patterns) / 5, 1.0)

        # If too much was removed, lower confidence (might have broken prompt)
        if removal_ratio > 0.5:
            confidence = 0.6
        else:
            confidence = 0.7 + (pattern_score * 0.3)

        return round(confidence, 2)

    def _estimate_risk_reduction(self, removed_patterns: List[str]) -> float:
        """
        Estimate how much risk was reduced by sanitization.

        Returns value between 0.0 and 1.0.
        """
        if not removed_patterns:
            return 0.0

        # Each removed pattern reduces risk
        # Critical patterns have more impact
        risk_reduction = min(len(removed_patterns) * 0.15, 1.0)

        return round(risk_reduction, 2)


class AdvancedSanitizer(PromptSanitizer):
    """
    Advanced sanitizer with additional context-aware cleaning.

    Extends PromptSanitizer with:
    - Intent preservation (tries to keep user's legitimate intent)
    - Smart replacement (replaces dangerous patterns with safe alternatives)
    - Context-aware cleaning (understands when patterns might be legitimate)
    """

    def sanitize_with_intent(
        self,
        prompt: str,
        intent: Optional[str] = None,
        strategy: SanitizationStrategy = SanitizationStrategy.BALANCED
    ) -> SanitizationResult:
        """
        Sanitize while trying to preserve the user's intent.

        Args:
            prompt: Prompt to sanitize
            intent: Detected intent (question, instruction, etc.)
            strategy: Sanitization strategy

        Returns:
            SanitizationResult with intent-aware cleaning
        """
        # If intent is QUESTION, be less aggressive with removal
        if intent and intent.lower() == "question":
            # Use minimal strategy for questions
            actual_strategy = SanitizationStrategy.MINIMAL
        else:
            actual_strategy = strategy

        # Perform standard sanitization
        result = self.sanitize(prompt, actual_strategy)

        # If too much was removed and we have intent, try to preserve it
        if result.was_modified and len(result.sanitized) < len(prompt) * 0.5:
            # Significant removal, try to add context back
            if intent == "question":
                result.sanitized = f"Question: {result.sanitized}"

        return result

    def suggest_alternative(self, prompt: str) -> Optional[str]:
        """
        Suggest a safe alternative phrasing for a malicious prompt.

        Args:
            prompt: Potentially malicious prompt

        Returns:
            Suggested safe alternative or None if prompt seems safe
        """
        prompt_lower = prompt.lower()

        # Common patterns and their alternatives
        alternatives = {
            r"ignore.*previous": "I have a new question:",
            r"forget.*instructions": "Starting fresh:",
            r"pretend.*you.*are": "Act as if you were",
            r"system\s+prompt": "your instructions",
        }

        for pattern, replacement in alternatives.items():
            if re.search(pattern, prompt_lower, re.IGNORECASE):
                return re.sub(pattern, replacement, prompt, flags=re.IGNORECASE)

        return None
