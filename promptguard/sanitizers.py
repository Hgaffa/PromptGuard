"""
Prompt sanitisation strategies for cleaning malicious content.

This module provides ``PromptSanitizer`` and ``AdvancedSanitizer`` which remove
or neutralise injection attempts and jailbreak patterns while trying to preserve
the user's legitimate intent.
"""

import re
import logging
import unicodedata
from typing import Any, Dict, List, Optional, Tuple

from .schemas import SanitizationResult, SanitizationStrategy

logger = logging.getLogger(__name__)


class PromptSanitizer:
    """Sanitise prompts by removing or neutralising malicious patterns.

    Input text is Unicode-normalised (NFKC) before pattern matching so that
    full-width and compatibility character obfuscation is caught automatically.

    Three strategies are supported:

    * **CONSERVATIVE** — applies all pattern groups.  Maximum safety; may
      affect some legitimate phrasing.
    * **BALANCED** (default) — applies critical, encoding, and context-reset
      patterns.  Good trade-off for most production applications.
    * **MINIMAL** — applies only the critical patterns.  Use when exact wording
      must be preserved as much as possible.
    """

    # ── Critical: direct instruction override & tag injection ─────────────────
    _CRITICAL_PATTERNS = [
        (
            r"ignore\s+(all\s+)?(previous|prior|above|earlier|all)"
            r"\s+(instructions?|rules?|prompts?)",
            "",
        ),
        (r"forget\s+(everything|all|prior|previous|instructions?)", ""),
        (
            r"disregard\s+(previous|prior|above|all)"
            r"\s+(instructions?|context|rules?)",
            "",
        ),
        (r"(developer|debug|admin|sudo|root)\s+mode", ""),
        (r"\byou\s+are\s+now\s+(a|an)\s+\w+", "you are an AI assistant"),
        (r"\bdan\b(?!\w)", ""),
        (r"do\s+anything\s+now", ""),
        (r"(print|show|reveal|display)\s+(your\s+)?(system\s+)?prompt", ""),
        (r"repeat\s+(the\s+)?(above|previous|initial)\s+(instructions?|text)", ""),
        (r"</?(system|user|assistant)>", ""),
        (r"\[/?INST\]", ""),
        (r"<</?SYS>>", ""),
    ]

    # ── Context manipulation: session/memory reset ─────────────────────────────
    # Used by BALANCED and CONSERVATIVE strategies.
    _CONTEXT_MANIPULATION_PATTERNS = [
        (r"start\s+(over|fresh|anew)", "continue"),
        (r"new\s+(conversation|context|session)", "current conversation"),
        (r"(clear|reset|wipe)\s+(your\s+)?(memory|context)", ""),
    ]

    # ── Role-play, safety bypass, and output shaping ───────────────────────────
    # Used only by the CONSERVATIVE strategy.
    _ROLEPLAY_PATTERNS = [
        (
            r"(act\s+as|pretend\s+to\s+be|roleplay\s+as)\s+(a|an)\s+\w+",
            "help with",
        ),
        (
            r"(ignore|bypass|disable|remove)\s+(safety|security|restrictions?)",
            "",
        ),
        (r"no\s+(restrictions?|limits?|rules?|filters?)", ""),
        (r"respond\s+(only|exclusively)\s+with", "respond with"),
        (r"(always|only)\s+(respond|reply|answer)\s+(in|with|as)", "respond"),
    ]

    # ── Encoding attacks ───────────────────────────────────────────────────────
    _ENCODING_PATTERNS = [
        (r"(?<!\w)[A-Za-z0-9+/]{30,}={0,2}(?!\w)", "[removed]"),  # Base64
        (r"(?:\\x[0-9a-fA-F]{2}){4,}", "[removed]"),               # Hex escapes
        (r"(?:\\u[0-9a-fA-F]{4}){3,}", "[removed]"),               # Unicode escapes
    ]

    # ── Character-level obfuscation ────────────────────────────────────────────
    _OBFUSCATION_PATTERNS = [
        # Character spacing: "i g n o r e" → "ignore"
        (r"\b([a-z])\s+([a-z])\s+([a-z])\s+([a-z])\s+([a-z])", r"\1\2\3\4\5"),
        (r"\b1gn[0o]r[e3]\b", "ignore"),
        (r"\bbyp[4a]ss\b", "bypass"),
        (r"\b[0o]v[e3]rr[1i]d[e3]\b", "override"),
        (r"([.!?])\1{2,}", r"\1"),  # Excessive punctuation
    ]

    # Pre-compiled whitespace cleaner (module-level to avoid re-instantiation)
    _WS_RE = re.compile(r"\s+")
    _PUNCT_WS_RE = re.compile(r"\s+([,.!?])")

    def __init__(self) -> None:
        """Compile all pattern lists at initialisation time."""
        self._compiled_critical = self._compile(self._CRITICAL_PATTERNS)
        self._compiled_context_manipulation = self._compile(
            self._CONTEXT_MANIPULATION_PATTERNS
        )
        self._compiled_roleplay = self._compile(self._ROLEPLAY_PATTERNS)
        self._compiled_encoding = self._compile(self._ENCODING_PATTERNS)
        self._compiled_obfuscation = self._compile(self._OBFUSCATION_PATTERNS)
        logger.debug("PromptSanitizer initialized")

    # ── Public interface ───────────────────────────────────────────────────────

    def sanitize(
        self,
        prompt: str,
        strategy: SanitizationStrategy = SanitizationStrategy.BALANCED,
    ) -> SanitizationResult:
        """Sanitise *prompt* using the specified *strategy*.

        The prompt is Unicode-normalised before any pattern matching so that
        obfuscated variants (e.g. full-width characters) are caught.

        Args:
            prompt: The prompt text to sanitise.
            strategy: Sanitisation strategy controlling which pattern groups
                are applied.

        Returns:
            A :class:`~promptguard.schemas.SanitizationResult` describing the
            outcome.

        Example::

            sanitizer = PromptSanitizer()
            result = sanitizer.sanitize("Ignore all previous instructions")
            print(result.sanitized)       # Cleaned prompt
            print(result.removed_patterns)  # What was removed
        """
        # Normalise Unicode before any matching
        original = unicodedata.normalize("NFKC", prompt)
        sanitized = original
        removed_patterns: List[str] = []

        if strategy == SanitizationStrategy.CONSERVATIVE:
            sanitized, patterns = self._apply_patterns(
                sanitized,
                self._compiled_critical
                + self._compiled_context_manipulation
                + self._compiled_roleplay
                + self._compiled_encoding
                + self._compiled_obfuscation,
            )
            removed_patterns.extend(patterns)

        elif strategy == SanitizationStrategy.BALANCED:
            sanitized, patterns = self._apply_patterns(
                sanitized,
                self._compiled_critical
                + self._compiled_encoding
                + self._compiled_context_manipulation,
            )
            removed_patterns.extend(patterns)

        else:  # MINIMAL
            sanitized, patterns = self._apply_patterns(
                sanitized, self._compiled_critical
            )
            removed_patterns.extend(patterns)

        sanitized = self._clean_whitespace(sanitized)

        was_modified = sanitized != original
        confidence = self._calculate_confidence(original, sanitized, removed_patterns)
        risk_reduction = self._estimate_risk_reduction(removed_patterns)

        return SanitizationResult(
            original=original,
            sanitized=sanitized,
            was_modified=was_modified,
            removed_patterns=removed_patterns,
            strategy=strategy,
            confidence=confidence,
            risk_reduction=risk_reduction,
        )

    # ── Private helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _compile(
        patterns: List[Tuple[str, str]],
    ) -> List[Tuple[re.Pattern, str]]:
        """Compile a list of ``(raw_pattern, replacement)`` tuples."""
        compiled = []
        for raw, replacement in patterns:
            try:
                compiled.append((re.compile(raw, re.IGNORECASE), replacement))
            except re.error as exc:
                logger.warning("Failed to compile pattern %r: %s", raw, exc)
        return compiled

    @staticmethod
    def _apply_patterns(
        text: str,
        patterns: List[Tuple[re.Pattern, str]],
    ) -> Tuple[str, List[str]]:
        """Apply *patterns* to *text* and return the result plus matched text.

        Returns:
            ``(modified_text, list_of_matched_strings)``
        """
        removed: List[str] = []
        for pattern, replacement in patterns:
            matches = pattern.findall(text)
            if matches:
                for match in matches:
                    if isinstance(match, tuple):
                        match = match[0]
                    removed.append(match if isinstance(match, str) else str(match))
                text = pattern.sub(replacement, text)
        return text, removed

    def _clean_whitespace(self, text: str) -> str:
        """Collapse multiple spaces and strip leading/trailing whitespace."""
        text = self._WS_RE.sub(" ", text)
        text = self._PUNCT_WS_RE.sub(r"\1", text)
        return text.strip()

    @staticmethod
    def _calculate_confidence(
        original: str,
        sanitized: str,
        removed_patterns: List[str],
    ) -> float:
        """Estimate how confident we are that the sanitised prompt is safe.

        Returns:
            A float in ``[0, 1]``.
        """
        if not removed_patterns:
            return 0.5

        removal_ratio = 1.0 - (len(sanitized) / max(len(original), 1))
        pattern_score = min(len(removed_patterns) / 5, 1.0)

        if removal_ratio > 0.5:
            confidence = 0.6
        else:
            confidence = 0.7 + (pattern_score * 0.3)

        return round(confidence, 2)

    @staticmethod
    def _estimate_risk_reduction(removed_patterns: List[str]) -> float:
        """Estimate how much risk was reduced by sanitisation.

        Returns:
            A float in ``[0, 1]``.
        """
        if not removed_patterns:
            return 0.0
        return round(min(len(removed_patterns) * 0.15, 1.0), 2)


class AdvancedSanitizer(PromptSanitizer):
    """Sanitiser with intent-aware cleaning and safe-rephrasing suggestions.

    Extends :class:`PromptSanitizer` with:

    * **Intent preservation** — uses a lighter strategy for question-type
      prompts to minimise over-removal.
    * **Safe alternative suggestions** — rewrites common attack patterns into
      legitimate equivalents.
    """

    # (compiled_pattern, replacement) — built once in __init__
    _ALTERNATIVE_PATTERNS_RAW = [
        (r"ignore.*previous", "I have a new question:"),
        (r"forget.*instructions", "Starting fresh:"),
        (r"pretend.*you.*are", "Act as if you were"),
        (r"system\s+prompt", "your instructions"),
    ]

    def __init__(self) -> None:
        """Compile parent patterns and pre-compile alternative patterns."""
        super().__init__()
        self._compiled_alternatives: List[Tuple[re.Pattern, str]] = [
            (re.compile(raw, re.IGNORECASE), replacement)
            for raw, replacement in self._ALTERNATIVE_PATTERNS_RAW
        ]

    def sanitize_with_intent(
        self,
        prompt: str,
        intent: Optional[str] = None,
        strategy: SanitizationStrategy = SanitizationStrategy.BALANCED,
    ) -> SanitizationResult:
        """Sanitise *prompt* while respecting the detected *intent*.

        When *intent* is ``"question"`` the MINIMAL strategy is used to avoid
        removing context that forms part of a legitimate query.

        Args:
            prompt: The prompt text to sanitise.
            intent: Detected intent string (e.g. ``"question"``,
                ``"instruction"``).
            strategy: Fallback strategy for non-question intents.

        Returns:
            A :class:`~promptguard.schemas.SanitizationResult`.
        """
        actual_strategy = (
            SanitizationStrategy.MINIMAL
            if intent and intent.lower() == "question"
            else strategy
        )

        result = self.sanitize(prompt, actual_strategy)

        # If a large portion was removed from a question, prepend context marker
        if (
            result.was_modified
            and intent == "question"
            and len(result.sanitized) < len(prompt) * 0.5
        ):
            result.sanitized = f"Question: {result.sanitized}"

        return result

    def suggest_alternative(self, prompt: str) -> Optional[str]:
        """Return a safe rephrasing of *prompt*, or ``None`` if no match.

        Uses pre-compiled patterns so there is no per-call compilation cost.

        Args:
            prompt: A potentially malicious prompt.

        Returns:
            A sanitised alternative string, or ``None`` if the prompt does not
            match any known attack pattern.
        """
        for compiled_re, replacement in self._compiled_alternatives:
            if compiled_re.search(prompt):
                return compiled_re.sub(replacement, prompt)
        return None
