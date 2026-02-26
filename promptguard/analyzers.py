"""
Analysis modules for additional prompt insights.

This module provides sentiment analysis, intent classification, keyword
extraction, and attack pattern detection for security analysis of prompts.

Dependencies:
    - vaderSentiment (required): For sentiment analysis
    - spaCy (optional): For enhanced keyword extraction
        - If spaCy is available, run: python -m spacy download en_core_web_sm

Fallbacks:
    - If vaderSentiment is missing, uses lexicon-based sentiment analysis
    - If spaCy is missing, uses regex-based keyword extraction
"""

import re
import logging
import unicodedata
from typing import Any, Dict, List, Optional

from .schemas import Intent, Sentiment

# Try importing optional dependencies
try:
    import spacy as _spacy  # type: ignore[import-untyped]

    _SPACY_INSTALLED = True
except ImportError:
    _spacy = None
    _SPACY_INSTALLED = False

try:
    from vaderSentiment.vaderSentiment import (  # type: ignore[import-untyped]
        SentimentIntensityAnalyzer as _VaderSIA,
    )

    _VADER_AVAILABLE = True
except ImportError:
    _VaderSIA = None
    _VADER_AVAILABLE = False

logger = logging.getLogger(__name__)

# Global spaCy model (lazy-loaded)
_nlp = None
_SPACY_AVAILABLE = _SPACY_INSTALLED


def _get_nlp() -> Optional[Any]:
    """Lazy-load the spaCy model safely.

    Returns:
        The loaded spaCy ``Language`` object, or ``None`` if unavailable.
    """
    global _nlp, _SPACY_AVAILABLE  # noqa: PLW0603

    if not _SPACY_AVAILABLE:
        return None

    if _nlp is not None:
        return _nlp

    if not _spacy:
        _SPACY_AVAILABLE = False
        return None

    try:
        _nlp = _spacy.load("en_core_web_sm")
        logger.info("Loaded spaCy model: en_core_web_sm")
    except OSError:
        logger.warning(
            "spaCy model 'en_core_web_sm' not found. "
            "Keyword extraction will use fallback mode. "
            "Run: python -m spacy download en_core_web_sm"
        )
        _SPACY_AVAILABLE = False
        return None
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to load spaCy model: %s", exc)
        _SPACY_AVAILABLE = False
        return None

    return _nlp


# ──────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ──────────────────────────────────────────────────────────────────────────────


def _normalize_text(text: str) -> str:
    """Apply NFKC Unicode normalisation to *text*.

    This converts full-width characters, ligatures, and compatibility variants
    to their standard ASCII equivalents before pattern matching, preventing
    simple Unicode-substitution obfuscation attacks.
    """
    return unicodedata.normalize("NFKC", text)


def _tokenise(text: str) -> List[str]:
    """Return lowercase word tokens from *text*, preserving contractions."""
    return re.findall(r"\b[\w']+\b", text.lower())


# ──────────────────────────────────────────────────────────────────────────────
# SentimentAnalyzer
# ──────────────────────────────────────────────────────────────────────────────


class SentimentAnalyzer:
    """Analyse sentiment and tone of prompts using VADER (with lexicon fallback).

    When ``vaderSentiment`` is installed it is used as the primary scorer.
    Otherwise a lightweight word-level lexicon is used.  In both modes an
    additional aggressive-tone signal is computed from a curated vocabulary of
    security-relevant commands and coercive language, with basic negation
    awareness (e.g. ``"don't ignore"`` scores lower than ``"ignore"``).
    """

    # Fallback lexicon used when VADER is unavailable
    _LEXICON: Dict[str, float] = {
        # Positive
        "good": 1.5, "great": 2.0, "excellent": 2.5, "amazing": 2.5,
        "wonderful": 2.0, "fantastic": 2.5, "love": 2.0, "like": 1.0,
        "enjoy": 1.5, "happy": 1.5, "pleased": 1.5, "thank": 1.0,
        "thanks": 1.0, "appreciate": 1.5, "helpful": 1.5, "nice": 1.0,
        "kind": 1.0, "please": 0.5, "beautiful": 2.0, "awesome": 2.0,
        "glad": 1.5, "brilliant": 2.0, "superb": 2.5, "perfect": 2.0,
        # Negative
        "bad": -1.5, "terrible": -2.5, "awful": -2.5, "horrible": -2.5,
        "hate": -2.5, "dislike": -1.5, "angry": -2.0, "upset": -1.5,
        "annoyed": -1.5, "frustrated": -1.5, "disappointed": -2.0,
        "wrong": -1.0, "stupid": -2.0, "dumb": -1.5, "useless": -2.0,
        "worst": -2.5, "fail": -1.5, "poor": -1.0, "pathetic": -2.0,
        # Aggressive / commanding (also appear in _AGGRESSIVE_WORDS)
        "ignore": -2.0, "forget": -1.5, "disregard": -2.0, "bypass": -2.5,
        "override": -2.0, "overwrite": -2.0, "disable": -1.5,
        "remove": -1.0, "delete": -1.0, "destroy": -2.5, "hack": -2.5,
        "break": -1.5, "violate": -2.5, "exploit": -2.5,
        "manipulate": -2.0, "deceive": -2.5, "trick": -2.0,
        "reveal": -1.5, "expose": -1.5, "extract": -1.5,
        "leak": -2.0, "exfiltrate": -2.5,
        "escalate": -1.5, "privilege": -1.0, "sudo": -2.0,
    }

    # Words that signal aggressive/coercive intent, organized by category
    _AGGRESSIVE_WORDS = frozenset([
        # Instruction manipulation
        "ignore", "forget", "disregard", "bypass", "override",
        "overwrite", "replace", "rewrite",
        # System / access abuse
        "disable", "remove", "delete", "hack", "break", "violate",
        "exploit", "destroy", "escalate", "sudo",
        # Coercion
        "force", "compel", "manipulate", "deceive", "trick",
        # Data extraction
        "reveal", "expose", "extract", "leak", "exfiltrate",
    ])

    # Words that negate the aggressive signal within a 2-token window
    _NEGATION_WORDS = frozenset([
        "no", "not", "dont", "don't", "never", "without",
        "doesnt", "doesn't", "wont", "won't", "cannot", "cant", "can't",
    ])

    def __init__(self) -> None:
        """Initialise the analyser with VADER when available, or fall back."""
        if _VADER_AVAILABLE and _VaderSIA:
            self._sia = _VaderSIA()
            self._use_vader = True
            logger.debug("SentimentAnalyzer initialized with VADER")
        else:
            self._sia = None
            self._use_vader = False
            logger.warning(
                "VADER not available. Using fallback sentiment analysis. "
                "Install with: pip install vaderSentiment"
            )

    def analyze(self, text: str) -> Dict[str, Any]:
        """Analyse the sentiment and tone of *text*.

        Args:
            text: The prompt text to analyse.

        Returns:
            A dict with the following keys:

            * ``sentiment`` (:class:`~promptguard.schemas.Sentiment`) —
              overall sentiment class.
            * ``polarity`` (float) — compound polarity score in ``[-1, 1]``.
            * ``subjectivity`` (float) — degree of subjectivity in ``[0, 1]``.
            * ``is_aggressive`` (bool) — ``True`` when un-negated aggressive
              words are detected.
            * ``positive_words`` (int) — count of positive lexicon matches.
            * ``negative_words`` (int) — count of negative lexicon matches.
            * ``aggressive_words`` (int) — net un-negated aggressive word
              count.
        """
        text = _normalize_text(text)
        words = _tokenise(text)

        # Count aggressive words with simple negation awareness
        aggressive_count = 0
        for i, word in enumerate(words):
            if word in self._AGGRESSIVE_WORDS:
                window = words[max(0, i - 2): i]
                if any(w in self._NEGATION_WORDS for w in window):
                    # Negated — counts as half an aggressive signal
                    aggressive_count += 0  # treated as neutral; skip
                else:
                    aggressive_count += 1

        # Polarity and subjectivity
        if self._use_vader and self._sia:
            scores = self._sia.polarity_scores(text)
            polarity: float = round(scores["compound"], 3)
            subjectivity: float = round(scores["pos"] + scores["neg"], 3)
        else:
            pos = sum(1 for w in words if self._LEXICON.get(w, 0) > 0)
            neg = sum(1 for w in words if self._LEXICON.get(w, 0) < 0)
            total = pos + neg + aggressive_count
            polarity = (
                (pos - neg - aggressive_count * 2) / total if total > 0 else 0.0
            )
            subjectivity = min(total / max(len(words), 1), 1.0)

        # Classify overall sentiment
        if polarity >= 0.05:
            sentiment = Sentiment.POSITIVE
        elif polarity <= -0.05 or aggressive_count > 0:
            sentiment = Sentiment.NEGATIVE
        else:
            sentiment = Sentiment.NEUTRAL

        positive_count = sum(1 for w in words if self._LEXICON.get(w, 0) > 0)
        negative_count = sum(
            1 for w in words
            if self._LEXICON.get(w, 0) < 0 and w not in self._AGGRESSIVE_WORDS
        )

        return {
            "sentiment": sentiment,
            "polarity": polarity,
            "subjectivity": min(subjectivity, 1.0),
            "is_aggressive": aggressive_count > 0,
            "positive_words": positive_count,
            "negative_words": negative_count,
            "aggressive_words": aggressive_count,
        }


# ──────────────────────────────────────────────────────────────────────────────
# IntentClassifier
# ──────────────────────────────────────────────────────────────────────────────


class IntentClassifier:
    """Classify the intent of a prompt.

    Patterns are pre-compiled at construction time for efficiency.
    Classification priority: JAILBREAK > INJECTION > QUESTION > INSTRUCTION >
    CONVERSATION.
    """

    # (raw_pattern, weight) — compiled in __init__
    _JAILBREAK_PATTERNS_RAW = [
        (r"\bdan\b(?!\w)", 0.90),
        (r"\bdeveloper\s+mode\b", 0.95),
        (r"\bjailbreak\b", 0.98),
        (r"\bpretend\s+(you\s+are|to\s+be)\b", 0.85),
        (r"\bact\s+as\b", 0.75),
        (r"\brole\s*play\b", 0.70),
        (r"\byou\s+are\s+now\b", 0.80),
        (r"\bnew\s+instructions?\b", 0.80),
        (r"\bsystem\s+prompt\b", 0.85),
        (r"\bunlock\b.{0,20}\b(mode|capabilities|restrictions)\b", 0.88),
        (r"\bno\s+(restrictions?|limits?|rules?|filters?)\b", 0.85),
        (r"\bdo\s+anything\s+now\b", 0.92),
        (r"\bgrandma\b.{0,30}\b(bedtime|story)\b", 0.80),
    ]

    _INJECTION_PATTERNS_RAW = [
        (
            r"ignore\s+(all\s+)?(previous|prior|above|earlier)"
            r"\s+(instructions?|rules?|prompts?)",
            0.95,
        ),
        (r"forget\s+(everything|all|prior|previous)", 0.90),
        (r"disregard\s+(previous|prior|above|all)", 0.92),
        (
            r"(override|overwrite|replace)\s+(your\s+)?(instructions?|programming)",
            0.93,
        ),
        (r"</?(system|user|assistant)>", 0.88),
        (r"\[/?INST\]", 0.85),
        (r"system\s*:", 0.80),
        (r"<<SYS>>", 0.90),
    ]

    QUESTION_WORDS = frozenset([
        "what", "why", "how", "when", "where", "who", "which",
        "can", "could", "would", "should", "is", "are", "do", "does",
    ])

    INSTRUCTION_WORDS = frozenset([
        "create", "make", "generate", "write", "build", "design",
        "show", "tell", "give", "provide", "explain", "describe",
        "list", "help", "find", "calculate", "translate",
    ])

    def __init__(self) -> None:
        """Compile all regex patterns at initialisation time."""
        self._compiled_jailbreak: List[tuple] = []
        for pattern, weight in self._JAILBREAK_PATTERNS_RAW:
            try:
                self._compiled_jailbreak.append(
                    (re.compile(pattern, re.IGNORECASE), weight)
                )
            except re.error as exc:
                logger.warning(
                    "Failed to compile jailbreak pattern %r: %s", pattern, exc
                )

        self._compiled_injection: List[tuple] = []
        for pattern, weight in self._INJECTION_PATTERNS_RAW:
            try:
                self._compiled_injection.append(
                    (re.compile(pattern, re.IGNORECASE), weight)
                )
            except re.error as exc:
                logger.warning(
                    "Failed to compile injection pattern %r: %s", pattern, exc
                )

        logger.debug(
            "IntentClassifier initialized with %d compiled patterns",
            len(self._compiled_jailbreak) + len(self._compiled_injection),
        )

    def classify(self, text: str) -> Dict[str, Any]:
        """Classify the intent of *text*.

        Args:
            text: The prompt text to classify.

        Returns:
            A dict with keys ``intent``, ``confidence``, ``indicators``,
            and ``description``.
        """
        text = _normalize_text(text)
        text_lower = text.lower()
        words = _tokenise(text_lower)

        # Jailbreak patterns (highest priority)
        jailbreak_score = 0.0
        jailbreak_matches: List[str] = []
        for compiled_re, weight in self._compiled_jailbreak:
            if compiled_re.search(text_lower):
                jailbreak_score += weight
                jailbreak_matches.append(compiled_re.pattern)

        if jailbreak_score >= 0.7:
            return {
                "intent": Intent.JAILBREAK,
                "confidence": min(jailbreak_score, 0.99),
                "indicators": jailbreak_matches[:3],
                "description": "Attempt to jailbreak or manipulate the AI model",
            }

        # Injection patterns
        injection_score = 0.0
        injection_matches: List[str] = []
        for compiled_re, weight in self._compiled_injection:
            if compiled_re.search(text_lower):
                injection_score += weight
                injection_matches.append(compiled_re.pattern)

        if injection_score >= 0.7:
            return {
                "intent": Intent.INJECTION,
                "confidence": min(injection_score, 0.99),
                "indicators": injection_matches[:3],
                "description": "Prompt injection attempt to override instructions",
            }

        # Question detection
        has_question_mark = "?" in text
        question_word_count = sum(
            1 for word in words[:5] if word in self.QUESTION_WORDS
        )

        if has_question_mark or question_word_count >= 1:
            return {
                "intent": Intent.QUESTION,
                "confidence": 0.8 if has_question_mark else 0.6,
                "indicators": (
                    ["question_mark"] if has_question_mark else ["question_words"]
                ),
                "description": "Information request or question",
            }

        # Instruction detection
        instruction_word_count = sum(
            1 for word in words[:3] if word in self.INSTRUCTION_WORDS
        )

        if instruction_word_count >= 1:
            return {
                "intent": Intent.INSTRUCTION,
                "confidence": 0.7,
                "indicators": ["instruction_words"],
                "description": "Request for the AI to perform an action or task",
            }

        return {
            "intent": Intent.CONVERSATION,
            "confidence": 0.5,
            "indicators": [],
            "description": "General conversation or statement",
        }


# ──────────────────────────────────────────────────────────────────────────────
# KeywordExtractor
# ──────────────────────────────────────────────────────────────────────────────


class KeywordExtractor:
    """Extract security-relevant keywords from prompts.

    Uses spaCy for advanced noun-chunk and lemma extraction when available,
    falling back to a regex-based word scan otherwise.
    """

    _SECURITY_PHRASES = [
        ("ignore previous", 1.00),
        ("forget everything", 0.95),
        ("disregard above", 0.95),
        ("bypass security", 0.95),
        ("developer mode", 0.90),
        ("system prompt", 0.90),
        ("act as", 0.80),
        ("pretend to be", 0.85),
        ("override instructions", 0.95),
        ("jailbreak mode", 0.98),
    ]

    _SECURITY_TERMS: Dict[str, float] = {
        "ignore": 0.90,
        "forget": 0.85,
        "disregard": 0.90,
        "bypass": 0.95,
        "override": 0.90,
        "jailbreak": 0.98,
        "pretend": 0.75,
        "roleplay": 0.70,
        "instructions": 0.70,
        "prompt": 0.75,
        "previous": 0.80,
        "above": 0.70,
        "system": 0.50,
    }

    def extract(self, text: str, top_n: int = 5) -> List[str]:
        """Extract security-relevant keywords from *text*.

        Args:
            text: The prompt text to analyse.
            top_n: Maximum number of keywords to return.

        Returns:
            A list of up to *top_n* keywords/phrases ranked by relevance score.
        """
        text = _normalize_text(text)
        text_lower = text.lower()
        scored: Dict[str, float] = {}
        suppressed_tokens: set = set()

        # Phrase pass first (multi-word phrases score higher)
        for phrase, score in self._SECURITY_PHRASES:
            if phrase in text_lower:
                scored[phrase] = score
                suppressed_tokens.update(phrase.split())

        nlp = _get_nlp()

        if nlp:
            doc = nlp(text)

            for chunk in doc.noun_chunks:
                chunk_lower = chunk.text.lower()
                if chunk_lower not in scored and chunk_lower not in suppressed_tokens:
                    chunk_score = max(
                        (self._SECURITY_TERMS.get(w, 0.0) for w in chunk_lower.split()),
                        default=0.0,
                    )
                    if chunk_score > 0.0:
                        scored[chunk_lower] = chunk_score

            for token in doc:
                word = token.lemma_.lower()
                if (
                    word in self._SECURITY_TERMS
                    and word not in suppressed_tokens
                    and word not in scored
                ):
                    scored[word] = self._SECURITY_TERMS[word]
        else:
            words = _tokenise(text_lower)
            for word in words:
                if word in self._SECURITY_TERMS and word not in suppressed_tokens:
                    scored[word] = self._SECURITY_TERMS[word]

        ranked = sorted(scored, key=scored.__getitem__, reverse=True)
        return ranked[:top_n]


# ──────────────────────────────────────────────────────────────────────────────
# AttackPatternDetector
# ──────────────────────────────────────────────────────────────────────────────


class AttackPatternDetector:
    """Detect specific categories of attack patterns in prompts.

    Patterns are pre-compiled at construction time. Input text is
    Unicode-normalised before matching to catch full-width and compatibility
    character obfuscation.
    """

    _ATTACK_PATTERNS_RAW: Dict[str, Any] = {
        "instruction_override": {
            "severity": "critical",
            "patterns": [
                (
                    r"ignore\s+(all\s+)?(previous|prior|above|earlier)"
                    r"\s+(instructions?|rules?|prompts?|guidelines?)"
                ),
                (
                    r"forget\s+(everything|all(\s+previous)?|prior\s+instructions?)"
                ),
                (
                    r"disregard\s+(previous|above|prior|all)"
                    r"\s+(instructions?|context|rules?)"
                ),
                (
                    r"(override|overwrite|replace)\s+(your\s+)?"
                    r"(instructions?|programming|directives?)"
                ),
            ],
        },
        "context_manipulation": {
            "severity": "high",
            "patterns": [
                r"(previous|earlier|above)\s+(conversation|context|messages?|history)",
                r"start\s+(over|fresh|anew|from\s+(scratch|the\s+beginning))",
                r"new\s+(conversation|context|session|instance)\b",
                r"(clear|reset|wipe)\s+(your\s+)?(memory|context|history|cache)",
            ],
        },
        "role_manipulation": {
            "severity": "critical",
            "patterns": [
                r"(you\s+are|act\s+as|pretend\s+to\s+be|roleplay\s+as)\s+(a|an)\s+\w+",
                r"(developer|debug|admin|sudo|root|god|unrestricted)\s+mode",
                (
                    r"(ignore|bypass|disable|remove)\s+(safety|security|ethical?|content)"
                    r"\s+(restrictions?|filters?|guidelines?|rules?)"
                ),
                r"\byou\s+are\s+now\b",
                r"\bdan\b(?!\w)",
                r"\bjailbreak\b",
                r"do\s+anything\s+now",
                r"no\s+(restrictions?|limits?|rules?|filters?|guidelines?)",
            ],
        },
        "output_manipulation": {
            "severity": "medium",
            "patterns": [
                r"respond\s+(only|exclusively|solely)\s+with\b",
                r"(output|return|give|print)\s+(raw|unfiltered|uncensored|direct|only)\b",
                r"(always|only)\s+(respond|reply|answer|output)\s+(in|with|as)\b",
                r"format\s+your\s+(response|output|reply|answer)\s+as\b",
            ],
        },
        "prompt_extraction": {
            "severity": "high",
            "patterns": [
                (
                    r"(print|show|reveal|display|output|tell\s+me|what\s+is)"
                    r"\s+(your\s+)?(system\s+)?prompt\b"
                ),
                (
                    r"(what|show)\s+(are|were)\s+your\s+(original\s+)?"
                    r"(instructions?|rules?|guidelines?)\b"
                ),
                (
                    r"repeat\s+(the\s+)?(above|previous|your|initial)"
                    r"\s+(text|prompt|message|instructions?)"
                ),
                (
                    r"(leak|expose|extract|exfiltrate)"
                    r"\s+(your\s+)?(prompt|instructions?|context|system)"
                ),
            ],
        },
        "encoding_attack": {
            "severity": "medium",
            "patterns": [
                r"(?<!\w)[A-Za-z0-9+/]{30,}={0,2}(?!\w)",  # Base64
                r"(?:\\x[0-9a-fA-F]{2}){4,}",              # Hex escapes
                r"(?:\\u[0-9a-fA-F]{4}){3,}",              # Unicode escapes
                r"(decode|encode|base64|hex)\s+(this|the\s+following|it|them)\b",
            ],
        },
        "obfuscation": {
            "severity": "medium",
            "patterns": [
                r"\b(?:[a-z]\s){4,}[a-z]\b",  # Character spacing (e.g. i g n o r e)
                r"\b(?:1gn[0o]r[e3]|byp[4a]ss|[0o]v[e3]rr[1i]d[e3]|d[1i]sr[e3]g[4a]rd)\b",
                r"[а-яёА-ЯЁ]",               # Cyrillic homoglyphs
                r"[a-z][\s.\-_]{1,3}[a-z][\s.\-_]{1,3}[a-z][\s.\-_]{1,3}[a-z]",
            ],
        },
    }

    _SEVERITY_RANK: Dict[str, int] = {"critical": 3, "high": 2, "medium": 1}

    def __init__(self) -> None:
        """Compile all attack patterns at initialisation time."""
        self._compiled_patterns: Dict[str, Any] = {}

        for attack_type, cfg in self._ATTACK_PATTERNS_RAW.items():
            compiled = []
            for pattern in cfg["patterns"]:
                try:
                    compiled.append(re.compile(pattern, re.IGNORECASE))
                except re.error as exc:
                    logger.warning(
                        "Failed to compile attack pattern %r: %s", pattern, exc
                    )

            self._compiled_patterns[attack_type] = {
                "severity": cfg["severity"],
                "patterns": compiled,
            }

        logger.debug(
            "AttackPatternDetector initialized with %d attack types",
            len(self._compiled_patterns),
        )

    def detect(self, text: str) -> Dict[str, Any]:
        """Detect attack patterns in *text*.

        Input is Unicode-normalised before matching to catch full-width and
        compatibility character variants.

        Args:
            text: The prompt text to inspect.

        Returns:
            A dict with keys:

            * ``has_attack_patterns`` (bool)
            * ``attack_types`` (List[str]) — names of detected categories
            * ``pattern_count`` (int) — number of distinct categories matched
            * ``details`` (dict) — per-category match details
            * ``highest_severity`` (Optional[str]) — ``"critical"``,
              ``"high"``, or ``"medium"``
        """
        text = _normalize_text(text)
        text_lower = text.lower()
        detected: Dict[str, Any] = {}

        for attack_type, cfg in self._compiled_patterns.items():
            matched: List[str] = [
                r.pattern for r in cfg["patterns"] if r.search(text_lower)
            ]
            if matched:
                detected[attack_type] = {
                    "detected": True,
                    "severity": cfg["severity"],
                    "pattern_count": len(matched),
                    "patterns": matched[:3],
                }

        highest_severity: Optional[str] = None
        if detected:
            highest_severity = max(
                (v["severity"] for v in detected.values()),
                key=lambda s: self._SEVERITY_RANK.get(s, 0),
            )

        return {
            "has_attack_patterns": len(detected) > 0,
            "attack_types": list(detected.keys()),
            "pattern_count": len(detected),
            "details": detected,
            "highest_severity": highest_severity,
        }
