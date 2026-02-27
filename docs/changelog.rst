Changelog
=========

All notable changes to PromptGuard are documented here.
The format follows `Keep a Changelog <https://keepachangelog.com/en/1.0.0/>`_
and the project adheres to `Semantic Versioning <https://semver.org/spec/v2.0.0.html>`_.

----

0.1.0 — 2026
-------------

Initial public release.

**Added**

- :class:`~promptguard.PromptGuard` — main classifier wrapping a fine-tuned
  DistilBERT model hosted on HuggingFace Hub
  (``arkaean/promptguard-distilbert``).
- :meth:`~promptguard.PromptGuard.analyze` and
  :meth:`~promptguard.PromptGuard.analyze_batch` for single-prompt and
  batch classification returning :class:`~promptguard.RiskScore`.
- :meth:`~promptguard.PromptGuard.classify` /
  :meth:`~promptguard.PromptGuard.classify_batch` for lightweight boolean
  classification.
- :meth:`~promptguard.PromptGuard.sanitize` and
  :meth:`~promptguard.PromptGuard.sanitize_if_malicious` with
  ``CONSERVATIVE``, ``BALANCED``, and ``MINIMAL`` sanitisation strategies.
- :class:`~promptguard.SentimentAnalyzer` with VADER integration, extended
  aggressive-word vocabulary, and negation-aware scoring.
- :class:`~promptguard.IntentClassifier` for JAILBREAK / INJECTION / QUESTION
  / INSTRUCTION / CONVERSATION classification.
- :class:`~promptguard.KeywordExtractor` with optional spaCy noun-chunk
  extraction.
- :class:`~promptguard.AttackPatternDetector` covering six attack categories
  (instruction override, role manipulation, context manipulation, prompt
  extraction, output manipulation, encoding/obfuscation attacks).
- NFKC Unicode normalisation in all analysers and the sanitiser to neutralise
  full-width character obfuscation.
- :class:`~promptguard.PromptCache` — O(1) LRU cache with configurable size
  and TTL, implemented with ``collections.OrderedDict``.
- :class:`~promptguard.SanitizeResponse` typed dataclass (replaces raw
  ``dict`` return).
- :class:`~promptguard.AdvancedSanitizer` with intent-aware strategy selection
  and alternative-rephrasing suggestions.
- PEP 561 ``py.typed`` marker and ``__init__.pyi`` type stub.
- ``promptguard.utils``: ``summarize_results``, ``filter_by_risk_level``,
  ``get_most_dangerous``, ``export_to_csv``, ``results_to_dataframe``.
- Pre-commit hooks (black, flake8, mypy) and 85 % coverage requirement.
- Sphinx documentation with Furo theme, auto-deployed to GitHub Pages.
