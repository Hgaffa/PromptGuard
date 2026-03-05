# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-03-05

### Fixed
- `classify_batch`: threshold value of `0.0` was treated as falsy, silently falling back to the default threshold
- `summarize_results` / `filter_by_risk_level` / `get_most_dangerous`: type hints corrected to accept `List[Optional[RiskScore]]`, matching the actual output of `analyze_batch`
- `summarize_results`: `np.mean` / `min` / `max` / `std` results now wrapped in `float()` to prevent `numpy.float64` JSON serialisation errors
- `clear_cache`, `setup_logging`, and `disable_transformers_logging` missing `-> None` return type annotations (mypy warnings)

### Changed
- Package published to PyPI as **promptguard-ml** (`pip install promptguard-ml`)
- `spacy` moved from required dependencies to optional extra: `pip install promptguard-ml[nlp]`
- Added `[full]` optional extra (`spacy` + `pandas`) for all optional features
- `pyproject.toml`: added `py.typed` and `*.pyi` to package data (PEP 561 wheel compliance)
- `pyproject.toml`: added Python 3.12 / 3.13 classifiers and `Topic :: Security` classifier
- `pyproject.toml`: updated `license` field to SPDX string format (deprecation fix)
- `setup.py` replaced with minimal shim — all metadata now lives exclusively in `pyproject.toml`
- README updated with correct package name, PyPI badge, and optional-extra install instructions

### Added
- `CHANGELOG.md` — this file
- `RELEASING.md` — step-by-step guide for publishing future releases
## [0.1.0] - 2026-03-05

### Added
- Initial release of PromptGuard
- `PromptGuard` core classifier backed by fine-tuned DistilBERT (`arkaean/promptguard-distilbert`)
- Single-prompt and batch analysis (`analyze`, `analyze_batch`)
- Binary classification helpers (`classify`, `classify_batch`)
- Three-tier prompt sanitisation (`CONSERVATIVE`, `BALANCED`, `MINIMAL` strategies)
- `AdvancedSanitizer` with intent-aware cleaning and safe-rephrasing suggestions
- Supplementary analysers: `SentimentAnalyzer`, `IntentClassifier`, `KeywordExtractor`, `AttackPatternDetector`
- In-memory LRU cache with TTL support (`PromptCache`)
- Utility functions: `summarize_results`, `filter_by_risk_level`, `get_most_dangerous`, `export_to_csv`, `results_to_dataframe`
- PEP 561 compliance (`py.typed` marker and `__init__.pyi` type stubs)
- Unicode NFKC normalisation throughout to catch full-width character obfuscation attacks
