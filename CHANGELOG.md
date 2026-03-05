# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
