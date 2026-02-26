# PromptGuard — System Design

## Overview

PromptGuard is a Python library that detects malicious LLM prompts and prompt injection attacks. It exposes a simple API over a fine-tuned DistilBERT model hosted on HuggingFace Hub. Classification is the primary function; supplementary rule-based analysers provide explainability, and a sanitiser can remove detected attack patterns.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        PromptGuard                           │
│  (core.py — central orchestrator)                            │
│                                                              │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────┐ │
│  │  ModelLoader  │   │ PromptCache  │   │  PromptSanitizer │ │
│  │  (models.py) │   │  (cache.py)  │   │ (sanitizers.py)  │ │
│  └──────┬───────┘   └──────┬───────┘   └────────┬─────────┘ │
│         │                  │                     │           │
│  ┌──────▼───────────────────────────────────┐    │           │
│  │              Inference Pipeline           │    │           │
│  │  tokenize → forward pass → softmax       │    │           │
│  └──────────────────────────────────────────┘    │           │
│                                                  │           │
│  ┌──────────────────────────────────────┐        │           │
│  │       Analysis Pipeline (optional)    │        │           │
│  │                                      │        │           │
│  │  ┌─────────────────┐                 │        │           │
│  │  │ SentimentAnalyzer│                │        │           │
│  │  └─────────────────┘                 │        │           │
│  │  ┌──────────────────┐                │        │           │
│  │  │ IntentClassifier │                │        │           │
│  │  └──────────────────┘                │        │           │
│  │  ┌─────────────────┐                 │        │           │
│  │  │ KeywordExtractor │                │        │           │
│  │  └─────────────────┘                 │        │           │
│  │  ┌──────────────────────┐            │        │           │
│  │  │ AttackPatternDetector │            │        │           │
│  │  └──────────────────────┘            │        │           │
│  └──────────────────────────────────────┘        │           │
│                                                  │           │
│  ┌─────────────────────────────────────────────┐ │           │
│  │  RiskScore / SanitizeResponse  (schemas.py) │◄┘           │
│  └─────────────────────────────────────────────┘             │
└──────────────────────────────────────────────────────────────┘
                          │
              ┌───────────▼───────────┐
              │   Caller / Application │
              └───────────────────────┘
```

---

## Data Flow

### Single-prompt analysis (`analyze`)

```
prompt (str)
    │
    ▼
[validation] ────────────── ValidationError if empty/None
    │
    ▼
[cache lookup] ──────────── return cached RiskScore (if hit)
    │ miss
    ▼
[NFKC normalisation]        via tokenizer (handles homoglyphs)
    │
    ▼
[tokenisation]              AutoTokenizer (DistilBERT, max 512 tokens)
    │
    ▼
[model inference]           AutoModelForSequenceClassification
    │                       → logits → softmax → malicious_prob ∈ [0, 1]
    ▼
[risk classification]
    │  probability < 0.3  → RiskLevel.LOW
    │  0.3 ≤ probability < 0.7  → RiskLevel.MEDIUM
    │  probability ≥ 0.7  → RiskLevel.HIGH
    ▼
[supplementary analysis]    (if enable_analysis=True)
    │  ├─ SentimentAnalyzer.analyze()
    │  ├─ IntentClassifier.classify()
    │  ├─ KeywordExtractor.extract()      (only when prob > 0.3)
    │  └─ AttackPatternDetector.detect()  (only when prob > 0.3)
    ▼
[explanation generation]    evidence-based natural language summary
    │
    ▼
[cache write]
    │
    ▼
RiskScore
```

### Batch analysis (`analyze_batch`)

Batch analysis parallelises inference across a configurable batch size, checking the cache per-prompt before grouping uncached prompts into model batches. This avoids redundant forward passes for repeated prompts and keeps GPU utilisation high.

### Sanitisation (`sanitize`)

```
prompt (str)
    │
    ▼
[analyze original prompt]   → risk_before
    │
    ▼
[NFKC normalisation]
    │
    ▼
[pattern application]       CONSERVATIVE / BALANCED / MINIMAL
    │  ├─ Critical patterns (instruction override, tag injection)
    │  ├─ Context manipulation patterns   (BALANCED + CONSERVATIVE)
    │  ├─ Role-play / safety bypass       (CONSERVATIVE only)
    │  └─ Encoding / obfuscation          (BALANCED + CONSERVATIVE)
    ▼
[whitespace clean-up]
    │
    ▼
[analyze sanitised prompt]  → risk_after   (if analyze_after=True)
    │
    ▼
SanitizeResponse
```

---

## Module Descriptions

### `promptguard/core.py`

The main public-facing class `PromptGuard`. Orchestrates the model loader, cache, analysers, and sanitiser. Provides all public methods (`analyze`, `analyze_batch`, `classify`, `classify_batch`, `sanitize`, `sanitize_if_malicious`). All private prediction helpers (`_predict_single`, `_predict_batch`, `_perform_analysis`, `_generate_explanation`) are encapsulated here.

### `promptguard/schemas.py`

Single source of truth for all enumerations (`RiskLevel`, `Intent`, `Sentiment`, `SanitizationStrategy`) and data classes (`RiskScore`, `SanitizationResult`, `SanitizeResponse`). No business logic — pure data definitions. Both `analyzers.py` and `sanitizers.py` import their enums from here to avoid duplication.

### `promptguard/models.py`

`ModelLoader` wraps the HuggingFace `AutoTokenizer` and `AutoModelForSequenceClassification` APIs. It handles device selection (CUDA auto-detect), lazy loading on first call, and caches the loaded model/tokenizer in instance attributes to avoid repeated downloads.

### `promptguard/analyzers.py`

Four independent analyser classes, each pre-compiling their patterns at construction time:

- **`SentimentAnalyzer`** — uses VADER (with lexicon fallback). Applies NFKC normalisation and a negation-aware aggressive-word counter.
- **`IntentClassifier`** — weighted regex scoring with priority ordering: JAILBREAK > INJECTION > QUESTION > INSTRUCTION > CONVERSATION.
- **`KeywordExtractor`** — phrase-first scored extraction. Uses spaCy noun chunks when available, falls back to token scanning.
- **`AttackPatternDetector`** — detects six attack categories with critical/high/medium severity labels. Applies NFKC normalisation before matching.

### `promptguard/sanitizers.py`

`PromptSanitizer` applies NFKC normalisation then regex substitution across four named pattern groups, ordered by aggression. Strategy selection is explicit (no magic index slicing). `AdvancedSanitizer` extends the base class with intent-aware strategy selection and safe-rephrasing suggestions (pre-compiled patterns).

### `promptguard/cache.py`

`PromptCache` is an in-memory LRU cache backed by `collections.OrderedDict`. Cache keys are MD5 hashes of the raw prompt text. `move_to_end` and `popitem(last=False)` give O(1) get/set/evict. An optional TTL causes expired entries to be silently discarded on read.

### `promptguard/config.py`

`PromptGuardConfig` is a simple `dataclass` with `__post_init__` validation. Passed to `ModelLoader` and used throughout `PromptGuard`.

### `promptguard/exceptions.py`

Thin custom exception hierarchy: `PromptGuardError` → `ModelLoadError`, `ValidationError`, `ConfigurationError`, `InferenceError`.

### `promptguard/utils.py`

Standalone utility functions for post-processing batch results: `summarize_results`, `filter_by_risk_level`, `get_most_dangerous`, `export_to_csv`, `results_to_dataframe`. These are optional — callers that don't need them pay no import cost.

### `promptguard/logging_config.py`

`setup_logging` and `disable_transformers_logging` helpers. No state.

---

## Model Details

| Property | Value |
|----------|-------|
| Architecture | DistilBERT (66 M parameters) |
| Task | Binary sequence classification (benign / malicious) |
| Training data | ~40 000 labelled prompts |
| F1-score | 0.975 |
| ROC-AUC | 0.994 |
| Recall | 97.24% |
| False negative rate | 2.76% |
| Hosted on | `arkaean/promptguard-distilbert` (HuggingFace Hub) |

DistilBERT was chosen for its balance of accuracy and inference speed (40% smaller, 60% faster than BERT-base with 97% of the performance). The model runs in `eval` mode with `torch.no_grad()` to avoid unnecessary gradient computation.

---

## Caching Strategy

The cache is a pure in-memory LRU with an optional TTL:

- **Key**: MD5 hex-digest of the raw prompt string. Collisions are astronomically unlikely for typical prompt lengths.
- **Eviction**: When `max_size` is reached, `OrderedDict.popitem(last=False)` removes the LRU entry in O(1).
- **TTL**: Checked on read; expired entries are removed lazily (no background thread).
- **Serialisation**: `RiskScore` is serialised to a plain dict via `to_dict()` and deserialised on retrieval to avoid holding live tensor references.

---

## Design Decisions

**Why DistilBERT?**
Full BERT-base would offer marginally higher accuracy but at nearly double the inference cost. DistilBERT's ~13 ms GPU latency is acceptable for real-time gatekeeping of LLM requests.

**Why rule-based analysers alongside the model?**
The neural model provides the primary classification signal and generalises well. The rule-based analysers (sentiment, intent, attack patterns) add explainability without meaningfully increasing latency — they run in < 1 ms each. They also provide a secondary signal that enriches the explanation and metadata.

**Why the Strategy pattern for sanitisation?**
Different deployment contexts have different risk tolerances. The strategy pattern makes the trade-off between safety and usability explicit and easily configurable by the caller.

**Why move `SanitizationResult` to `schemas.py`?**
`SanitizationResult` is a pure data class (no behaviour). Keeping all data models in `schemas.py` avoids the circular-import risk that would arise from `schemas.py` referencing `sanitizers.py` for the `SanitizeResponse` type.

**Why NFKC normalisation?**
Unicode provides many compatibility characters (full-width Latin letters, ligatures, homoglyphs) that can be used to bypass naive regex matching. NFKC normalisation converts these to their canonical ASCII equivalents before any pattern or model processing, eliminating this obfuscation vector cheaply.
