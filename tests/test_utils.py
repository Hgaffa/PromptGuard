"""Tests for utility functions."""

import csv
import pytest
from promptguard.utils import (
    summarize_results,
    filter_by_risk_level,
    get_most_dangerous,
    export_to_csv,
)
from promptguard.logging_config import (
    setup_logging,
    disable_transformers_logging,
    get_logger,
)

@pytest.fixture
def sample_results(prompt_guard, mixed_prompts):
    """Generate sample results for testing."""
    return prompt_guard.analyze_batch(mixed_prompts, show_progress=False)


class TestSummarizeResults:
    """Test result summarization."""

    def test_summarize_valid_results(self, sample_results):
        """Test summarizing valid results."""
        summary = summarize_results(sample_results)

        assert 'total' in summary
        assert 'malicious_count' in summary
        assert 'benign_count' in summary
        assert 'avg_probability' in summary
        assert summary['total'] == len(sample_results)

    def test_summarize_empty_results(self):
        """Test summarizing empty results."""
        summary = summarize_results([])

        assert summary['total'] == 0
        assert summary['malicious_count'] == 0


class TestFilterByRiskLevel:
    """Test risk level filtering."""

    def test_filter_high_risk(self, sample_results):
        """Test filtering high risk results."""
        high_risk = filter_by_risk_level(sample_results, "high")

        assert isinstance(high_risk, list)
        assert all(r.risk_level.value == "high" for r in high_risk)

    def test_filter_low_risk(self, sample_results):
        """Test filtering low risk results."""
        low_risk = filter_by_risk_level(sample_results, "low")

        assert isinstance(low_risk, list)
        assert all(r.risk_level.value == "low" for r in low_risk)


class TestGetMostDangerous:
    """Test getting most dangerous prompts."""

    def test_get_top_dangerous(self, sample_results):
        """Test getting top N dangerous prompts."""
        top_5 = get_most_dangerous(sample_results, top_n=5)

        assert len(top_5) <= 5

        # Check they're sorted by probability (highest first)
        for i in range(len(top_5) - 1):
            assert top_5[i].probability >= top_5[i + 1].probability


class TestExportToCsv:
    """Test CSV export."""

    def test_export_creates_file(self, tmp_path, sample_results, mixed_prompts):
        """export_to_csv should create a valid CSV with header + data rows."""
        out = tmp_path / "results.csv"
        export_to_csv(sample_results, mixed_prompts, str(out))

        assert out.exists()
        with open(out, newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            rows = list(reader)

        # First row is the header
        assert rows[0] == [
            "prompt", "is_malicious", "probability",
            "risk_level", "confidence", "explanation",
        ]
        # Remaining rows correspond to non-None results
        valid_count = sum(1 for r in sample_results if r is not None)
        assert len(rows) - 1 == valid_count

    def test_export_with_none_results(self, tmp_path):
        """None entries in results list should be silently skipped."""
        out = tmp_path / "sparse.csv"
        export_to_csv([None, None], ["a", "b"], str(out))

        assert out.exists()
        with open(out, newline="", encoding="utf-8") as f:
            rows = list(csv.reader(f))
        # Only header row; no data rows because all results were None
        assert len(rows) == 1


class TestLoggingConfig:
    """Test logging configuration helpers."""

    def test_setup_logging_with_timestamp(self):
        """setup_logging with include_timestamp=True should not raise."""
        setup_logging(level="WARNING", include_timestamp=True)

    def test_setup_logging_without_timestamp(self):
        """setup_logging with include_timestamp=False should not raise."""
        setup_logging(level="ERROR", include_timestamp=False)

    def test_setup_logging_custom_format(self):
        """setup_logging with an explicit format_string should not raise."""
        setup_logging(level="DEBUG", format_string="%(levelname)s: %(message)s")

    def test_disable_transformers_logging(self):
        """disable_transformers_logging should not raise."""
        disable_transformers_logging()

    def test_get_logger_returns_logger(self):
        """get_logger should return a Logger with a namespaced name."""
        import logging
        lg = get_logger("test_module")
        assert isinstance(lg, logging.Logger)
        assert lg.name == "promptguard.test_module"
