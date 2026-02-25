"""Tests for utility functions."""

import pytest
from promptguard.utils import (
    summarize_results,
    filter_by_risk_level,
    get_most_dangerous
)
from promptguard import PromptGuard


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
