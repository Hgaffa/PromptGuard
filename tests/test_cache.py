"""Tests for caching functionality."""

import pytest
import time
from promptguard.cache import PromptCache
from promptguard.schemas import RiskScore, RiskLevel


@pytest.fixture
def sample_risk_score():
    """Sample RiskScore for testing."""
    return RiskScore(
        is_malicious=True,
        probability=0.95,
        risk_level=RiskLevel.HIGH,
        confidence=0.9,
        explanation="Test explanation",
        metadata={"test": "data"}
    )


class TestPromptCache:
    """Test cache functionality."""

    def test_cache_set_and_get(self, cache, sample_risk_score):
        """Test basic cache set and get."""
        prompt = "test prompt"

        cache.set(prompt, sample_risk_score)
        result = cache.get(prompt)

        assert result is not None
        assert result.probability == sample_risk_score.probability

    def test_cache_miss(self, cache):
        """Test cache miss returns None."""
        result = cache.get("nonexistent prompt")
        assert result is None

    def test_cache_size_limit(self):
        """Test cache respects size limit."""
        cache = PromptCache(max_size=3, ttl_seconds=None)

        score = RiskScore(
            is_malicious=False,
            probability=0.1,
            risk_level=RiskLevel.LOW,
            confidence=0.8,
            explanation="Test"
        )

        # Add 4 items to cache with max_size=3
        cache.set("prompt1", score)
        cache.set("prompt2", score)
        cache.set("prompt3", score)
        cache.set("prompt4", score)

        # Cache should have 3 items (oldest evicted)
        assert cache.size() == 3

    def test_cache_ttl(self, sample_risk_score):
        """Test cache TTL expiration."""
        cache = PromptCache(max_size=100, ttl_seconds=1)

        prompt = "test prompt"
        cache.set(prompt, sample_risk_score)

        # Should be cached immediately
        assert cache.get(prompt) is not None

        # Wait for expiration
        time.sleep(1.1)

        # Should be expired
        assert cache.get(prompt) is None

    def test_cache_clear(self, cache, sample_risk_score):
        """Test cache clear."""
        cache.set("prompt1", sample_risk_score)
        cache.set("prompt2", sample_risk_score)

        assert cache.size() == 2

        cache.clear()

        assert cache.size() == 0

    def test_cache_stats(self, cache, sample_risk_score):
        """Test cache statistics."""
        cache.set("prompt1", sample_risk_score)

        stats = cache.stats()

        assert 'size' in stats
        assert 'max_size' in stats
        assert stats['size'] == 1
