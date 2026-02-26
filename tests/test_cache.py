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

    def test_lru_order_preserved(self):
        """Verify LRU eviction removes the least-recently-used item.

        Insert [p1, p2, p3] into a cache of size 3, then access p1 to promote
        it.  Adding p4 should evict p2 (now the LRU), not p1.
        """
        score = RiskScore(
            is_malicious=False,
            probability=0.1,
            risk_level=RiskLevel.LOW,
            confidence=0.8,
            explanation="Test",
        )
        cache = PromptCache(max_size=3, ttl_seconds=None)

        cache.set("p1", score)
        cache.set("p2", score)
        cache.set("p3", score)

        # Access p1 to make it the most recently used
        assert cache.get("p1") is not None

        # Adding p4 must evict p2 (the true LRU after p1 was accessed)
        cache.set("p4", score)

        assert cache.size() == 3
        assert cache.get("p1") is not None, "p1 should still be cached"
        assert cache.get("p2") is None, "p2 should have been evicted (LRU)"
        assert cache.get("p3") is not None, "p3 should still be cached"
        assert cache.get("p4") is not None, "p4 should be cached"

    def test_duplicate_set_updates_entry(self, cache, sample_risk_score):
        """Setting the same prompt twice should update, not duplicate."""
        cache.set("prompt", sample_risk_score)
        cache.set("prompt", sample_risk_score)
        assert cache.size() == 1
