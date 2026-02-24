"""Caching system for PromptGuard to avoid re-analyzing identical prompts."""

import hashlib
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import json
import logging

from .schemas import RiskScore, RiskLevel

logger = logging.getLogger(__name__)


class PromptCache:
    """
    Simple in-memory cache for prompt analysis results.

    Uses prompt hash as key to detect duplicate prompts.
    """

    def __init__(self, max_size: int = 10000, ttl_seconds: Optional[int] = 3600):
        """
        Initialize cache.
        """
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._access_order: list = []  # For LRU eviction

        logger.info(
            "Cache initialized (max_size=%s, ttl=%ss)",
            max_size,
            ttl_seconds,
        )

    def _hash_prompt(self, prompt: str) -> str:
        """Generate hash for prompt."""
        return hashlib.md5(prompt.encode('utf-8')).hexdigest()

    def get(self, prompt: str) -> Optional[RiskScore]:
        """
        Get cached result for prompt.
        """
        key = self._hash_prompt(prompt)

        if key not in self._cache:
            return None

        entry = self._cache[key]

        # Check expiration
        if self.ttl_seconds is not None:
            cached_time = entry['timestamp']
            age = (datetime.now() - cached_time).total_seconds()

            if age > self.ttl_seconds:
                logger.debug(
                    "Cache entry expired (age=%.1fs)",
                    age,
                )
                self._cache.pop(key)
                if key in self._access_order:
                    self._access_order.remove(key)
                return None

        # Update access order for LRU
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)

        logger.debug("Cache hit")
        return self._deserialize_result(entry['result'])

    def set(self, prompt: str, result: RiskScore):
        """
        Cache a result.
        """
        key = self._hash_prompt(prompt)

        # Evict oldest entry if at capacity
        if len(self._cache) >= self.max_size and key not in self._cache:
            if self._access_order:
                oldest_key = self._access_order.pop(0)
                self._cache.pop(oldest_key, None)
                logger.debug("Cache eviction (LRU)")

        self._cache[key] = {
            'result': self._serialize_result(result),
            'timestamp': datetime.now()
        }

        # Update access order
        if key in self._access_order:
            self._access_order.remove(key)
        self._access_order.append(key)

        logger.debug(
            "Cached result (total entries: %s)",
            len(self._cache),
        )

    def _serialize_result(self, result: RiskScore) -> Dict[str, Any]:
        """Convert RiskScore to dict for caching."""
        return result.to_dict()

    def _deserialize_result(self, data: Dict[str, Any]) -> RiskScore:
        """Convert cached dict back to RiskScore."""
        return RiskScore(
            is_malicious=data['is_malicious'],
            probability=data['probability'],
            risk_level=RiskLevel(data['risk_level']),
            confidence=data['confidence'],
            explanation=data['explanation'],
            metadata=data.get('metadata', {})
        )

    def clear(self):
        """Clear all cached entries."""
        self._cache.clear()
        self._access_order.clear()
        logger.info("Cache cleared")

    def size(self) -> int:
        """Get number of cached entries."""
        return len(self._cache)

    def stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        return {
            'size': len(self._cache),
            'max_size': self.max_size,
            'ttl_seconds': self.ttl_seconds,
            'oldest_entry_age': self._get_oldest_age()
        }

    def _get_oldest_age(self) -> Optional[float]:
        """Get age of oldest cache entry in seconds."""
        if not self._cache:
            return None

        oldest_time = min(entry['timestamp'] for entry in self._cache.values())
        return (datetime.now() - oldest_time).total_seconds()
