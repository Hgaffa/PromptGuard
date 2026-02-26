"""Caching system for PromptGuard to avoid re-analysing identical prompts."""

import hashlib
import logging
from collections import OrderedDict
from datetime import datetime
from typing import Any, Dict, Optional

from .schemas import RiskLevel, RiskScore

logger = logging.getLogger(__name__)


class PromptCache:
    """
    In-memory LRU cache for prompt analysis results.

    Uses MD5 hash of the prompt text as the cache key.  Entries are evicted in
    least-recently-used order when the cache reaches ``max_size``.  An optional
    TTL causes stale entries to be discarded on read.

    Args:
        max_size: Maximum number of entries to hold before evicting the LRU
            entry. Must be a positive integer. Defaults to 10 000.
        ttl_seconds: Optional time-to-live in seconds.  Entries older than this
            value are treated as cache misses and silently removed.  Pass
            ``None`` (the default) to disable expiry.
    """

    def __init__(
        self,
        max_size: int = 10_000,
        ttl_seconds: Optional[int] = 3600,
    ) -> None:
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        # OrderedDict preserves insertion/access order for O(1) LRU operations.
        # Each value is {"result": dict, "timestamp": datetime}.
        self._cache: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        logger.info(
            "Cache initialised (max_size=%s, ttl=%ss)",
            max_size,
            ttl_seconds,
        )

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def get(self, prompt: str) -> Optional[RiskScore]:
        """Return the cached ``RiskScore`` for *prompt*, or ``None`` on miss.

        A miss is returned when:
        * the prompt has never been cached, or
        * the cached entry has exceeded ``ttl_seconds``.
        """
        key = self._hash_prompt(prompt)

        if key not in self._cache:
            return None

        entry = self._cache[key]

        # Check TTL expiry
        if self.ttl_seconds is not None:
            age = (datetime.now() - entry["timestamp"]).total_seconds()
            if age > self.ttl_seconds:
                logger.debug("Cache entry expired (age=%.1fs)", age)
                del self._cache[key]
                return None

        # Move to end to mark as most recently used (O(1))
        self._cache.move_to_end(key)
        logger.debug("Cache hit")
        return self._deserialize_result(entry["result"])

    def set(self, prompt: str, result: RiskScore) -> None:
        """Store *result* in the cache keyed by *prompt*.

        If the cache is at capacity, the least-recently-used entry is evicted
        before the new entry is inserted.
        """
        key = self._hash_prompt(prompt)

        if key in self._cache:
            # Update existing entry and move to MRU position
            self._cache[key] = {
                "result": self._serialize_result(result),
                "timestamp": datetime.now(),
            }
            self._cache.move_to_end(key)
        else:
            # Evict LRU entry when at capacity (popitem(last=False) is O(1))
            if len(self._cache) >= self.max_size:
                self._cache.popitem(last=False)
                logger.debug("Cache eviction (LRU)")

            self._cache[key] = {
                "result": self._serialize_result(result),
                "timestamp": datetime.now(),
            }

        logger.debug("Cached result (total entries: %s)", len(self._cache))

    def clear(self) -> None:
        """Remove all cached entries."""
        self._cache.clear()
        logger.info("Cache cleared")

    def size(self) -> int:
        """Return the number of currently cached entries."""
        return len(self._cache)

    def stats(self) -> Dict[str, Any]:
        """Return a dictionary of cache statistics."""
        return {
            "size": len(self._cache),
            "max_size": self.max_size,
            "ttl_seconds": self.ttl_seconds,
            "oldest_entry_age": self._get_oldest_age(),
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _hash_prompt(prompt: str) -> str:
        """Return the MD5 hex-digest of *prompt* (used as cache key)."""
        return hashlib.md5(prompt.encode("utf-8")).hexdigest()

    @staticmethod
    def _serialize_result(result: RiskScore) -> Dict[str, Any]:
        """Convert a ``RiskScore`` to a plain dict for storage."""
        return result.to_dict()

    @staticmethod
    def _deserialize_result(data: Dict[str, Any]) -> RiskScore:
        """Reconstruct a ``RiskScore`` from a stored dict."""
        return RiskScore(
            is_malicious=data["is_malicious"],
            probability=data["probability"],
            risk_level=RiskLevel(data["risk_level"]),
            confidence=data["confidence"],
            explanation=data["explanation"],
            metadata=data.get("metadata", {}),
        )

    def _get_oldest_age(self) -> Optional[float]:
        """Return the age of the oldest cache entry in seconds, or ``None``."""
        if not self._cache:
            return None
        oldest_time = min(e["timestamp"] for e in self._cache.values())
        return (datetime.now() - oldest_time).total_seconds()
