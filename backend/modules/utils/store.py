"""
Key-value store with expiry: Redis, or per-process memory when Redis is unavailable
"""
import logging
import time

import redis

logger = logging.getLogger(__name__)


def connect_redis(host: str, port: int, db: int):
    """A Redis client, or None after three failed attempts"""
    for attempt in range(1, 4):
        try:
            client = redis.Redis(host=host, port=port, db=db, decode_responses=True,
                                 socket_connect_timeout=2, socket_timeout=2)
            client.ping()
            logger.info(f"✓ Redis connected at {host}:{port}")
            return client
        except redis.RedisError as e:
            logger.debug(f"Redis connection attempt {attempt}/3 failed: {e}")
    logger.warning("✗ Redis unavailable")
    return None


class MemoryStore:
    """Per-process stand-in when Redis is unavailable, so the limit never fails open"""

    def __init__(self):
        self.values = {}

    def _live(self, key):
        value, expires = self.values.get(key, (None, 0))
        if expires and expires < time.time():
            self.values.pop(key, None)
            return None
        return value

    def get(self, key):
        return self._live(key)

    def incr(self, key):
        value = int(self._live(key) or 0) + 1
        expires = self.values.get(key, (None, 0))[1]
        self.values[key] = (value, expires)
        return value

    def expire(self, key, seconds):
        if key in self.values:
            self.values[key] = (self.values[key][0], time.time() + seconds)

    def setex(self, key, seconds, value):
        self.values[key] = (value, time.time() + seconds)

    def set(self, key, value, nx=False, ex=None):
        if nx and self._live(key) is not None:
            return None
        self.values[key] = (value, time.time() + ex if ex else 0)
        return True

    def delete(self, key):
        self.values.pop(key, None)
