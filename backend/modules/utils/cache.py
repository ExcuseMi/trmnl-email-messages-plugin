"""
Cache utilities for email data
"""
import json
import hashlib
import redis
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class CacheManager:
    """Manages Redis caching for email data"""

    def __init__(self, redis_host: str, redis_port: int, redis_db: int,
                 ttl_seconds: int, enabled: bool = True):
        self.enabled = enabled
        self.ttl_seconds = ttl_seconds
        self.redis_client = None

        if enabled:
            self._connect(redis_host, redis_port, redis_db)

    def _connect(self, host: str, port: int, db: int):
        """Connect to Redis with retry logic"""
        max_attempts = 3
        for attempt in range(1, max_attempts + 1):
            try:
                client = redis.Redis(
                    host=host,
                    port=port,
                    db=db,
                    decode_responses=True,
                    socket_connect_timeout=2,
                    socket_timeout=2
                )
                client.ping()
                logger.info(f"✓ Redis connected at {host}:{port}")
                self.redis_client = client
                return
            except redis.ConnectionError:
                if attempt < max_attempts:
                    logger.debug(f"Redis connection attempt {attempt}/{max_attempts} failed")
                else:
                    logger.warning("✗ Redis unavailable - cache disabled")
                    self.enabled = False
            except Exception as e:
                logger.warning(f"✗ Redis error: {e} - cache disabled")
                self.enabled = False
                return

    def generate_key(self, prefix: str, params: Dict[str, Any]) -> str:
        """Generate cache key from parameters"""
        cache_str = json.dumps(params, sort_keys=True)
        cache_hash = hashlib.md5(cache_str.encode()).hexdigest()
        return f"{prefix}:{cache_hash}"

    def get(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached data"""
        if not self.enabled or not self.redis_client:
            return None

        try:
            cached_json = self.redis_client.get(cache_key)
            if cached_json:
                return json.loads(cached_json)
            return None
        except Exception as e:
            logger.error(f"✗ Cache read error: {e}")
            return None

    def set(self, cache_key: str, data: Dict[str, Any]) -> bool:
        """Store data in cache"""
        if not self.enabled or not self.redis_client:
            return False

        try:
            self.redis_client.setex(
                cache_key,
                self.ttl_seconds,
                json.dumps(data)
            )
            return True
        except Exception as e:
            logger.error(f"✗ Cache write error: {e}")
            return False