import redis
from .config import settings

# Synchronous Redis client for background tasks/caching
redis_client = redis.Redis.from_url(settings.REDIS_URL, decode_responses=True)

# Async Redis client for the FastAPI app (if needed later)
import redis.asyncio as aioredis
async_redis_client = aioredis.Redis.from_url(settings.REDIS_URL, decode_responses=True)