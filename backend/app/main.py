from fastapi import FastAPI
from pydantic_settings import BaseSettings
import redis.asyncio as redis
from elasticsearch import AsyncElasticsearch

class Settings(BaseSettings):
    DATABASE_URL: str
    REDIS_URL: str
    ELASTICSEARCH_URL: str
    ENVIRONMENT: str = "local"

    class Config:
        env_file = ".env"

settings = Settings()
app = FastAPI(title="ThreatLens API", version="0.1.0")

# Initialize clients
redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
es_client = AsyncElasticsearch(hosts=[settings.ELASTICSEARCH_URL])

@app.get("/health")
async def health_check():
    try:
        await redis_client.ping()
        es_health = await es_client.cluster.health()
        return {
            "status": "healthy",
            "environment": settings.ENVIRONMENT,
            "redis": "connected",
            "elasticsearch": es_health.get("status", "unknown"),
            "database": "connected"
        }
    except Exception as e:
        return {"status": "degraded", "error": str(e)}