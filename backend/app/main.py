from .feeds.feodo import FeodoParser
from .feeds.malwarebazaar import MalwareBazaarParser
from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
import redis.asyncio as redis
from elasticsearch import AsyncElasticsearch
from sqlalchemy import select
import uuid

from .config import settings
from . import models, database, auth, schemas, dependencies
from .feeds.urlhaus import URLHausParser

app = FastAPI(title="ThreatLens API", version="0.1.0")

# Initialize clients
redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
es_client = AsyncElasticsearch(hosts=[settings.ELASTICSEARCH_URL])

@app.on_event("startup")
async def startup_event():
    # Auto-create tables on startup
    async with database.engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)

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

@app.post("/api/v1/auth/register", response_model=schemas.UserResponse)
async def register(user: schemas.UserCreate, db: database.AsyncSession = Depends(database.get_db)):
    result = await db.execute(select(models.User).where(models.User.email == user.email))
    db_user = result.scalar_one_or_none()
    
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    count_result = await db.execute(select(models.User))
    user_count = len(count_result.scalars().all())
    role = models.RoleEnum(user.role) if user_count == 0 else models.RoleEnum.soc_analyst

    new_user = models.User(
        email=user.email,
        hashed_password=auth.get_password_hash(user.password),
        role=role
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return new_user

@app.post("/api/v1/auth/login", response_model=schemas.Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: database.AsyncSession = Depends(database.get_db)):
    result = await db.execute(select(models.User).where(models.User.email == form_data.username))
    user = result.scalar_one_or_none()
    
    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.email, "role": user.role.value}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/v1/users/me", response_model=schemas.UserResponse)
async def get_me(current_user: models.User = Depends(dependencies.get_current_user)):
    return current_user

@app.post("/api/v1/feeds/ingest/urlhaus")
async def trigger_urlhaus_ingestion(
    background_tasks: BackgroundTasks, 
    db: database.AsyncSession = Depends(database.get_db)
):
    # 1. Find or Create the URLHaus Feed config in DB
    result = await db.execute(select(models.Feed).where(models.Feed.name == "URLhaus"))
    feed = result.scalar_one_or_none()
    
    if not feed:
        feed = models.Feed(name="URLhaus", url="https://urlhaus-api.abuse.ch/", feed_type="urlhaus")
        db.add(feed)
        await db.commit()
        await db.refresh(feed)

    # 2. Queue the background task
    background_tasks.add_task(run_ingestion, feed.id)
    
    return {"message": "URLHaus ingestion started in background."}

# Helper function to run outside the request context
async def run_ingestion(feed_id: uuid.UUID):
    from .database import AsyncSessionLocal
    
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(models.Feed).where(models.Feed.id == feed_id))
        feed = result.scalar_one()
        
        parser = URLHausParser(db, feed)
        await parser.process()
        print("✅ URLHaus ingestion complete!")

@app.get("/api/v1/indicators")
async def get_indicators(db: database.AsyncSession = Depends(database.get_db)):
    result = await db.execute(select(models.Indicator))
    indicators = result.scalars().all()
    return [
        {
            "id": str(i.id), 
            "value": i.value, 
            "type": i.type, 
            "severity_score": i.severity_score
        } for i in indicators
    ][:50] # Limit to 50 for the UI

@app.post("/api/v1/feeds/ingest/feodo")
async def trigger_feodo_ingestion(background_tasks: BackgroundTasks, db: database.AsyncSession = Depends(database.get_db)):
    result = await db.execute(select(models.Feed).where(models.Feed.name == "Feodo Tracker"))
    feed = result.scalar_one_or_none()
    if not feed:
        feed = models.Feed(name="Feodo Tracker", url="https://feodotracker.abuse.ch/", feed_type="feodo")
        db.add(feed)
        await db.commit()
        await db.refresh(feed)
    background_tasks.add_task(run_ingestion_task, feed.id, "feodo")
    return {"message": "Feodo ingestion started."}

@app.post("/api/v1/feeds/ingest/malwarebazaar")
async def trigger_mb_ingestion(background_tasks: BackgroundTasks, db: database.AsyncSession = Depends(database.get_db)):
    result = await db.execute(select(models.Feed).where(models.Feed.name == "MalwareBazaar"))
    feed = result.scalar_one_or_none()
    if not feed:
        feed = models.Feed(name="MalwareBazaar", url="https://bazaar.abuse.ch/", feed_type="malwarebazaar")
        db.add(feed)
        await db.commit()
        await db.refresh(feed)
    background_tasks.add_task(run_ingestion_task, feed.id, "malwarebazaar")
    return {"message": "MalwareBazaar ingestion started."}

# Update the helper function to handle different feed types
async def run_ingestion_task(feed_id: uuid.UUID, feed_type: str):
    from .database import AsyncSessionLocal
    
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(models.Feed).where(models.Feed.id == feed_id))
        feed = result.scalar_one()
        
        if feed_type == "urlhaus":
            from .feeds.urlhaus import URLHausParser
            parser = URLHausParser(db, feed)
        elif feed_type == "feodo":
            parser = FeodoParser(db, feed)
        elif feed_type == "malwarebazaar":
            parser = MalwareBazaarParser(db, feed)
            
        await parser.process()
        print(f"✅ {feed_type} ingestion complete!")