from sqlalchemy.orm import selectinload
from fastapi import FastAPI, Depends, HTTPException, status, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta, datetime
import redis.asyncio as redis
from elasticsearch import AsyncElasticsearch
from sqlalchemy import select
import uuid
import time
import asyncio

from .config import settings
from . import models, database, auth, schemas, dependencies
from .feeds.urlhaus import URLHausParser
from .feeds.feodo import FeodoParser
from .feeds.malwarebazaar import MalwareBazaarParser
from .services.es_sync import create_index_if_not_exists, search_indicators
from .services.redis_pubsub import redis_pubsub_listener
from .services.alert_engine import AlertRuleEngine
from .websocket_manager import manager

app = FastAPI(title="ThreatLens API", version="0.1.0")

# Initialize clients
redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
es_client = AsyncElasticsearch(hosts=[settings.ELASTICSEARCH_URL])

@app.on_event("startup")
async def startup_event():
    # 1. Auto-create PostgreSQL tables
    async with database.engine.begin() as conn:
        await conn.run_sync(models.Base.metadata.create_all)
    
    # 2. Auto-create Elasticsearch index
    await create_index_if_not_exists()
    
    # 3. Start Redis Pub/Sub listener in background for real-time alerts
    asyncio.create_task(redis_pubsub_listener())
    print("🔊 Redis Pub/Sub listener started")

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

# ==========================================
# AUTHENTICATION ENDPOINTS
# ==========================================
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

# ==========================================
# FEED INGESTION ENDPOINTS
# ==========================================
@app.post("/api/v1/feeds/ingest/urlhaus")
async def trigger_urlhaus_ingestion(
    background_tasks: BackgroundTasks, 
    db: database.AsyncSession = Depends(database.get_db)
):
    result = await db.execute(select(models.Feed).where(models.Feed.name == "URLhaus"))
    feed = result.scalar_one_or_none()
    
    if not feed:
        feed = models.Feed(name="URLhaus", url="https://urlhaus-api.abuse.ch/", feed_type="urlhaus")
        db.add(feed)
        await db.commit()
        await db.refresh(feed)

    background_tasks.add_task(run_ingestion_task, feed.id, "urlhaus")
    return {"message": "URLHaus ingestion started in background."}

@app.post("/api/v1/feeds/ingest/feodo")
async def trigger_feodo_ingestion(
    background_tasks: BackgroundTasks, 
    db: database.AsyncSession = Depends(database.get_db)
):
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
async def trigger_mb_ingestion(
    background_tasks: BackgroundTasks, 
    db: database.AsyncSession = Depends(database.get_db)
):
    result = await db.execute(select(models.Feed).where(models.Feed.name == "MalwareBazaar"))
    feed = result.scalar_one_or_none()
    if not feed:
        feed = models.Feed(name="MalwareBazaar", url="https://bazaar.abuse.ch/", feed_type="malwarebazaar")
        db.add(feed)
        await db.commit()
        await db.refresh(feed)
    background_tasks.add_task(run_ingestion_task, feed.id, "malwarebazaar")
    return {"message": "MalwareBazaar ingestion started."}

# Helper function to run ingestion outside the request context
async def run_ingestion_task(feed_id: uuid.UUID, feed_type: str):
    async with database.AsyncSessionLocal() as db:
        result = await db.execute(select(models.Feed).where(models.Feed.id == feed_id))
        feed = result.scalar_one()
        
        if feed_type == "urlhaus":
            parser = URLHausParser(db, feed)
        elif feed_type == "feodo":
            parser = FeodoParser(db, feed)
        elif feed_type == "malwarebazaar":
            parser = MalwareBazaarParser(db, feed)
        else:
            return
            
        await parser.process()
        print(f"✅ {feed_type} ingestion complete!")

# ==========================================
# INDICATOR & SEARCH ENDPOINTS
# ==========================================
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
    ][:50]

@app.get("/api/v1/search")
async def search_intelligence(
    q: str = "",
    type: str = "",
    min_score: int = 0,
    status: str = "active",
    size: int = 50,
    current_user: models.User = Depends(dependencies.get_current_user)
):
    """FR-25: Full-text and faceted search across all indicators with sub-second response."""
    start_time = time.time()
    
    results = await search_indicators(
        query=q,
        type_filter=type,
        min_score=min_score,
        status_filter=status,
        size=size
    )
    
    latency_ms = (time.time() - start_time) * 1000
    
    return {
        "results": results,
        "count": len(results),
        "latency_ms": round(latency_ms, 2),
        "query_params": {"q": q, "type": type, "min_score": min_score, "status": status}
    }

# ==========================================
# ALERT MANAGEMENT ENDPOINTS
# ==========================================
@app.get("/api/v1/alerts")
async def list_alerts(
    status_filter: str = "new",
    severity: str = "",
    limit: int = 50,
    db: database.AsyncSession = Depends(database.get_db),
    current_user: models.User = Depends(dependencies.get_current_user)
):
    """List alerts with filtering."""
    query = select(models.Alert).options(
        selectinload(models.Alert.indicator)  # Eagerly load the indicator relationship
    )
    
    if status_filter:
        query = query.where(models.Alert.status == status_filter)
    if severity:
        query = query.where(models.Alert.severity == severity)
    
    query = query.order_by(models.Alert.created_at.desc()).limit(limit)
    
    result = await db.execute(query)
    alerts = result.scalars().unique().all()  # Use unique() to handle duplicates from joins
    
    return [
        {
            "id": str(a.id),
            "title": a.title,
            "severity": a.severity,
            "status": a.status,
            "indicator_value": a.indicator.value if a.indicator else None,
            "created_at": a.created_at.isoformat() if a.created_at else None
        } for a in alerts
    ]

@app.patch("/api/v1/alerts/{alert_id}")
async def update_alert(
    alert_id: uuid.UUID,
    status: str,
    db: database.AsyncSession = Depends(database.get_db),
    current_user: models.User = Depends(dependencies.get_current_user)
):
    """Update alert lifecycle status (FR-18)."""
    result = await db.execute(select(models.Alert).where(models.Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.status = status
    if status == "acknowledged":
        alert.acknowledged_at = datetime.utcnow()
    elif status == "resolved":
        alert.resolved_at = datetime.utcnow()
    
    await db.commit()
    
    # Publish update event to Redis for real-time UI update
    engine = AlertRuleEngine(db)
    engine._publish_alert_event(alert, "alerts.updated")
    
    return {"message": f"Alert {status}"}

@app.post("/api/v1/debug/force-alert")
async def force_alert_creation(
    db: database.AsyncSession = Depends(database.get_db),
    current_user: models.User = Depends(dependencies.get_current_user)
):
    """
    DEBUG ENDPOINT: Forces the creation of a high-severity indicator 
    to guarantee the Alert Engine and Redis Pub/Sub pipeline can be tested.
    """
    # 1. Create a fake high-severity indicator
    indicator = models.Indicator(
        id=uuid.uuid4(),
        value="10.99.99.99",
        type="ip",
        severity_score=95,  # Guaranteed to trigger the >80 rule
        confidence=99,
        status="active",
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow()
    )
    db.add(indicator)
    await db.flush()
    
    # 2. Trigger the Alert Engine
    engine = AlertRuleEngine(db)
    alerts = await engine.evaluate_indicator(indicator)
    await db.commit()
    
    return {
        "message": f"Successfully forced creation of {len(alerts)} alert(s)",
        "indicator_value": indicator.value,
        "severity_score": indicator.severity_score
    }

# ==========================================
# REAL-TIME WEBSOCKET ENDPOINT
# ==========================================
@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """
    FR-15: WebSocket endpoint for real-time alert streaming.
    Clients connect to this endpoint to receive live alerts and high-severity indicators.
    """
    await manager.connect(websocket, "alerts_stream")
    try:
        while True:
            # Keep connection alive, receive messages if any (e.g., client acknowledgements)
            data = await websocket.receive_text()
            print(f"Received from client: {data}")
    except WebSocketDisconnect:
        manager.disconnect(websocket, "alerts_stream")
        print("Client disconnected from alerts stream")