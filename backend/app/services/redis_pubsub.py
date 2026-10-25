import asyncio
import json
import redis.asyncio as redis
from ..config import settings
from ..websocket_manager import manager

async def redis_pubsub_listener():
    """
    Listens to Redis pub/sub channels and broadcasts messages to WebSocket clients.
    Includes graceful shutdown handling for Uvicorn hot-reloads.
    """
    r = redis.from_url(settings.REDIS_URL, decode_responses=True)
    pubsub = r.pubsub()
    
    await pubsub.subscribe(
        "alerts.new",
        "alerts.updated",
        "indicators.high_severity",
        "incidents.updated"
    )
    
    print("🔊 Redis Pub/Sub listener started, waiting for events...")
    
    try:
        async for message in pubsub.listen():
            if message["type"] == "message":
                channel = message["channel"]
                data = json.loads(message["data"])
                ws_channel = channel.replace(".", "_")
                
                print(f"📨 Received event on {channel}: {data.get('type', 'unknown')}")
                
                await manager.broadcast_to_channel(ws_channel, {
                    "channel": channel,
                    "data": data,
                    "timestamp": asyncio.get_event_loop().time()
                })
    except asyncio.CancelledError:
        print("🛑 Redis Pub/Sub listener cancelled gracefully (normal during reload).")
    except GeneratorExit:
        print("🛑 Redis Pub/Sub listener generator exited gracefully (normal during reload).")
    except Exception as e:
        print(f"❌ Redis Pub/Sub error: {e}")
    finally:
        try:
            await pubsub.unsubscribe()
            await r.close()
        except Exception:
            pass # Ignore cleanup errors during forced shutdown