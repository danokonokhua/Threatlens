from fastapi import WebSocket
from typing import List, Dict
import asyncio
import json

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, channel: str):
        await websocket.accept()
        if channel not in self.active_connections:
            self.active_connections[channel] = []
        self.active_connections[channel].append(websocket)
        print(f"✅ Client connected to {channel}. Total: {len(self.active_connections[channel])}")

    def disconnect(self, websocket: WebSocket, channel: str):
        if channel in self.active_connections:
            self.active_connections[channel].remove(websocket)
            if not self.active_connections[channel]:
                del self.active_connections[channel]
        print(f"❌ Client disconnected from {channel}")

    async def broadcast_to_channel(self, channel: str, message: dict):
        """Broadcast a message to all clients subscribed to a specific channel."""
        if channel in self.active_connections:
            dead_sockets = []
            for connection in self.active_connections[channel]:
                try:
                    await connection.send_json(message)
                except:
                    dead_sockets.append(connection)
            
            # Clean up dead connections
            for sock in dead_sockets:
                self.active_connections[channel].remove(sock)
            
            print(f" Broadcasted to {len(self.active_connections.get(channel, []))} clients on {channel}")

manager = ConnectionManager()