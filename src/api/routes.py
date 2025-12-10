from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import List
import asyncio
import logging
from .models import AttackEvent

router = APIRouter()
logger = logging.getLogger(__name__)

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.history: List[dict] = []
        self.MAX_HISTORY = 100

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"Client connected. Total: {len(self.active_connections)}")
        
        # Send history to new client
        if self.history:
            logger.info(f"Sending {len(self.history)} cached events to new client")
            for event in self.history:
                try:
                    await websocket.send_json(event)
                except Exception as e:
                    logger.error(f"Error sending history: {e}")
                    break

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        logger.info(f"Client disconnected. Total: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        # Add to history
        self.history.append(message)
        if len(self.history) > self.MAX_HISTORY:
            self.history.pop(0)
            
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Error sending to client: {e}")
                # We might want to remove dead connections here, but disconnect() usually handles explicit closes
                
manager = ConnectionManager()

@router.get("/status")
async def get_status():
    return {"status": "online", "connections": len(manager.active_connections)}

@router.websocket("/ws/attacks")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # We just keep the connection open. Use a heartbeat maybe?
            # efficient way to wait for disconnect
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        manager.disconnect(websocket)
