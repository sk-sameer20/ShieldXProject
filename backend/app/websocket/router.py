"""
WebSocket Endpoints for ShieldX SOC
"""
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.websocket.manager import ws_manager

logger = logging.getLogger("shieldx.websocket")
websocket_router = APIRouter(tags=["WebSockets"])


@websocket_router.websocket("/ws/alerts")
async def websocket_alerts_endpoint(websocket: WebSocket):
    """
    Real-time WebSocket endpoint streaming alert events.
    Clients receive notifications when new security alerts are confirmed and persisted.
    """
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive; clients may send ping or messages
            data = await websocket.receive_text()
            # Optional: respond to ping
            if data.strip().lower() == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as exc:
        logger.warning(f"WebSocket client loop exception: {exc}")
        ws_manager.disconnect(websocket)
