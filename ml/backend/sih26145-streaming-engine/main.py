import asyncio
import logging
from typing import Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

from src.streaming.scheduler import StreamingScheduler
from src.alerts.schema import AlertSchema

logger = logging.getLogger(__name__)

scheduler: Optional[StreamingScheduler] = None
consumer_task: Optional[asyncio.Task] = None

class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_alert(self, alert: AlertSchema):
        alert_data = alert.model_dump()
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(alert_data)
            except Exception as e:
                logger.error(f"Failed to send to client: {e}")
                disconnected.append(connection)
        for conn in disconnected:
            self.disconnect(conn)

manager = ConnectionManager()

def on_alert_generated(alert: AlertSchema):
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(manager.broadcast_alert(alert))
    except RuntimeError:
        logger.warning("No running event loop to broadcast alert")

@asynccontextmanager
async def lifespan(app: FastAPI):
    global scheduler, consumer_task
    logger.info("Initializing SIH26145 Backend Streaming Engine")
    
    scheduler = StreamingScheduler(alert_callback=on_alert_generated)
    consumer_task = asyncio.create_task(scheduler.run_loop())
    
    yield
    
    logger.info("Shutting down Backend Engine")
    if scheduler:
        scheduler.stop()
    if consumer_task:
        consumer_task.cancel()
        try:
            await consumer_task
        except asyncio.CancelledError:
            pass

app = FastAPI(title="SIH26145 API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
async def health():
    return {"status": "ok", "service": "SIH26145 Backend"}

@app.get("/alerts")
async def get_alerts(limit: int = Query(100, ge=1, le=1000), threat_type: Optional[str] = None):
    if not scheduler or not scheduler.storage:
        return {"alerts": []}
    
    if threat_type:
        alerts = scheduler.storage.get_alerts_by_threat(threat_type=threat_type, limit=limit)
    else:
        alerts = scheduler.storage.get_recent_alerts(limit=limit)
    return {"alerts": alerts}

@app.get("/stats")
async def get_stats():
    if not scheduler or not scheduler.storage:
        return {}
    return scheduler.storage.get_stats()

@app.get("/traffic")
async def get_traffic():
    if not scheduler or not scheduler.queue:
        return {}
    return scheduler.queue.get_stats()

@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.error(f"Websocket error: {e}")
        manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
