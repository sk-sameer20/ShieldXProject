"""
WebSocket Connection Manager for ShieldX SOC
Manages active real-time connections, isolated broadcasting, and connection logging.
"""
import json
import logging
from typing import Any, Dict, List, Set, Union
from fastapi import WebSocket

logger = logging.getLogger("shieldx.websocket")


class ConnectionManager:
    """
    Manages active WebSocket connections with robust client failure isolation.
    Ensures that a failure or disconnection in one client does not interrupt
    or corrupt broadcasts to other connected clients.
    """

    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and register an incoming WebSocket connection."""
        await websocket.accept()
        self.active_connections.add(websocket)
        client = getattr(websocket, "client", None)
        client_host = getattr(client, "host", "unknown") if client else "unknown"
        client_port = getattr(client, "port", "unknown") if client else "unknown"
        logger.info(
            f"WebSocket client connected from {client_host}:{client_port}. "
            f"Total active clients: {len(self.active_connections)}"
        )

    def disconnect(self, websocket: WebSocket) -> None:
        """Safely unregister a WebSocket connection."""
        self.active_connections.discard(websocket)
        client = getattr(websocket, "client", None)
        client_host = getattr(client, "host", "unknown") if client else "unknown"
        client_port = getattr(client, "port", "unknown") if client else "unknown"
        logger.info(
            f"WebSocket client disconnected ({client_host}:{client_port}). "
            f"Total active clients: {len(self.active_connections)}"
        )

    async def broadcast(self, message: Union[Dict[str, Any], str]) -> None:
        """
        Broadcast a message to all active WebSocket clients with failure isolation.
        Dead or failed connections are safely collected and pruned without raising errors.
        """
        if not self.active_connections:
            return

        text_payload = json.dumps(message) if isinstance(message, dict) else message
        dead_connections: List[WebSocket] = []

        # Iterate over a snapshot of active connections
        for connection in list(self.active_connections):
            try:
                await connection.send_text(text_payload)
            except Exception as exc:
                logger.warning(f"Failed to send to client; marking for disconnection: {exc}")
                dead_connections.append(connection)

        # Prune dead connections
        for dead_conn in dead_connections:
            self.disconnect(dead_conn)

    @property
    def client_count(self) -> int:
        """Return the number of currently active connections."""
        return len(self.active_connections)


# Global singleton manager instance
ws_manager = ConnectionManager()
