/**
 * SHIELDX Real-time WebSocket Client
 * Connects to ws://127.0.0.1:8000/ws/alerts
 * Handles connection lifecycle, exponential backoff reconnection, and real alert dispatch.
 */

import { AlertItem } from "./api";

export type WebSocketStatus = "CONNECTING" | "OPEN" | "CLOSED" | "RECONNECTING";

type AlertHandler = (alert: AlertItem) => void;
type StatusHandler = (status: WebSocketStatus) => void;

class ShieldXWebSocketClient {
  private ws: WebSocket | null = null;
  private status: WebSocketStatus = "CLOSED";
  private alertListeners: Set<AlertHandler> = new Set();
  private statusListeners: Set<StatusHandler> = new Set();
  private reconnectAttempts = 0;
  private maxReconnectDelay = 30000;
  private reconnectTimer: any = null;
  private isManuallyClosed = false;

  private getUrl() {
    if (typeof window !== "undefined") {
      const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
      return `${proto}//${window.location.hostname}:8000/ws/alerts`;
    }
    return "ws://127.0.0.1:8000/ws/alerts";
  }

  public connect() {
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }

    this.isManuallyClosed = false;
    this.setStatus(this.reconnectAttempts > 0 ? "RECONNECTING" : "CONNECTING");

    try {
      this.ws = new WebSocket(this.getUrl());

      this.ws.onopen = () => {
        this.reconnectAttempts = 0;
        this.setStatus("OPEN");
      };

      this.ws.onmessage = (event) => {
        try {
          // Backend may echo pong or send json
          const raw = typeof event.data === "string" ? event.data : "";
          if (raw.trim().toLowerCase() === "pong") {
            return;
          }

          const parsed = JSON.parse(raw);
          // Check for alert payload
          const alertData: AlertItem | null =
            parsed.data && (parsed.type === "alert" || parsed.event === "NEW_ALERT" || parsed.data.alert_id)
              ? parsed.data
              : parsed.alert_id
              ? parsed
              : null;

          if (alertData) {
            this.notifyAlert(alertData);
          }
        } catch {
          // Non-JSON or unsupported packet; safely ignore without crashing
        }
      };

      this.ws.onclose = () => {
        this.setStatus("CLOSED");
        if (!this.isManuallyClosed) {
          this.scheduleReconnect();
        }
      };

      this.ws.onerror = () => {
        // Handled via onclose
      };
    } catch {
      this.setStatus("CLOSED");
      if (!this.isManuallyClosed) {
        this.scheduleReconnect();
      }
    }
  }

  private scheduleReconnect() {
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    this.reconnectAttempts++;
    // Exponential backoff: 1s, 2s, 4s, 8s... up to 30s max
    const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts - 1), this.maxReconnectDelay);
    this.setStatus("RECONNECTING");
    this.reconnectTimer = setTimeout(() => {
      this.connect();
    }, delay);
  }

  public disconnect() {
    this.isManuallyClosed = true;
    if (this.reconnectTimer) clearTimeout(this.reconnectTimer);
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
    this.setStatus("CLOSED");
  }

  public onAlert(handler: AlertHandler): () => void {
    this.alertListeners.add(handler);
    return () => this.alertListeners.delete(handler);
  }

  public onStatusChange(handler: StatusHandler): () => void {
    this.statusListeners.add(handler);
    handler(this.status);
    return () => this.statusListeners.delete(handler);
  }

  public getStatus(): WebSocketStatus {
    return this.status;
  }

  private setStatus(status: WebSocketStatus) {
    if (this.status !== status) {
      this.status = status;
      this.statusListeners.forEach((fn) => {
        try {
          fn(status);
        } catch {}
      });
    }
  }

  private notifyAlert(alert: AlertItem) {
    this.alertListeners.forEach((fn) => {
      try {
        fn(alert);
      } catch {}
    });
  }
}

export const shieldXWebSocket = new ShieldXWebSocketClient();
