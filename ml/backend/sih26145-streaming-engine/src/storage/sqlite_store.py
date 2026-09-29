import os
import json
import sqlite3
from typing import List, Dict, Any, Optional
from src.alerts.schema import AlertSchema


class SQLiteStore:
    """
    SQLite database interface for persisting and querying threat alerts.
    """

    def __init__(self, db_path: str = "outputs/sih26145.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    flow_id TEXT,
                    threat_type TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    severity TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    model_version TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT,
                    window_start REAL,
                    window_end REAL,
                    raw_features TEXT,
                    suppressed_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()

    def save_alert(self, alert: AlertSchema) -> bool:
        """
        Saves or updates an alert in the SQLite database.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO alerts (
                    id, timestamp, flow_id, threat_type, confidence, severity,
                    evidence, model_version, src_ip, dst_ip,
                    window_start, window_end, raw_features, suppressed_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                alert.id,
                alert.timestamp,
                alert.flow_id,
                alert.threat_type,
                alert.confidence,
                alert.severity,
                json.dumps(alert.evidence),
                alert.model_version,
                alert.src_ip,
                alert.dst_ip,
                alert.window_start,
                alert.window_end,
                json.dumps(alert.raw_features),
                alert.suppressed_count
            ))
            conn.commit()
            return True

    def get_recent_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Returns recent alerts ordered by timestamp descending.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            results = []
            for row in rows:
                item = dict(row)
                item["evidence"] = json.loads(item["evidence"]) if item["evidence"] else []
                item["raw_features"] = json.loads(item["raw_features"]) if item["raw_features"] else {}
                results.append(item)
            return results

    def get_alerts_by_threat(self, threat_type: str, limit: int = 100) -> List[Dict[str, Any]]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM alerts WHERE threat_type = ? ORDER BY timestamp DESC LIMIT ?
            """, (threat_type, limit))
            rows = cursor.fetchall()
            results = []
            for row in rows:
                item = dict(row)
                item["evidence"] = json.loads(item["evidence"]) if item["evidence"] else []
                item["raw_features"] = json.loads(item["raw_features"]) if item["raw_features"] else {}
                results.append(item)
            return results

    def clear_alerts(self) -> None:
        with self._get_connection() as conn:
            conn.cursor().execute("DELETE FROM alerts")
            conn.commit()

    def get_stats(self) -> Dict[str, Any]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) as count FROM alerts")
            total = cursor.fetchone()["count"]
            
            cursor.execute("SELECT threat_type, COUNT(*) as count FROM alerts GROUP BY threat_type")
            by_threat = {row["threat_type"]: row["count"] for row in cursor.fetchall()}

            cursor.execute("SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity")
            by_severity = {row["severity"]: row["count"] for row in cursor.fetchall()}

            return {
                "total_alerts": total,
                "by_threat_type": by_threat,
                "by_severity": by_severity
            }
