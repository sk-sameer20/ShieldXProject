from typing import Dict, Tuple, Optional
from src.alerts.schema import AlertSchema


class AlertDeduplicator:
    """
    Suppresses duplicate alerts for the same source_ip and threat_class within a time window.
    """

    def __init__(self, suppression_window_seconds: float = 30.0):
        self.suppression_window_seconds = suppression_window_seconds
        # (source_ip, threat_class) -> (last_emitted_alert, last_timestamp, hit_count)
        self._history: Dict[Tuple[str, str], Tuple[AlertSchema, float, int]] = {}

    def process_alert(self, alert: AlertSchema) -> Tuple[bool, AlertSchema]:
        """
        Processes an alert.
        Returns (should_emit, alert_to_emit).
        If duplicate within suppression window, returns (False, updated_alert).
        If new or suppression window expired, returns (True, alert).
        """
        key = (alert.src_ip, alert.threat_type)
        current_time = alert.timestamp

        if key in self._history:
            prev_alert, prev_ts, hit_count = self._history[key]
            if (current_time - prev_ts) < self.suppression_window_seconds:
                # Duplicate within window -> update count and suppress emission
                new_count = hit_count + 1
                updated_alert = alert.model_copy(update={"suppressed_count": new_count})
                self._history[key] = (updated_alert, prev_ts, new_count)
                return False, updated_alert

        # New alert or window expired -> emit
        self._history[key] = (alert, current_time, 0)
        return True, alert

    def clear(self) -> None:
        self._history.clear()
