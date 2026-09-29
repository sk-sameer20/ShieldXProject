from collections import defaultdict, deque
from typing import Dict, List, Optional, Any
from src.ingestion.parser import NetworkEvent


class WindowManager:
    """
    Manages sliding time windows and host state tracking across event streams.
    """

    def __init__(self, window_config: Optional[Dict[str, float]] = None):
        self.config = window_config or {
            "ddos_seconds": 5.0,
            "c2_seconds": 60.0,
            "dns_seconds": 60.0,
            "cleanup_ttl_seconds": 300.0,
        }
        
        # Max window size to keep in memory
        self.max_window_seconds = max(
            self.config.get("ddos_seconds", 5.0),
            self.config.get("c2_seconds", 60.0),
            self.config.get("dns_seconds", 60.0),
        )

        # Event storage: deque of events sorted by timestamp
        self._events: deque[NetworkEvent] = deque()
        
        # Host state tracking: src_ip -> metadata dict
        self._host_state: Dict[str, Dict[str, Any]] = defaultdict(lambda: {
            "last_seen": 0.0,
            "dst_ips": set(),
            "dns_queries": [],
            "flow_timestamps": [],
        })
        
        self.latest_timestamp: float = 0.0

    def add_event(self, event: NetworkEvent) -> None:
        """
        Adds a new event and updates sliding window and host state.
        """
        if event.timestamp > self.latest_timestamp:
            self.latest_timestamp = event.timestamp

        # Insert keeping timestamp order (handles slightly out-of-order events)
        if not self._events or event.timestamp >= self._events[-1].timestamp:
            self._events.append(event)
        else:
            # Out of order insertion
            idx = len(self._events) - 1
            while idx >= 0 and self._events[idx].timestamp > event.timestamp:
                idx -= 1
            self._events.insert(idx + 1, event)

        # Update host state
        host_info = self._host_state[event.src_ip]
        host_info["last_seen"] = max(host_info["last_seen"], event.timestamp)
        host_info["dst_ips"].add(event.dst_ip)
        host_info["flow_timestamps"].append(event.timestamp)
        if event.query:
            host_info["dns_queries"].append((event.timestamp, event.query))

        # Perform routine window cleanup relative to latest_timestamp
        self._prune_expired_events()

    def get_window_events(self, window_seconds: float, host_ip: Optional[str] = None) -> List[NetworkEvent]:
        """
        Returns all events within [latest_timestamp - window_seconds, latest_timestamp].
        Optionally filtered by target host_ip (as source or destination).
        """
        cutoff = self.latest_timestamp - window_seconds
        result: List[NetworkEvent] = []
        
        for ev in reversed(self._events):
            if ev.timestamp < cutoff:
                break
            if host_ip is None or ev.src_ip == host_ip or ev.dst_ip == host_ip:
                result.append(ev)
                
        result.reverse()
        return result

    def get_ddos_window(self, host_ip: Optional[str] = None) -> List[NetworkEvent]:
        return self.get_window_events(self.config["ddos_seconds"], host_ip)

    def get_c2_window(self, host_ip: Optional[str] = None) -> List[NetworkEvent]:
        return self.get_window_events(self.config["c2_seconds"], host_ip)

    def get_dns_window(self, host_ip: Optional[str] = None) -> List[NetworkEvent]:
        return self.get_window_events(self.config["dns_seconds"], host_ip)

    def get_active_hosts(self) -> List[str]:
        """
        Returns list of source IPs active in the current window storage.
        """
        cutoff = self.latest_timestamp - self.max_window_seconds
        return [
            ip for ip, state in self._host_state.items()
            if state["last_seen"] >= cutoff
        ]

    def _prune_expired_events(self) -> None:
        """
        Removes events older than max_window_seconds and prunes stale host state.
        """
        cutoff = self.latest_timestamp - self.max_window_seconds
        while self._events and self._events[0].timestamp < cutoff:
            self._events.popleft()

        # Cleanup host state TTL
        ttl_cutoff = self.latest_timestamp - self.config.get("cleanup_ttl_seconds", 300.0)
        expired_hosts = [
            ip for ip, state in self._host_state.items()
            if state["last_seen"] < ttl_cutoff
        ]
        for ip in expired_hosts:
            del self._host_state[ip]
