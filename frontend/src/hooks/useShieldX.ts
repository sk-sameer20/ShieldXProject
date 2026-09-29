/**
 * TanStack Query hooks for ShieldX Backend.
 * Automatically invalidated on WebSocket real alert events.
 */

import { useEffect, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, AlertItem } from "../services/api";
import { shieldXWebSocket, WebSocketStatus } from "../services/websocket";

export function useShieldXWebSocketSync() {
  const queryClient = useQueryClient();
  const [wsStatus, setWsStatus] = useState<WebSocketStatus>(shieldXWebSocket.getStatus());

  useEffect(() => {
    shieldXWebSocket.connect();

    const unsubStatus = shieldXWebSocket.onStatusChange((status) => {
      setWsStatus(status);
    });

    const unsubAlert = shieldXWebSocket.onAlert((newAlert: AlertItem) => {
      // Invalidate relevant queries so all views refresh their data automatically
      queryClient.invalidateQueries({ queryKey: ["alerts"] });
      queryClient.invalidateQueries({ queryKey: ["stats"] });
      queryClient.invalidateQueries({ queryKey: ["threat-distribution"] });
      queryClient.invalidateQueries({ queryKey: ["traffic"] });

      // Optimistically prepend to active alert lists in cache if present
      queryClient.setQueriesData<any>({ queryKey: ["alerts"] }, (old: any) => {
        if (!old) return old;
        if (Array.isArray(old)) {
          if (old.some((a) => a.id === newAlert.id || a.alert_id === newAlert.alert_id)) return old;
          return [newAlert, ...old];
        }
        if (old.items && Array.isArray(old.items)) {
          if (old.items.some((a: any) => a.id === newAlert.id || a.alert_id === newAlert.alert_id)) return old;
          return {
            ...old,
            total: (old.total ?? 0) + 1,
            items: [newAlert, ...old.items],
          };
        }
        return old;
      });
    });

    return () => {
      unsubStatus();
      unsubAlert();
    };
  }, [queryClient]);

  return { wsStatus };
}

export function useHealth() {
  return useQuery({
    queryKey: ["health"],
    queryFn: api.getHealth,
    staleTime: 15000,
    retry: 1,
  });
}

export function useStats() {
  return useQuery({
    queryKey: ["stats"],
    queryFn: api.getStats,
    staleTime: 10000,
    retry: 1,
  });
}

export function useThreatDistribution() {
  return useQuery({
    queryKey: ["threat-distribution"],
    queryFn: api.getThreatDistribution,
    staleTime: 15000,
    retry: 1,
  });
}

export function useAlerts(params?: { page?: number; page_size?: number; severity?: string; threat_class?: string }) {
  return useQuery({
    queryKey: ["alerts", params],
    queryFn: () => api.getAlerts(params),
    staleTime: 5000,
    retry: 1,
  });
}

export function useAlertDetail(alertId: string | null) {
  return useQuery({
    queryKey: ["alert-detail", alertId],
    queryFn: () => (alertId ? api.getAlertById(alertId) : null),
    enabled: Boolean(alertId),
    staleTime: 30000,
  });
}

export function useTraffic(limit = 20) {
  return useQuery({
    queryKey: ["traffic", limit],
    queryFn: () => api.getTraffic(limit),
    staleTime: 8000,
    refetchInterval: 10000, // gentle quiescent fallback polling
    retry: 1,
  });
}

export function useDetectorsStatus() {
  return useQuery({
    queryKey: ["detectors-status"],
    queryFn: api.getDetectorsStatus,
    staleTime: 20000,
    retry: 1,
  });
}

export function useProtocols() {
  return useQuery({
    queryKey: ["protocols"],
    queryFn: api.getProtocols,
    staleTime: 15000,
    retry: 1,
  });
}

