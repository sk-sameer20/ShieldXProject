/**
 * SHIELDX REST API Service Layer
 * Strictly bound to FastAPI Enclave Pydantic Schemas.
 * Zero invented fields; honest unavailable and empty state handling.
 */

const API_BASE = typeof window !== "undefined"
  ? `${window.location.protocol}//${window.location.hostname}:8000/api`
  : "http://127.0.0.1:8000/api";

// ─────────────────────────────────────────────────────────────
// SCHEMAS & INTERFACES
// ─────────────────────────────────────────────────────────────

export interface GaugeItem {
  label: string;
  val: number;
  detail: string;
  color: string;
}

export interface DataSourceItem {
  name: string;
  status: string;
  latency: string;
}

export interface SensorNetworkItem {
  online_sensors: number;
  total_sensors: number;
  regions_count: number;
  uptime_pct: number;
  avg_latency: string;
}

export interface DiodeIntegrityItem {
  physical_link_rx: boolean;
  physical_link_tx: boolean;
  optical_power_dbm: number;
  ring_buffer_utilization_pct: number;
  dropped_frames: number;
  diode_state: string;
  tamper_evident_chain_valid: boolean;
  last_audit_hash: string;
}

export interface HealthResponse {
  status: string;
  gauges: GaugeItem[];
  sources: DataSourceItem[];
  sensor_network: SensorNetworkItem;
  diode_integrity: DiodeIntegrityItem;
}

export interface StatisticsResponse {
  total_alerts: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  active_flows: number;
  packets_per_sec: number;
  bytes_per_sec: number;
  mbps: number;
  detection_latency_ms: number;
  actual_egress_packets: number;
  actual_egress_bytes: number;
}

export interface ThreatCategoryItem {
  label: string;
  pct: number;
  pct_formatted: string;
  count: number;
  color: string;
}

export interface ThreatDistributionResponse {
  filter_mode: string;
  total_threats: number;
  categories: ThreatCategoryItem[];
}

export interface AlertItem {
  id: string;
  alert_id: string;
  timestamp: string;
  time: string;
  dateLabel: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  classification: string;
  attack_classification?: string;
  threat_class: string;
  srcIp: string;
  destIp: string;
  source_ip: string;
  destination_ip: string;
  source_port?: number;
  destination_port?: number;
  protocol: string;
  confidence: number;
  confidence_pct: number;
  confidenceFormatted: string;
  triage: string;
  triage_status: string;
  triageType: string;
  status: string;
  accentColor: string;
  whyFlagged: string;
  reason: string;
  detectorModel: string;
  detector_model: string;
  mitre: string;
  mitre_technique?: string;
  triggerFeatures?: Record<string, any>;
  trigger_features?: Record<string, any>;
  evidence?: {
    rule_or_model?: string;
    why_flagged?: string;
    mitre_technique_id?: string;
    mitre_tactic?: string;
    trigger_features?: Record<string, any>;
    [key: string]: any;
  } | null;
  metadata?: Record<string, any>;
}

export interface AlertListResponse {
  total: number;
  counts: Record<string, number>;
  items: AlertItem[];
  page: number;
  page_size: number;
  total_pages: number;
}

export interface TrafficPoint {
  timestamp: string;
  time_label: string;
  packets_per_sec: number;
  bytes_per_sec: number;
  mbps: number;
  is_anomaly: boolean;
  anomaly_val?: string | null;
}

export interface DetectorStatusItem {
  engine_type: string;
  status: string;
  rule_name: string;
  target_host: string;
  attack_vector: string;
  cadence_or_duration: string;
  recommended_action: string;
  metrics: Record<string, any>;
}

export interface ProtocolItem {
  name: string;
  packet_count: number;
  byte_count: number;
  bandwidth_pct: number;
  color: string;
}

// ─────────────────────────────────────────────────────────────
// FETCH HELPERS
// ─────────────────────────────────────────────────────────────

async function apiFetch<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  try {
    const res = await fetch(url, {
      ...options,
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
        ...(options?.headers || {}),
      },
    });

    if (!res.ok) {
      const errText = await res.text().catch(() => "Unknown error");
      throw new Error(`API ${endpoint} failed (${res.status}): ${errText}`);
    }

    return (await res.json()) as T;
  } catch (err: any) {
    // Graceful offline detection: propagate clear offline status
    throw err;
  }
}

// ─────────────────────────────────────────────────────────────
// API METHODS
// ─────────────────────────────────────────────────────────────

export const api = {
  getHealth: () => apiFetch<HealthResponse>("/health"),
  getStats: () => apiFetch<StatisticsResponse>("/stats"),
  getThreatDistribution: () => apiFetch<ThreatDistributionResponse>("/stats/threat-distribution"),
  getAlerts: (params?: { page?: number; page_size?: number; severity?: string; threat_class?: string }) => {
    const query = new URLSearchParams();
    if (params?.page) query.append("page", String(params.page));
    if (params?.page_size) query.append("page_size", String(params.page_size));
    if (params?.severity) query.append("severity", params.severity);
    if (params?.threat_class) query.append("threat_class", params.threat_class);
    const qs = query.toString();
    return apiFetch<AlertListResponse>(`/alerts${qs ? `?${qs}` : ""}`);
  },
  getAlertById: (alertId: string) => apiFetch<AlertItem>(`/alerts/${encodeURIComponent(alertId)}`),
  getTraffic: (limit = 20) => apiFetch<TrafficPoint[]>(`/traffic?limit=${limit}`),
  getProtocols: () => apiFetch<ProtocolItem[]>("/traffic/protocols"),
  getDetectorsStatus: () => apiFetch<DetectorStatusItem[]>("/detectors/status"),
};
