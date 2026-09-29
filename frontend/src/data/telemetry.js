/*
 * Demo telemetry for the ShieldX console.
 *
 * `alerts` matches the backend `alerts` table column-for-column
 * (id, timestamp, flow_id, threat_class, confidence, severity, evidence,
 * model_version, source_ip, destination_ip, window_start, window_end), so
 * wiring this up later means replacing these exports with fetch calls and
 * nothing else. Plain-language copy lives in `explainers`, keyed by
 * threat_class — that stays in the UI layer where it belongs.
 *
 * Figures quoted in `models` and `datasets` are the real ones from the
 * training runs, not invented.
 */

/*
 * Whether the console is reading real telemetry. The header's live indicator
 * renders only when this is true, so the UI never claims to be live while it is
 * running on the demo records below. Flip to true at integration.
 */
export const dataMode = {
  live: false,
};

export const THREAT_ORDER = ["DDoS", "C2", "DGA", "DNS"];

/* Identity colours are assigned in fixed slot order and never cycled. */
export const threatMeta = {
  DDoS: {
    short: "DDoS",
    label: "Volumetric flood",
    series: "var(--series-1)",
    window: "5s window",
    blurb: "Traffic arriving far faster than the link's learned normal, with handshakes that never complete.",
  },
  C2: {
    short: "C2",
    label: "Command & control beaconing",
    series: "var(--series-2)",
    window: "60s window",
    blurb: "A host calling out on a clock. Regular timing gives away an implant even when the payload is encrypted.",
  },
  DGA: {
    short: "DGA",
    label: "Algorithmic domains",
    series: "var(--series-3, #8b5cf6)",
    window: "60s window",
    blurb: "Machine-generated domain names — random-looking labels, mostly resolving to nothing.",
  },
  "DNS-Tunnel": {
    short: "DNS Tunnel",
    label: "DNS tunnelling",
    series: "var(--series-4, #eab308)",
    window: "60s window",
    blurb: "Data smuggled inside DNS queries, using the resolver as a transport channel.",
  },
  DNS: {
    short: "DNS Tunnel",
    label: "DNS tunnelling",
    series: "var(--series-4, #eab308)",
    window: "60s window",
    blurb: "Data smuggled inside DNS queries, using the resolver as a transport channel.",
  },
  DNS_TUNNEL: {
    short: "DNS Tunnel",
    label: "DNS tunnelling",
    series: "var(--series-4, #eab308)",
    window: "60s window",
    blurb: "Data smuggled inside DNS queries, using the resolver as a transport channel.",
  },
  "DNS Tunnel": {
    short: "DNS Tunnel",
    label: "DNS tunnelling",
    series: "var(--series-4, #eab308)",
    window: "60s window",
    blurb: "Data smuggled inside DNS queries, using the resolver as a transport channel.",
  },
  DDOS: {
    short: "DDoS",
    label: "Volumetric flood",
    series: "var(--series-1)",
    window: "5s window",
    blurb: "Traffic arriving far faster than the link's learned normal, with handshakes that never complete.",
  },
  C2_BEACONING: {
    short: "C2",
    label: "Command & control beaconing",
    series: "var(--series-2)",
    window: "60s window",
    blurb: "A host calling out on a clock. Regular timing gives away an implant even when the payload is encrypted.",
  },
  DGA_DNS_TUNNEL: {
    short: "DGA",
    label: "Algorithmic domains",
    series: "var(--series-3, #8b5cf6)",
    window: "60s window",
    blurb: "Machine-generated domain names or data smuggled inside DNS queries.",
  },
  "DGA/DNS": {
    short: "DGA",
    label: "Algorithmic domains",
    series: "var(--series-3, #8b5cf6)",
    window: "60s window",
    blurb: "Machine-generated domain names or data smuggled inside DNS queries.",
  },
  ANOMALY: {
    short: "Anomaly",
    label: "Traffic anomaly",
    series: "var(--series-4)",
    window: "30s window",
    blurb: "Statistical flow deviation from baseline.",
  },
};

/*
 * The four detection families SHIELDX actually ships: DDoS, C2 beaconing,
 * DGA algorithmic domains, and DNS tunnelling.
 */
export const detectionFamilies = [
  { id: "ddos", label: "DDoS", classes: ["DDoS", "DDOS"], color: "var(--series-1)" },
  { id: "c2", label: "C2 beaconing", classes: ["C2", "C2_BEACONING"], color: "var(--series-2)" },
  { id: "dga", label: "DGA", classes: ["DGA"], color: "var(--series-3, #8b5cf6)" },
  { id: "dns", label: "DNS Tunnel", classes: ["DNS", "DNS-Tunnel", "DNS_TUNNEL", "DNS Tunnel"], color: "var(--series-4, #eab308)" },
];

export const severityMeta = {
  critical: { label: "Critical", color: "var(--critical)", rank: 4 },
  high: { label: "High", color: "var(--serious)", rank: 3 },
  medium: { label: "Medium", color: "var(--warn)", rank: 2 },
  low: { label: "Low", color: "var(--ink-3)", rank: 1 },
};

/*
 * Why a detector considered a window suspicious, stated in terms of what it
 * measured. Deliberately not dramatic: passive observation can show that
 * connections repeat on a regular interval, not what the software intends.
 * These strings will be generated from real detector evidence later.
 */
export const explainers = {
  DDoS:
    "Packet rate into this destination sat far above the rate the link normally carries, while almost no connections completed a handshake. High rate plus near-zero completion is what produced the flood evidence.",
  C2:
    "Repeated connections toward a dominant destination at a highly regular interval produced strong beaconing evidence. Timing variation across the window was very low and payload sizes barely changed, and enough connections accumulated for the window to be scored.",
  DGA:
    "The domain labels queried in this window scored high for character entropy and length, and most lookups returned NXDOMAIN. On those inputs the character model scored the label set as algorithmically generated rather than human-chosen.",
  "DNS-Tunnel":
    "Query length, subdomain entropy and query rate all sat above their configured thresholds in this window. That combination is the shape of data encoded into DNS names, rather than names being resolved.",
};

/*
 * Demo alert records, shaped to the backend `alerts` table.
 *
 * Every `evidence` key is a feature the corresponding detector actually
 * computes — C2 from the 16-feature Isolation Forest vector, DDoS from the four
 * adapter features (pps, bps, syn_ratio, unique_dst_ips), DGA/DNS from the
 * configured lexical and query thresholds. `means` carries the plain-language
 * reading of each value; `threshold` is the configured bound where one applies.
 */
const demoAlerts = [
  {
    id: "a1f4c2e8",
    flow_id: "147.32.84.165:1043-93.184.216.34:443",
    threat_class: "C2",
    confidence: 0.91,
    severity: "critical",
    model_version: "c2-v1",
    source_ip: "147.32.84.165",
    destination_ip: "93.184.216.34",
    window_start: "14:03:00",
    window_end: "14:04:00",
    observed: "14:04:02",
    headline: "Regular 60-second connection interval from 147.32.84.165",
    evidence: [
      { k: "periodicity_score", v: "0.94", threshold: "0.70", means: "Connections repeat at a highly regular interval", flag: true },
      { k: "iat_cv", v: "0.03", means: "Very low variation in that timing", flag: true },
      { k: "dominant_destination_ratio", v: "0.98", threshold: "0.70", means: "Nearly all connections target one destination", flag: true },
      { k: "iat_mean", v: "60.2 s", means: "Average gap between connections" },
      { k: "connection_count", v: "58", threshold: "minimum 7 connections", means: "Enough observations to score the window" },
      { k: "orig_bytes_std", v: "9 B", means: "Payload size barely changes between connections" },
      { k: "mean_orig_bytes", v: "512 B", means: "Typical payload sent per connection" },
      { k: "tcp_success_ratio", v: "1.00", means: "Every connection completed its handshake" },
    ],
    timeline: [
      { at: "11:12:00", text: "Repeating connections first seen between this host pair" },
      { at: "13:40:22", text: "Connection count passed the 7-connection minimum for scoring" },
      { at: "14:02:10", text: "Periodicity score rose above the configured 0.70 threshold" },
      { at: "14:04:02", text: "Isolation Forest scored the window anomalous — confidence 0.91" },
    ],
  },
  {
    id: "b7e91d03",
    flow_id: "10.9.44.2:53129-10.0.0.53:53",
    threat_class: "DGA",
    confidence: 0.87,
    severity: "high",
    model_version: "dga-v6",
    source_ip: "10.9.44.2",
    destination_ip: "10.0.0.53",
    window_start: "13:57:00",
    window_end: "13:58:00",
    observed: "13:58:03",
    headline: "High-entropy domain labels queried by 10.9.44.2",
    evidence: [
      { k: "avg_shannon_entropy", v: "4.34", threshold: "3.50", means: "Label characters are close to random", flag: true },
      { k: "nxdomain_ratio", v: "0.88", threshold: "0.40", means: "Most lookups resolved to nothing", flag: true },
      { k: "avg_domain_length", v: "18.4", threshold: "12", means: "Labels longer than typical domains", flag: true },
      { k: "digit_ratio", v: "0.31", threshold: "0.30", means: "Digit share within the labels", flag: true },
      { k: "unique_domains_count", v: "1,904", means: "Distinct domains queried in the window" },
      { k: "query_rate", v: "42 /s", means: "Lookup rate from this client" },
    ],
    timeline: [
      { at: "13:51:10", text: "NXDOMAIN ratio for this client passed 0.40" },
      { at: "13:56:40", text: "Label entropy and length both above configured thresholds" },
      { at: "13:58:03", text: "Character model scored the label set at 0.87" },
    ],
  },
  {
    id: "c3a8b511",
    flow_id: "203.0.113.0/24-147.32.80.9:443",
    threat_class: "DDoS",
    confidence: 0.96,
    severity: "critical",
    model_version: "ddos-v1",
    source_ip: "203.0.113.0/24",
    destination_ip: "147.32.80.9",
    window_start: "13:54:50",
    window_end: "13:54:55",
    observed: "13:54:55",
    headline: "SYN flood against 147.32.80.9",
    evidence: [
      { k: "pps", v: "412,088", means: "Packets per second into this destination", flag: true },
      { k: "syn_ratio", v: "0.94", means: "Nearly all packets are connection openers", flag: true },
      { k: "bps", v: "1.84 Gbps", means: "Bit rate over the same window" },
      { k: "unique_dst_ips", v: "1", means: "All traffic aimed at a single destination" },
    ],
    timeline: [
      { at: "13:54:51", text: "Packet rate rose above the baseline learned for this link" },
      { at: "13:54:53", text: "SYN ratio held near 1.0 — connections not completing" },
      { at: "13:54:55", text: "DDoS detector scored the five-second window at 0.96" },
    ],
  },
  {
    id: "d9c07f24",
    flow_id: "147.32.84.191:41022-8.8.8.8:53",
    threat_class: "DNS-Tunnel",
    confidence: 0.78,
    severity: "high",
    model_version: "dns-v1",
    source_ip: "147.32.84.191",
    destination_ip: "8.8.8.8",
    window_start: "13:51:00",
    window_end: "13:52:00",
    observed: "13:52:11",
    headline: "Oversized encoded queries from 147.32.84.191",
    evidence: [
      { k: "query_length", v: "121 chars", threshold: "50", means: "Queries far longer than a normal lookup", flag: true },
      { k: "subdomain_entropy", v: "4.41", threshold: "3.80", means: "Subdomain characters close to random", flag: true },
      { k: "unique_subdomains", v: "64", threshold: "20", means: "Distinct subdomains under one parent domain", flag: true },
      { k: "query_freq", v: "14.2 /s", threshold: "10.0", means: "Query rate from this client", flag: true },
    ],
    timeline: [
      { at: "13:51:04", text: "Mean query length passed the 50-character threshold" },
      { at: "13:51:40", text: "Subdomain entropy and query rate also above thresholds" },
      { at: "13:52:11", text: "Tunnelling heuristics agreed on four signals — confidence 0.78" },
    ],
  },
  {
    id: "e2b64a90",
    flow_id: "147.32.84.209:1108-185.199.108.153:8443",
    threat_class: "C2",
    confidence: 0.64,
    severity: "medium",
    model_version: "c2-v1",
    source_ip: "147.32.84.209",
    destination_ip: "185.199.108.153",
    window_start: "13:47:00",
    window_end: "13:48:00",
    observed: "13:48:30",
    headline: "Loose 30-minute interval from 147.32.84.209",
    evidence: [
      { k: "periodicity_score", v: "0.72", threshold: "0.70", means: "Regular, but only just above threshold", flag: true },
      { k: "dominant_destination_ratio", v: "0.81", threshold: "0.70", means: "Most connections target one destination", flag: true },
      { k: "iat_cv", v: "0.22", means: "Timing varies far more than a tight beacon" },
      { k: "iat_mean", v: "1,802 s", means: "Roughly 30 minutes between connections" },
      { k: "connection_count", v: "9", threshold: "minimum 7 connections", means: "Few observations — limits confidence" },
    ],
    timeline: [
      { at: "13:18:05", text: "Repeating connections seen toward a single destination" },
      { at: "13:48:30", text: "Periodicity just above threshold on nine connections — scored 0.64" },
    ],
  },
  {
    id: "f508c1b7",
    flow_id: "198.18.4.9:40231-147.32.80.9:123",
    threat_class: "DDoS",
    confidence: 0.58,
    severity: "medium",
    model_version: "ddos-v1",
    source_ip: "198.18.4.9",
    destination_ip: "147.32.80.9",
    window_start: "13:44:15",
    window_end: "13:44:20",
    observed: "13:44:20",
    headline: "Elevated UDP packet rate on 147.32.80.9",
    evidence: [
      { k: "pps", v: "8,841", means: "Packets per second into this destination", flag: true },
      { k: "bps", v: "33 Mbps", means: "Bit rate over the same window" },
      { k: "syn_ratio", v: "0.02", means: "Almost no connection openers — not a SYN flood" },
      { k: "unique_dst_ips", v: "1", means: "All traffic aimed at a single destination" },
    ],
    timeline: [
      { at: "13:44:15", text: "UDP packet rate rose above the baseline for this link" },
      { at: "13:44:20", text: "Rate stayed below the flood threshold — scored 0.58" },
    ],
  },
  {
    id: "0a4d33e6",
    flow_id: "147.32.84.192:52001-10.0.0.53:53",
    threat_class: "DGA",
    confidence: 0.55,
    severity: "low",
    model_version: "dga-v6",
    source_ip: "147.32.84.192",
    destination_ip: "10.0.0.53",
    window_start: "13:41:00",
    window_end: "13:42:00",
    observed: "13:42:08",
    headline: "Borderline label entropy on 22 lookups",
    evidence: [
      { k: "avg_shannon_entropy", v: "3.61", threshold: "3.50", means: "Marginally above the entropy threshold", flag: true },
      { k: "avg_domain_length", v: "13.1", threshold: "12", means: "Marginally longer than typical domains", flag: true },
      { k: "nxdomain_ratio", v: "0.18", threshold: "0.40", means: "Most lookups resolved normally" },
      { k: "unique_domains_count", v: "22", means: "Few distinct domains in the window" },
    ],
    timeline: [
      { at: "13:42:08", text: "Entropy marginally over threshold, NXDOMAIN ratio normal — scored 0.55" },
    ],
  },
];

/*
 * Demo records carry one observation time each, and the epoch timestamp is
 * derived from it against a single demo date — so the time shown on screen and
 * the timestamp in the structured alert can never describe different moments.
 * Epoch SECONDS, matching the backend's REAL timestamp column. At integration
 * the backend supplies the field directly and this mapping goes away.
 */
const DEMO_DATE = '2026-09-27';
const epochSeconds = (clock) => new Date(`${DEMO_DATE}T${clock}`).getTime() / 1000;

export const alerts = demoAlerts.map((a) => ({ ...a, timestamp: epochSeconds(a.observed) }));

/* Alerts by detector over 24h. Order follows THREAT_ORDER. */
export const detectorActivity = [
  { threat_class: "DDoS", count: 12 },
  { threat_class: "C2", count: 9 },
  { threat_class: "DGA", count: 6 },
  { threat_class: "DNS-Tunnel", count: 3 },
];

/*
 * What a flow's state means. Deliberately three states and no more — each one
 * describes what SHIELDX has observed, never what it would do about it, because
 * a receive-only console cannot act on a flow.
 */
export const flowStateMeta = {
  alerting: {
    label: "Alerting",
    tone: "var(--critical)",
    meaning: "A detector has associated an active detection with this flow.",
  },
  watching: {
    label: "Watching",
    tone: "var(--warn)",
    meaning: "Inside a detector's evaluation window, with no detection raised yet.",
  },
  normal: {
    label: "Normal",
    tone: "var(--ok)",
    meaning: "No detection currently associated with this flow.",
  },
};

/* Derived, never stored — state follows from detection context, so real backend
 * context will produce it the same way. */
export function flowState(flow) {
  if (flow.detection) return "alerting";
  if (flow.evaluating) return "watching";
  return "normal";
}

/*
 * Observed flows, as a Zeek conn record reduced to what the console shows.
 * `family` is the protocol grouping the protocol-mix card filters on, and
 * `conn_state` uses Zeek's own vocabulary (S0 openers with no reply, SF normal
 * establish and teardown, S1 established and still open, OTH midstream).
 *
 * `detection.alert_id` points at a record in `alerts`, so a flow that a
 * detector cares about can be opened as its incident. Flow identifiers and
 * packet rates deliberately match the corresponding alert's evidence.
 */
export const flows = [
  {
    flow_id: "203.0.113.0/24-147.32.80.9:443",
    src_ip: "203.0.113.0/24",
    src_port: null,
    dst_ip: "147.32.80.9",
    dst_port: 443,
    proto: "TCP",
    family: "TCP",
    bytes: "1.15 GB",
    pps: "412,088",
    duration: "5 s",
    conn_state: "S0",
    first_seen: "13:54:50",
    last_seen: "13:54:55",
    detection: { alert_id: "c3a8b511", threat_class: "DDoS", confidence: 0.96 },
  },
  {
    flow_id: "147.32.84.165:1043-93.184.216.34:443",
    src_ip: "147.32.84.165",
    src_port: 1043,
    dst_ip: "93.184.216.34",
    dst_port: 443,
    proto: "TCP",
    family: "TCP",
    bytes: "29 KB",
    pps: "2",
    duration: "60 s window",
    conn_state: "SF",
    first_seen: "14:03:00",
    last_seen: "14:04:00",
    detection: { alert_id: "a1f4c2e8", threat_class: "C2", confidence: 0.91 },
  },
  {
    flow_id: "10.9.44.2:53129-10.0.0.53:53",
    src_ip: "10.9.44.2",
    src_port: 53129,
    dst_ip: "10.0.0.53",
    dst_port: 53,
    proto: "UDP",
    family: "DNS",
    bytes: "182 KB",
    pps: "42",
    duration: "60 s window",
    conn_state: "SF",
    first_seen: "13:57:00",
    last_seen: "13:58:00",
    detection: { alert_id: "b7e91d03", threat_class: "DGA", confidence: 0.87 },
  },
  {
    flow_id: "147.32.84.191:41022-8.8.8.8:53",
    src_ip: "147.32.84.191",
    src_port: 41022,
    dst_ip: "8.8.8.8",
    dst_port: 53,
    proto: "UDP",
    family: "DNS",
    bytes: "104 KB",
    pps: "14",
    duration: "60 s window",
    conn_state: "SF",
    first_seen: "13:51:00",
    last_seen: "13:52:00",
    detection: { alert_id: "d9c07f24", threat_class: "DNS-Tunnel", confidence: 0.78 },
  },
  {
    flow_id: "147.32.86.96:49510-203.0.113.9:443",
    src_ip: "147.32.86.96",
    src_port: 49510,
    dst_ip: "203.0.113.9",
    dst_port: 443,
    proto: "TCP",
    family: "TCP",
    bytes: "41 KB",
    pps: "3",
    duration: "60 s window",
    conn_state: "SF",
    first_seen: "14:03:10",
    last_seen: "14:04:05",
    evaluating: true,
  },
  {
    flow_id: "147.32.84.192:52001-10.0.0.53:53",
    src_ip: "147.32.84.192",
    src_port: 52001,
    dst_ip: "10.0.0.53",
    dst_port: 53,
    proto: "UDP",
    family: "DNS",
    bytes: "9 KB",
    pps: "1",
    duration: "60 s window",
    conn_state: "SF",
    first_seen: "13:41:00",
    last_seen: "13:42:00",
    detection: { alert_id: "0a4d33e6", threat_class: "DGA", confidence: 0.55 },
  },
  {
    flow_id: "147.32.84.170:44120-151.101.1.140:443",
    src_ip: "147.32.84.170",
    src_port: 44120,
    dst_ip: "151.101.1.140",
    dst_port: 443,
    proto: "TCP",
    family: "TCP",
    bytes: "812 KB",
    pps: "180",
    duration: "42 s",
    conn_state: "S1",
    first_seen: "14:03:24",
    last_seen: "14:04:06",
  },
  {
    flow_id: "147.32.84.164:60112-140.82.114.4:22",
    src_ip: "147.32.84.164",
    src_port: 60112,
    dst_ip: "140.82.114.4",
    dst_port: 22,
    proto: "TCP",
    family: "TCP",
    bytes: "44 KB",
    pps: "12",
    duration: "6 m 11 s",
    conn_state: "S1",
    first_seen: "13:57:55",
    last_seen: "14:04:06",
  },
  {
    flow_id: "147.32.84.134:51877-142.250.74.174:443",
    src_ip: "147.32.84.134",
    src_port: 51877,
    dst_ip: "142.250.74.174",
    dst_port: 443,
    proto: "UDP",
    family: "UDP",
    bytes: "980 KB",
    pps: "140",
    duration: "1 m 28 s",
    conn_state: "SF",
    first_seen: "14:02:38",
    last_seen: "14:04:06",
  },
  {
    flow_id: "147.32.84.13-147.32.80.9-icmp",
    src_ip: "147.32.84.13",
    src_port: null,
    dst_ip: "147.32.80.9",
    dst_port: null,
    proto: "ICMP",
    family: "ICMP",
    bytes: "1.2 KB",
    pps: "4",
    duration: "18 s",
    conn_state: "OTH",
    first_seen: "14:03:48",
    last_seen: "14:04:06",
  },
  {
    flow_id: "147.32.85.7-192.0.2.44-esp",
    src_ip: "147.32.85.7",
    src_port: null,
    dst_ip: "192.0.2.44",
    dst_port: null,
    proto: "ESP",
    family: "Other",
    bytes: "3.4 MB",
    pps: "120",
    duration: "14 m 02 s",
    conn_state: "OTH",
    first_seen: "13:50:04",
    last_seen: "14:04:06",
  },
];

/* Share of observed packets per protocol family. `family` keys into the flow
 * records above so the card can scope the flow table. */
export const protocolMix = [
  { label: "TCP", family: "TCP", value: 62 },
  { label: "UDP", family: "UDP", value: 21 },
  { label: "DNS", family: "DNS", value: 9 },
  { label: "ICMP", family: "ICMP", value: 5 },
  { label: "Other", family: "Other", value: 3 },
];

/*
 * What each component state means. These describe the state of the codebase,
 * not a running system — this console is not connected to a backend, so there
 * is deliberately no state that claims a component is live.
 */
export const componentStatusMeta = {
  ready: {
    label: "Ready",
    tone: "var(--ok)",
    meaning: "Implemented in the repository and covered by its tests.",
  },
  configured: {
    label: "Configured",
    tone: "var(--warn)",
    meaning: "Present with its configuration in place, not yet exercised from this console.",
  },
  pending: {
    label: "Integration pending",
    tone: "var(--ink-3)",
    meaning: "Not yet connected to this console.",
  },
};

/*
 * The components SHIELDX is built from, and their role. No runtime figures
 * appear here on purpose: CPU, memory, uptime and throughput cannot be known
 * until the console is connected, so the UI does not invent them.
 */
export const systemComponents = [
  {
    group: "Ingest",
    name: "Passive ingest",
    role: "Reads a mirror of the observed link. Receive-only by construction.",
    status: "ready",
  },
  {
    group: "Ingest",
    name: "Zeek",
    role: "Parses packets into conn, dns and http records on a common event schema.",
    status: "configured",
  },
  {
    group: "Processing",
    name: "Streaming engine",
    role: "Bounded event queue, sliding windows and the scheduler that drives them.",
    status: "ready",
  },
  {
    group: "Processing",
    name: "Feature extraction",
    role: "Per-window feature vectors and an online per-host baseline.",
    status: "ready",
  },
  {
    group: "Detection",
    name: "DDoS detector",
    role: "Threshold and statistical traffic analysis.",
    status: "ready",
  },
  {
    group: "Detection",
    name: "C2 detector",
    role: "Isolation Forest with temporal periodicity analysis.",
    status: "ready",
  },
  {
    group: "Detection",
    name: "DGA detector",
    role: "Character TF-IDF + logistic regression, with a character CNN providing independent evidence.",
    status: "ready",
  },
  {
    group: "Detection",
    name: "DNS tunnelling detector",
    role: "Multi-signal heuristic analysis against configured thresholds.",
    status: "configured",
  },
  {
    group: "Delivery",
    name: "Evidence / alert store",
    role: "Deduplicated alerts persisted to SQLite with the feature snapshot behind each one.",
    status: "ready",
  },
  {
    group: "Delivery",
    name: "FastAPI",
    role: "Read-only query surface over the alert store.",
    status: "configured",
  },
  {
    group: "Delivery",
    name: "WebSocket / console connection",
    role: "Pushes newly stored alerts to a connected console.",
    status: "pending",
  },
];

/* The platform's defining constraint, split into what it does and what it
 * structurally cannot do. */
export const securityBoundary = {
  observes: [
    { label: "Passive observation", detail: "Analysis runs against a copy of the traffic, never the traffic itself." },
    { label: "Receive-only ingest", detail: "The ingest path carries data in one direction only." },
  ],
  cannot: [
    { label: "No return path", detail: "There is no channel back onto a monitored link." },
    { label: "No control path", detail: "The platform issues no commands to network devices." },
    { label: "No inline mitigation", detail: "Nothing sits in the traffic path to drop, shape or redirect it." },
    { label: "No traffic modification", detail: "Observed packets are never rewritten, injected or replayed." },
  ],
};

/* Properties of the implementation as it actually stands. */
export const implementationNotes = [
  {
    label: "Streaming, not batch",
    detail: "Events are scored as they arrive in sliding windows rather than in scheduled passes.",
  },
  {
    label: "Passive observation",
    detail: "Detection works from traffic shape and timing, so encrypted payloads need no decryption.",
  },
  {
    label: "Structured alert output",
    detail: "Every detection is emitted on one standardized alert schema, whichever detector produced it.",
  },
  {
    label: "Evidence retained with alerts",
    detail: "The feature values that produced a verdict are stored alongside the verdict.",
  },
  {
    label: "SQLite persistence",
    detail: "Alerts and their evidence are written to a local SQLite store.",
  },
  {
    label: "FastAPI interface",
    detail: "A read-only HTTP surface serves stored alerts to a console.",
  },
  {
    label: "WebSocket alert channel",
    detail: "New alerts are pushed to connected consoles rather than polled for.",
  },
];

export const pipeline = [
  { id: "tap", label: "Passive tap", detail: "SPAN or optical mirror. Receive only — nothing is ever transmitted back onto the link." },
  { id: "zeek", label: "Zeek parser", detail: "Raw packets become conn / dns / http records with a common event schema." },
  { id: "queue", label: "Bounded queue", detail: "Async queue with overflow accounting, so a burst drops packets instead of the process." },
  { id: "windows", label: "Sliding windows", detail: "5s for DDoS, 60s for C2 and DNS. Out-of-order events are inserted in timestamp order." },
  { id: "features", label: "Feature extraction", detail: "Inter-arrival stats, entropy, rates — plus a Welford baseline per host." },
  { id: "models", label: "Four detectors", detail: "DDoS, C2, DGA and DNS tunnelling score each window independently." },
  { id: "fusion", label: "Evidence fusion", detail: "Signals combine into one confidence; severity is judged separately, on impact." },
  { id: "store", label: "Alert store", detail: "Deduplicated alerts persisted to SQLite with the feature snapshot that caused them." },
  { id: "api", label: "API and console", detail: "A read-only query surface, and the console an analyst reads it through." },
];

export const models = [
  {
    threat_class: "DDoS",
    version: "ddos-v1",
    kind: "Threshold + baseline deviation",
    trained_on: "Live link baseline (Welford, online)",
    window: "5 second window",
    features: ["pps", "bps", "syn_ratio", "unique_dst_ips"],
    notes: "One-way visibility is a feature here: because ShieldX never waits for a handshake, the absence of completion is itself the signal.",
  },
  {
    threat_class: "C2",
    version: "c2-v1",
    kind: "Isolation Forest + periodicity scorer",
    trained_on: "6,472 benign CTU-13 windows",
    window: "60 second window, min 7 connections",
    features: [
      "iat_mean",
      "iat_std",
      "iat_cv",
      "iat_entropy",
      "periodicity_score",
      "connection_count",
      "unique_destinations",
      "dominant_destination_ratio",
      "mean_duration",
      "mean_orig_bytes",
      "mean_resp_bytes",
      "orig_bytes_std",
      "byte_ratio",
      "udp_ratio",
      "mean_packets",
      "tcp_success_ratio",
    ],
    notes: "Confidence is a weighted blend — anomaly 0.35, periodicity 0.30, repetition 0.20, regularity 0.15. It is a ranking score, not a calibrated probability, and the console labels it that way.",
  },
  {
    threat_class: "DGA",
    version: "dga-v6",
    kind: "Character TF-IDF + logistic regression, with a character CNN providing independent evidence.",
    trained_on: "Tranco top-1M vs. 60+ DGA families",
    window: "Per domain, 24 character cap",
    features: ["character sequence", "shannon_entropy", "label_length", "digit_ratio", "nxdomain_ratio"],
    notes: "22,209 parameters over a 40-token vocabulary — small enough to score every lookup inline without a GPU.",
  },
  {
    threat_class: "DNS-Tunnel",
    version: "dns-v1",
    kind: "Multi-signal heuristics",
    trained_on: "Configured thresholds, tuned on resolver traffic",
    window: "60 second window per client",
    features: ["query_length", "subdomain_entropy", "query_freq", "unique_subdomains"],
    notes: "Deliberately rule-based: tunnelling has hard physical tells, and a reviewer can check every threshold by hand.",
  },
];

export const datasets = [
  { name: "CTU-13", use: "C2 training and evaluation", detail: "9,727,344 raw flows filtered to 185,003, producing 7,698 labelled 60-second windows (7,138 benign / 560 C2)." },
  { name: "DGA archive", use: "DGA training", detail: "60+ malware families, from banjori and tinba through to zloader and bumblebee." },
  { name: "Tranco top 1M", use: "Benign domain baseline", detail: "The negative class for the DGA model — real domains people actually resolve." },
];

/*
 * Observed traffic, held as recorded samples at two resolutions — the way an
 * alert store keeps raw observations plus rollups. There is ONE dataset and ONE
 * windowing function; the range control selects a window over it rather than
 * switching between separate hand-built charts.
 *
 * `observationWindow(range)` is the seam for integration: it returns
 * `{ samples, resolution, label }`, and a backend query for the same range
 * returns the same shape. Nothing downstream needs to change.
 */

const TIERS = {
  /* Five-minute samples covering the last three hours. */
  fine: {
    stepMinutes: 5,
    samples: [
      { t: "11:05", gbps: 12.1 },
      { t: "11:10", gbps: 12.8 },
      { t: "11:15", gbps: 11.9 },
      { t: "11:20", gbps: 13.4 },
      { t: "11:25", gbps: 14.0 },
      { t: "11:30", gbps: 13.1 },
      { t: "11:35", gbps: 12.6 },
      { t: "11:40", gbps: 13.8 },
      { t: "11:45", gbps: 14.6 },
      { t: "11:50", gbps: 14.1 },
      { t: "11:55", gbps: 15.2 },
      { t: "12:00", gbps: 14.7 },
      { t: "12:05", gbps: 13.9 },
      { t: "12:10", gbps: 14.4 },
      { t: "12:15", gbps: 15.8 },
      { t: "12:20", gbps: 16.2 },
      { t: "12:25", gbps: 15.4 },
      { t: "12:30", gbps: 14.9 },
      { t: "12:35", gbps: 15.1 },
      { t: "12:40", gbps: 16.7 },
      { t: "12:45", gbps: 17.2 },
      { t: "12:50", gbps: 16.4 },
      { t: "12:55", gbps: 15.9 },
      { t: "13:00", gbps: 16.1 },
      { t: "13:05", gbps: 15.6 },
      { t: "13:10", gbps: 16.8 },
      { t: "13:15", gbps: 17.4 },
      { t: "13:20", gbps: 16.9 },
      { t: "13:25", gbps: 17.1 },
      { t: "13:30", gbps: 18.2 },
      { t: "13:35", gbps: 17.6 },
      { t: "13:40", gbps: 19.1 },
      { t: "13:45", gbps: 20.4 },
      { t: "13:50", gbps: 19.6 },
      { t: "13:55", gbps: 21.2 },
      { t: "14:00", gbps: 18.9 },
      { t: "14:05", gbps: 18.4 },
    ],
  },
  /* Hourly rollups covering a full day, with the usual overnight trough. */
  hourly: {
    stepMinutes: 60,
    samples: [
      { t: "15:00", gbps: 17.4 },
      { t: "16:00", gbps: 18.1 },
      { t: "17:00", gbps: 18.9 },
      { t: "18:00", gbps: 16.7 },
      { t: "19:00", gbps: 14.4 },
      { t: "20:00", gbps: 12.9 },
      { t: "21:00", gbps: 10.8 },
      { t: "22:00", gbps: 9.6 },
      { t: "23:00", gbps: 8.6 },
      { t: "00:00", gbps: 7.9 },
      { t: "01:00", gbps: 7.2 },
      { t: "02:00", gbps: 6.8 },
      { t: "03:00", gbps: 6.9 },
      { t: "04:00", gbps: 7.4 },
      { t: "05:00", gbps: 8.1 },
      { t: "06:00", gbps: 9.8 },
      { t: "07:00", gbps: 12.7 },
      { t: "08:00", gbps: 15.3 },
      { t: "09:00", gbps: 17.3 },
      { t: "10:00", gbps: 18.6 },
      { t: "11:00", gbps: 19.8 },
      { t: "12:00", gbps: 19.1 },
      { t: "13:00", gbps: 18.1 },
      { t: "14:00", gbps: 18.9 },
      { t: "14:05", gbps: 18.4 },
    ],
  },
};

/* Which tier serves each range, and how much of it the window covers. */
const RANGES = {
  "1h": { tier: "fine", minutes: 60, label: "last hour" },
  "3h": { tier: "fine", minutes: 180, label: "last 3 hours" },
  "24h": { tier: "hourly", minutes: 1440, label: "last 24 hours" },
};

export const RANGE_KEYS = Object.keys(RANGES);

export function observationWindow(range) {
  const spec = RANGES[range] ?? RANGES["3h"];
  const tier = TIERS[spec.tier];
  /* +1 because the window is inclusive of both ends. */
  const count = Math.min(tier.samples.length, Math.floor(spec.minutes / tier.stepMinutes) + 1);
  return {
    samples: tier.samples.slice(-count),
    resolution: tier.stepMinutes,
    label: spec.label,
  };
}

/* Most recent observation — the value the KPI tile reads. */
export const trafficNow = (() => {
  const { samples } = observationWindow("3h");
  return { value: samples[samples.length - 1].gbps, unit: "Gbps" };
})();

export const config = {
  c2: { min_connections: 7, contamination: 0.05, periodicity_lag_max: 20, repetition_ratio_threshold: 0.7 },
  dga: { entropy_threshold: 3.5, length_threshold: 12, digit_ratio_threshold: 0.3, nxdomain_ratio_threshold: 0.4 },
  dns_tunnel: { query_length_threshold: 50, entropy_threshold: 3.8, query_freq_threshold: 10.0, unique_subdomain_threshold: 20 },
};

export function confidenceBand(c) {
  if (c >= 0.85) return "High";
  if (c >= 0.65) return "Moderate";
  return "Low";
}
