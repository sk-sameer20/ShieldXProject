import { useMemo, useState } from "react";
import { BarList, Trend } from "@/components/Charts";
import { Dot, KeyValue, Panel, SectionHead } from "@/components/ui";
import { useTraffic, useStats, useProtocols, useAlerts } from "@/hooks/useShieldX";
import { flows } from "@/data/telemetry";
import { parseUtcDate } from "@/lib/time";

const formatMb = (bytes) => {
  if (!bytes) return "0 MB";
  return `${(bytes / 1000000).toFixed(1)} MB`;
};

export function Traffic() {
  const { data: trafficData, isSuccess: isTrafficSuccess } = useTraffic(30);
  const { data: stats } = useStats();
  const { data: protocols } = useProtocols();
  const { data: alertsRes } = useAlerts({ page_size: 100 });
  const [selectedProtocol, setSelectedProtocol] = useState(null);

  const directionalIps = useMemo(() => {
    if (!selectedProtocol) return null;

    const protoUpper = selectedProtocol.toUpperCase();
    const isInternal = (ip) => {
      if (!ip) return false;
      const clean = ip.split("/")[0].trim();
      return (
        clean.startsWith("10.") ||
        clean.startsWith("192.168.") ||
        clean.startsWith("147.32.") ||
        /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(clean)
      );
    };

    const matchesProto = (pStr) => {
      const p = (pStr || "").toUpperCase();
      if (protoUpper === "TCP") return p.includes("TCP") || p.includes("TLS") || p.includes("HTTP");
      if (protoUpper === "UDP") return p.includes("UDP") && !p.includes("DNS");
      if (protoUpper === "DNS") return p.includes("DNS");
      if (protoUpper === "ICMP") return p.includes("ICMP");
      return false;
    };

    const inboundMap = {};
    const outboundMap = {};

    // 1. Process observed security alerts from enclave backend
    if (alertsRes?.items && Array.isArray(alertsRes.items)) {
      alertsRes.items.forEach((a) => {
        if (!matchesProto(a.protocol)) return;

        const pkts =
          a.trigger_features?.syn_pps ||
          a.evidence?.trigger_features?.syn_pps ||
          (typeof a.trigger_features?.packets === "number" ? a.trigger_features.packets : null) ||
          1;

        const src = a.source_ip || a.srcIp;
        const dst = a.destination_ip || a.destIp;

        if (src && dst) {
          if (!isInternal(src) && isInternal(dst)) {
            inboundMap[dst] = (inboundMap[dst] || 0) + pkts;
          } else if (isInternal(src) && !isInternal(dst)) {
            outboundMap[src] = (outboundMap[src] || 0) + pkts;
          } else {
            if (isInternal(dst)) inboundMap[dst] = (inboundMap[dst] || 0) + pkts;
            if (isInternal(src)) outboundMap[src] = (outboundMap[src] || 0) + pkts;
          }
        }
      });
    }

    // 2. Process passive connection flow records if available/fallback
    if (Array.isArray(flows)) {
      flows.forEach((f) => {
        if (!matchesProto(f.proto || f.family)) return;

        const pkts =
          typeof f.packets === "number"
            ? f.packets
            : parseInt(String(f.pps || "1").replace(/,/g, ""), 10) || 1;

        const src = f.src_ip;
        const dst = f.dst_ip;

        if (src && dst) {
          if (!isInternal(src) && isInternal(dst)) {
            inboundMap[dst] = (inboundMap[dst] || 0) + pkts;
          } else if (isInternal(src) && !isInternal(dst)) {
            outboundMap[src] = (outboundMap[src] || 0) + pkts;
          } else {
            if (isInternal(dst)) inboundMap[dst] = (inboundMap[dst] || 0) + pkts;
            if (isInternal(src)) outboundMap[src] = (outboundMap[src] || 0) + pkts;
          }
        }
      });
    }

    const topIn = Object.entries(inboundMap).sort((a, b) => b[1] - a[1])[0];
    const topOut = Object.entries(outboundMap).sort((a, b) => b[1] - a[1])[0];

    return {
      inbound: topIn ? { ip: topIn[0], count: topIn[1], unit: "packets" } : null,
      outbound: topOut ? { ip: topOut[0], count: topOut[1], unit: "packets" } : null,
    };
  }, [selectedProtocol, alertsRes]);

  const liveSamples =
    isTrafficSuccess && trafficData && trafficData.length > 0
      ? trafficData.map((p) => {
          let label = p.time_label || "";
          if (p.timestamp) {
            const d = parseUtcDate(p.timestamp);
            if (d) {
              const h = String(d.getHours()).padStart(2, "0");
              const m = String(d.getMinutes()).padStart(2, "0");
              label = `${h}:${m}`;
            }
          }
          return {
            label,
            value: p.mbps,
            packets: p.packets_per_sec,
            is_anomaly: p.is_anomaly,
          };
        })
      : null;

  const totalCapturedPackets = useMemo(() => {
    if (!protocols || !protocols.length) return 0;
    return protocols.reduce((sum, p) => sum + p.packet_count, 0);
  }, [protocols]);

  const totalCapturedBytes = useMemo(() => {
    if (!protocols || !protocols.length) return 0;
    return protocols.reduce((sum, p) => sum + p.byte_count, 0);
  }, [protocols]);

  return (
    <>
      <SectionHead
        eyebrow="Observation"
        title="Live traffic"
        hint="What the observed network is doing right now. Aggregate throughput and passive flow volume across the monitored link."
      />

      <Panel
        title="Observed traffic"
        hint={
          stats
            ? `Current throughput: ${stats.mbps.toFixed(2)} Mbps · ${Math.round(stats.packets_per_sec || 0).toLocaleString()} pps`
            : "Aggregate activity crossing the observed link. Passive observation."
        }
        meta={stats ? "Mbps · Enclave Live" : "Offline"}
      >
        {liveSamples ? (
          <Trend data={liveSamples} unit=" Mbps" label="Observed traffic" height={240} xKey="label" yKey="value" />
        ) : (
          <div style={{ height: 240, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--muted)", fontSize: 14 }}>
            {isTrafficSuccess ? "No live traffic observed" : "Offline · No live traffic observed"}
          </div>
        )}
      </Panel>

      <div className="stack" style={{ gap: 16 }}>
        <Panel
          title="Aggregate flow activity"
          hint="Flows observed in current window. Real-time aggregate flow volume across the monitored link."
          meta={stats ? `${stats.active_flows.toLocaleString()} flows` : "—"}
        >
          <div className="flow-hero">
            <div className="flow-stat">
              <span className="flow-stat__label">Active flows</span>
              <div className="flow-stat__val">
                {stats ? stats.active_flows.toLocaleString() : "—"}
                <span className="flow-stat__unit">flows</span>
              </div>
              <p className="flow-stat__sub">Observed in current window</p>
            </div>

            <div className="flow-stat">
              <span className="flow-stat__label">Throughput</span>
              <div className="flow-stat__val">
                {stats ? stats.mbps.toFixed(1) : "—"}
                <span className="flow-stat__unit">Mbps</span>
              </div>
              <p className="flow-stat__sub">Current link bandwidth</p>
            </div>

            <div className="flow-stat">
              <span className="flow-stat__label">Packet rate</span>
              <div className="flow-stat__val">
                {stats ? Math.round(stats.packets_per_sec || 0).toLocaleString() : "—"}
                <span className="flow-stat__unit">pps</span>
              </div>
              <p className="flow-stat__sub">Ingress packet rate</p>
            </div>

            <div className="flow-stat">
              <span className="flow-stat__label">Observation</span>
              <div className="flow-stat__val" style={{ gap: 8, fontSize: 18, alignItems: "center" }}>
                <Dot tone="var(--ok)" live />
                <span>Passive</span>
                <span className="flow-stat__unit">RX-only</span>
              </div>
              <p className="flow-stat__sub">Hardware diode link</p>
            </div>
          </div>

          <div className="facts">
            <KeyValue label="Detection latency">
              {stats ? `${stats.detection_latency_ms.toFixed(1)} ms (Enclave baseline)` : "—"}
            </KeyValue>
            <KeyValue label="Hardware diode egress">
              {stats ? `${stats.actual_egress_packets} pkts · ${stats.actual_egress_bytes} B (Physically severed TX)` : "—"}
            </KeyValue>
            <KeyValue label="Capture interface">
              Passive non-intrusive optical tap (10 GbE)
            </KeyValue>
            <KeyValue label="Diode boundary">
              Zero return packets · Unidirectional optical PHY
            </KeyValue>
          </div>

          <div className="flow-notice">
            <strong>Diode Boundary Policy:</strong> Individual per-flow records are restricted from console export across the unidirectional boundary. Continuous flow state tables are captured within hardware ring buffer memory and extracted only upon confirmed detection triggers.
          </div>
        </Panel>

        <Panel
          title="Protocol telemetry"
          hint="L4 ingress protocol distribution and packet volume captured across the monitored link."
          meta={protocols && protocols.length > 0 ? `${protocols.length} protocols tracked` : (stats ? "Enclave Live" : "—")}
        >
          {protocols && protocols.length > 0 ? (
            <div className="protocol-layout">
              <div className="protocol-col">
                <h3 className="protocol-col__title">Bandwidth share (% link volume)</h3>
                <BarList
                  rows={protocols.map((p) => ({
                    label: p.name,
                    value: p.bandwidth_pct,
                    color: p.color,
                  }))}
                  max={100}
                  unit="%"
                  selected={selectedProtocol}
                  onSelect={setSelectedProtocol}
                />

                {selectedProtocol && (
                  <div className="protocol-ip-detail">
                    <div className="protocol-ip-detail__head">
                      <span className="protocol-ip-detail__title">{selectedProtocol}</span>
                      <span className="protocol-ip-detail__hint">Directional endpoints</span>
                    </div>

                    <div className="protocol-ip-detail__grid">
                      <div className="protocol-ip-detail__group">
                        <span className="protocol-ip-detail__label">Most observed inbound IP</span>
                        <div className="protocol-ip-detail__val">
                          {directionalIps?.inbound ? (
                            <>
                              <span className="mono">{directionalIps.inbound.ip}</span>
                              <span className="protocol-ip-detail__sep">—</span>
                              <span className="tnum">{directionalIps.inbound.count.toLocaleString()} {directionalIps.inbound.unit}</span>
                            </>
                          ) : (
                            <span className="protocol-ip-detail__empty">Unavailable · No inbound packets</span>
                          )}
                        </div>
                      </div>

                      <div className="protocol-ip-detail__group">
                        <span className="protocol-ip-detail__label">Most observed outbound IP</span>
                        <div className="protocol-ip-detail__val">
                          {directionalIps?.outbound ? (
                            <>
                              <span className="mono">{directionalIps.outbound.ip}</span>
                              <span className="protocol-ip-detail__sep">—</span>
                              <span className="tnum">{directionalIps.outbound.count.toLocaleString()} {directionalIps.outbound.unit}</span>
                            </>
                          ) : (
                            <span className="protocol-ip-detail__empty">Unavailable · No outbound packets</span>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              <div className="protocol-col">
                <h3 className="protocol-col__title">Protocol volume breakdown</h3>
                <table className="protocol-table">
                  <thead>
                    <tr>
                      <th>Protocol</th>
                      <th style={{ textAlign: "right" }}>Packets</th>
                      <th style={{ textAlign: "right" }}>Volume</th>
                      <th style={{ textAlign: "right" }}>Share</th>
                    </tr>
                  </thead>
                  <tbody>
                    {protocols.map((p) => (
                      <tr key={p.name}>
                        <td>
                          <span className="protocol-badge">
                            <i className="protocol-badge__dot" style={{ background: p.color }} aria-hidden />
                            {p.name}
                          </span>
                        </td>
                        <td className="tnum" style={{ textAlign: "right" }}>
                          {p.packet_count.toLocaleString()}
                        </td>
                        <td className="tnum" style={{ textAlign: "right" }}>
                          {formatMb(p.byte_count)}
                        </td>
                        <td className="tnum" style={{ textAlign: "right", fontWeight: 600 }}>
                          {p.bandwidth_pct.toFixed(1)}%
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>

                <div className="protocol-summary-bar">
                  <span>
                    Total captured: <strong>{totalCapturedPackets.toLocaleString()} pkts</strong> ({formatMb(totalCapturedBytes)})
                  </span>
                  <span>Hardware ring buffer active</span>
                </div>
              </div>
            </div>
          ) : (
            <div style={{ padding: "28px 16px", textAlign: "center", color: "var(--muted)", fontSize: 13 }}>
              {stats ? (
                <>
                  <p style={{ margin: "0 0 6px 0", color: "var(--ink-2)", fontWeight: 550 }}>
                    Ingress Protocol Monitoring Active
                  </p>
                  <p style={{ margin: 0, fontSize: 12 }}>
                    Full L4 protocol distribution is captured in hardware ring buffer. Ingress link rate: {stats.mbps.toFixed(2)} Mbps ({Math.round(stats.packets_per_sec || 0).toLocaleString()} pps).
                  </p>
                </>
              ) : (
                "Offline · Protocol telemetry unavailable"
              )}
            </div>
          )}
        </Panel>
      </div>
    </>
  );
}
