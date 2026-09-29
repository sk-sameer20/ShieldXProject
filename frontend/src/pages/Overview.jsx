import { useMemo } from "react";
import { Link, useOutletContext } from "@/lib/rr";
import { AlertTriangle, ArrowRight, ShieldCheck } from "lucide-react";
import { Donut, Trend } from "@/components/Charts";
import { GlassLink } from "@/components/Glass";
import { Panel, SeverityTag, Stat, ThreatTag } from "@/components/ui";
import { GlobalAttackMap } from "@/components/GlobalAttackMap";
import {
  confidenceBand,
  detectionFamilies,
  severityMeta,
} from "@/data/telemetry";
import { useStats, useThreatDistribution, useAlerts, useTraffic } from "@/hooks/useShieldX";
import { formatLocalTimestamp, parseUtcDate } from "@/lib/time";

export function Overview() {
  const { range } = useOutletContext();

  // Real backend queries
  const { data: stats, isSuccess: isStatsSuccess } = useStats();
  const { data: threatDist } = useThreatDistribution();
  const { data: alertsRes, isSuccess: isAlertsSuccess } = useAlerts({ page_size: 10 });
  const { data: trafficData, isSuccess: isTrafficSuccess } = useTraffic(20);

  // Active data selection: Live backend when connected, honest empty state when offline
  const isLive = isStatsSuccess || isAlertsSuccess;
  const activeAlerts = isAlertsSuccess && alertsRes?.items ? alertsRes.items : [];

  const critical = stats?.critical_count ?? (isAlertsSuccess ? activeAlerts.filter((a) => String(a.severity).toLowerCase() === "critical").length : 0);
  const high = stats?.high_count ?? (isAlertsSuccess ? activeAlerts.filter((a) => String(a.severity).toLowerCase() === "high").length : 0);
  const pressing = isLive ? critical + high : 0;
  const totalCount = isStatsSuccess && stats ? stats.total_alerts : (isAlertsSuccess ? (alertsRes?.total ?? activeAlerts.length) : null);

  const headline = !isLive
    ? "Backend offline — awaiting telemetry"
    : critical > 0
      ? `${critical} critical detection${critical > 1 ? "s" : ""} in this window`
      : high > 0
        ? `${high} high-severity detection${high > 1 ? "s" : ""} in this window`
        : "No significant detections in this window";

  const leading = [...activeAlerts]
    .sort((a, b) => (b.confidence ?? 0) - (a.confidence ?? 0))
    .slice(0, 2);

  // Threat distribution mapping: strictly display the 4 primary detection engine families
  const PRIMARY_FAMILIES = useMemo(() => [
    { label: "DDoS", color: "var(--series-1, #ef4444)" },
    { label: "C2", color: "var(--series-2, #f97316)" },
    { label: "DGA", color: "var(--series-3, #8b5cf6)" },
    { label: "DNS Tunnel", color: "var(--series-4, #eab308)" },
  ], []);

  const familyRows = useMemo(() => {
    if (threatDist?.categories && threatDist.categories.length > 0) {
      return PRIMARY_FAMILIES.map((family) => {
        const found = threatDist.categories.find((c) => {
          const l = String(c.label || "").toUpperCase();
          if (family.label === "DDoS") return l === "DDOS";
          if (family.label === "C2") return l === "C2" || l.includes("C2");
          if (family.label === "DGA") return l === "DGA";
          if (family.label === "DNS Tunnel") return l.includes("DNS") || l.includes("TUNNEL");
          return false;
        });

        return {
          label: family.label,
          color: family.color,
          value: found ? found.count : 0,
        };
      });
    }

    return PRIMARY_FAMILIES.map((f) => ({
      label: f.label,
      color: f.color,
      value: 0,
    }));
  }, [threatDist, PRIMARY_FAMILIES]);

  // Live traffic samples mapping with local timezone formatting
  const trafficSamples =
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

  return (
    <>
      <div className="posture rise">
        <div className="posture__main">
          <span className="posture__icon" data-calm={!isLive || pressing === 0}>
            {pressing > 0 ? (
              <AlertTriangle size={16} strokeWidth={2.1} aria-hidden />
            ) : (
              <ShieldCheck size={16} strokeWidth={2.1} aria-hidden />
            )}
          </span>
          <div className="posture__body">
            <p className="posture__head">{headline}</p>
            <p className="posture__detail">
              {!isLive
                ? "Enclave connection unavailable. No live alerts observed."
                : leading.length
                  ? `Highest confidence right now: ${leading
                      .map((a) => a.attack_classification || a.classification || a.reason || a.headline || "Detection")
                      .join("; ")}.`
                  : "Nothing recorded from any detector in this window."}
            </p>
          </div>
          <div className="posture__aside">
            <GlassLink to="/console/incidents" variant="ink" size="sm">
              View detections
              <ArrowRight size={14} />
            </GlassLink>
          </div>
        </div>

        <div className="watching">
          <span className="watching__label">Monitoring</span>
          <ul className="watching__list">
            {detectionFamilies.map((f) => (
              <li key={f.id} className="watching__item">
                <i className="watching__dot" style={{ background: f.color }} aria-hidden />
                {f.label}
                <span className="watching__state">{isLive ? "active" : "offline"}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="g3" data-stagger>
        <Stat
          label="Open detections"
          value={totalCount !== null ? totalCount : "—"}
          note={
            isLive && stats
              ? `${critical} critical · ${high} high · ${stats.medium_count ?? 0} medium`
              : isLive
                ? `${activeAlerts.length} total recorded`
                : "Offline · Passive, receive-only"
          }
        />
        <Stat
          label="Critical and high"
          value={isLive ? pressing : "—"}
          accent={pressing > 0 ? "var(--critical)" : undefined}
          note={isLive && totalCount !== null ? `of ${totalCount} recorded` : "Offline"}
        />
        <Stat
          label="Traffic observed"
          value={stats ? stats.mbps.toFixed(1) : "—"}
          unit={stats ? "Mbps" : ""}
          note={stats ? `${Math.round(stats.packets_per_sec || 0).toLocaleString()} pps · Passive` : "Offline · Passive, receive-only"}
        />
      </div>

      <div className="g2-1">
        <Panel
          title="Observed traffic"
          hint="Aggregate activity crossing the observed link. Hover the line to read a value."
          meta={stats ? `Mbps · Live Enclave` : `Offline`}
          footer={
            stats ? (
              <div style={{ display: "flex", gap: "24px", fontSize: "12px", color: "var(--ink-2)", flexWrap: "wrap", alignItems: "center" }}>
                <span><b>Current:</b> {stats.mbps.toFixed(1)} Mbps</span>
                <span><b>Rate:</b> {Math.round(stats.packets_per_sec).toLocaleString()} pps</span>
                <span><b>Active flows:</b> {stats.active_flows.toLocaleString()}</span>
                <span><b>Inference latency:</b> {stats.detection_latency_ms.toFixed(1)} ms</span>
              </div>
            ) : null
          }
        >
          {trafficSamples && trafficSamples.length > 0 ? (
            <Trend data={trafficSamples} unit=" Mbps" label="Observed traffic" height={248} xKey="label" yKey="value" />
          ) : (
            <div style={{ height: 248, display: "flex", alignItems: "center", justifyContent: "center", color: "var(--muted)", fontSize: 14 }}>
              {isTrafficSuccess ? "No live traffic observed" : "Offline · No live traffic observed"}
            </div>
          )}
        </Panel>

        <Panel
          title="Threat distribution"
          hint="Which detection families are producing alerts. Hover a slice for its count."
          meta={isLive ? "Detections" : "Offline"}
          footer={
            <Link to="/console/detectors" className="foot-link">
              How each detector works <ArrowRight size={13} />
            </Link>
          }
        >
          <Donut rows={familyRows} centreLabel="detections" />
        </Panel>
      </div>

      <GlobalAttackMap />

      <Panel
        title="Recent alerts"
        hint="Newest first. Each row carries the detector that fired and how strongly its signals agreed."
        meta={isAlertsSuccess ? `${activeAlerts.length} records` : "Offline"}
        footer={
          <Link to="/console/incidents" className="foot-link">
            Open full evidence for any alert <ArrowRight size={13} />
          </Link>
        }
      >
        <table className="table table--rows">
          <thead>
            <tr>
              <th>Severity</th>
              <th>What happened</th>
              <th>Type</th>
              <th>Source</th>
              <th className="num-col">Confidence</th>
              <th className="num-col">Seen</th>
            </tr>
          </thead>
          <tbody>
            {activeAlerts.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ textAlign: "center", padding: "24px 0", color: "var(--muted)" }}>
                  {isAlertsSuccess ? "No detections recorded in this window" : "Offline · No detections recorded"}
                </td>
              </tr>
            ) : (
              activeAlerts.map((a) => {
                const sev = String(a.severity || "low").toLowerCase();
                const conf = typeof a.confidence === "number" ? a.confidence : null;
                const timeDisplay = formatLocalTimestamp(a.timestamp);

                return (
                  <tr key={a.id || a.alert_id}>
                    <td>
                      <SeverityTag severity={sev} />
                    </td>
                    <td className="cell-head">
                      {a.attack_classification || a.classification || a.reason || a.headline || "Detection Alert"}
                    </td>
                    <td>
                      <ThreatTag threat_class={a.threat_class || a.threatClass || "ANOMALY"} size="sm" />
                    </td>
                    <td className="mono">{a.source_ip || a.srcIp || "—"}</td>
                    <td className="num-col">
                      {conf !== null ? conf.toFixed(2) : "—"}
                      <span className="cell-sub">{conf !== null ? confidenceBand(conf) : ""}</span>
                    </td>
                    <td className="num-col mono">{timeDisplay}</td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </Panel>
    </>
  );
}
