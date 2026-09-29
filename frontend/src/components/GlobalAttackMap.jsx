import React, { useState, useMemo, useEffect, useRef, memo } from "react";
import {
  Globe,
  Maximize2,
  Minimize2,
  Shield,
  ArrowRight,
} from "lucide-react";
import { CONTINENTS, GRATICULES } from "./WorldMapVectors";
import { resolveGeoEndpoint, computeArcTrajectory } from "@/lib/geo";
import { useAlerts } from "@/hooks/useShieldX";
import { formatLocalTimestamp } from "@/lib/time";
import { SeverityTag, ThreatTag } from "./ui";

const FILTER_OPTIONS = ["All", "DDoS", "C2", "DGA", "DNS Tunnel"];

const THREAT_COLORS = {
  DDOS: "var(--series-1, #ef4444)",
  DDoS: "var(--series-1, #ef4444)",
  C2: "var(--series-2, #f59e0b)",
  C2_BEACONING: "var(--series-2, #f59e0b)",
  DGA: "var(--series-3, #8b5cf6)",
  "DNS Tunnel": "var(--series-4, #eab308)",
  DNS: "var(--series-4, #eab308)",
  DNS_TUNNEL: "var(--series-4, #eab308)",
  "DNS-Tunnel": "var(--series-4, #eab308)",
  SCANNING: "#ec4899",
  ANOMALY: "var(--series-4, #10b981)",
};

function getThreatColor(threatClass) {
  const norm = String(threatClass || "").toUpperCase();
  if (norm.includes("DDOS")) return THREAT_COLORS.DDOS;
  if (norm.includes("C2")) return THREAT_COLORS.C2;
  if (norm.includes("TUNNEL") || (norm.includes("DNS") && !norm.includes("DGA"))) return THREAT_COLORS["DNS Tunnel"];
  if (norm.includes("DGA")) return THREAT_COLORS.DGA;
  if (norm.includes("SCAN")) return THREAT_COLORS.SCANNING;
  return THREAT_COLORS.ANOMALY;
}

function matchesFilter(threatClass, filter) {
  if (!filter || filter === "All") return true;
  const tc = String(threatClass || "").toUpperCase();
  if (filter === "DDoS") return tc.includes("DDOS");
  if (filter === "C2") return tc.includes("C2");
  if (filter === "DGA") return tc === "DGA" || (tc.includes("DGA") && !tc.includes("TUNNEL"));
  if (filter === "DNS Tunnel" || filter === "DNS") return tc.includes("DNS") || tc.includes("TUNNEL");
  return false;
}

// Memoized static SVG geography layers to avoid recalculation/re-rendering
const StaticMapBackground = memo(function StaticMapBackground() {
  return (
    <>
      <g className="map-graticules">
        {GRATICULES.map((g) => (
          <path
            key={g.id}
            d={g.d}
            className="map-graticule"
            strokeDasharray={g.strokeDasharray}
            opacity={g.opacity}
          />
        ))}
      </g>
      <g className="map-continents">
        {CONTINENTS.map((continent) => (
          <path
            key={continent.id}
            d={continent.d}
            className="map-continent"
            id={`continent-${continent.id}`}
          />
        ))}
      </g>
    </>
  );
});

export function GlobalAttackMap() {
  const [activeFilter, setActiveFilter] = useState("All");
  const [isExpanded, setIsExpanded] = useState(false);
  const [hoveredFlow, setHoveredFlow] = useState(null);
  const [selectedFlowId, setSelectedFlowId] = useState(null);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });
  const containerRef = useRef(null);

  // Real backend alerts
  const { data: alertsRes } = useAlerts({ page_size: 50 });
  const rawAlerts = alertsRes?.items || [];

  // Lock body scroll and listen for Escape key when expanded
  useEffect(() => {
    if (!isExpanded) return;
    document.body.style.overflow = "hidden";

    function handleKeyDown(e) {
      if (e.key === "Escape") {
        setIsExpanded(false);
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      document.body.style.overflow = "";
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [isExpanded]);

  // Derive attack flows once from rawAlerts
  const allFlows = useMemo(() => {
    if (!rawAlerts || rawAlerts.length === 0) return [];

    return rawAlerts.map((alert, index) => {
      const srcIp = alert.source_ip || alert.srcIp || "198.51.100.44";
      const dstIp = alert.destination_ip || alert.destIp || "10.240.0.12";
      const srcGeo = resolveGeoEndpoint(srcIp);
      const dstGeo = resolveGeoEndpoint(dstIp);

      const threat = alert.threat_class || alert.threatClass || "ANOMALY";
      const color = getThreatColor(threat);
      const arc = computeArcTrajectory(srcGeo.x, srcGeo.y, dstGeo.x, dstGeo.y);

      return {
        id: alert.id || alert.alert_id || `flow-${index}`,
        alert,
        threat,
        severity: alert.severity || "HIGH",
        confidence: alert.confidence ?? 0.85,
        timestamp: alert.timestamp,
        srcIp,
        dstIp,
        srcGeo,
        dstGeo,
        color,
        arc,
        duration: Math.max(2.0, Math.min(3.6, arc.dist / 140)),
      };
    });
  }, [rawAlerts]);

  // Filter flows by active detector category
  const filteredFlows = useMemo(() => {
    return allFlows.filter((flow) => matchesFilter(flow.threat, activeFilter));
  }, [allFlows, activeFilter]);

  // Unique origin regions for summary
  const topOrigin = useMemo(() => {
    if (filteredFlows.length === 0) return "None observed";
    const counts = {};
    filteredFlows.forEach((f) => {
      const r = f.srcGeo.region;
      counts[r] = (counts[r] || 0) + 1;
    });
    return Object.entries(counts).sort((a, b) => b[1] - a[1])[0]?.[0] || "Global";
  }, [filteredFlows]);

  // Distinct nodes for drawing
  const nodes = useMemo(() => {
    const nodeMap = new Map();

    filteredFlows.forEach((f) => {
      // Source node
      const srcKey = `${f.srcGeo.x},${f.srcGeo.y}`;
      if (!nodeMap.has(srcKey)) {
        nodeMap.set(srcKey, {
          ...f.srcGeo,
          type: "source",
          color: f.color,
          flowCount: 1,
        });
      } else {
        nodeMap.get(srcKey).flowCount += 1;
      }

      // Destination node
      const dstKey = `${f.dstGeo.x},${f.dstGeo.y}`;
      if (!nodeMap.has(dstKey)) {
        nodeMap.set(dstKey, {
          ...f.dstGeo,
          type: "destination",
          color: "var(--ink)",
          flowCount: 1,
        });
      } else {
        nodeMap.get(dstKey).flowCount += 1;
      }
    });

    return Array.from(nodeMap.values());
  }, [filteredFlows]);

  function handleMouseMove(e) {
    if (!containerRef.current) return;
    const rect = containerRef.current.getBoundingClientRect();
    setMousePos({
      x: e.clientX - rect.left,
      y: e.clientY - rect.top,
    });
  }

  // Render SVG Map content - Fast, hardware-accelerated, no blur filter stalls
  const renderMapSvg = (isLarge = false) => (
    <svg
      viewBox="0 0 1000 500"
      className="attack-map-svg"
      preserveAspectRatio="xMidYMid meet"
    >
      {/* Memoized static continent shapes and graticules */}
      <StaticMapBackground />

      {/* Major Geographic Labels in expanded mode */}
      {isLarge && (
        <g className="map-geo-labels" pointerEvents="none" opacity="0.6">
          <text x="210" y="145" fontSize="11" fill="var(--ink-3)" fontFamily="var(--mono)" letterSpacing="0.08em">
            NORTH AMERICA
          </text>
          <text x="330" y="325" fontSize="11" fill="var(--ink-3)" fontFamily="var(--mono)" letterSpacing="0.08em">
            SOUTH AMERICA
          </text>
          <text x="515" y="125" fontSize="11" fill="var(--ink-3)" fontFamily="var(--mono)" letterSpacing="0.08em">
            EUROPE
          </text>
          <text x="525" y="275" fontSize="11" fill="var(--ink-3)" fontFamily="var(--mono)" letterSpacing="0.08em">
            AFRICA
          </text>
          <text x="730" y="130" fontSize="11" fill="var(--ink-3)" fontFamily="var(--mono)" letterSpacing="0.08em">
            ASIA
          </text>
          <text x="860" y="365" fontSize="11" fill="var(--ink-3)" fontFamily="var(--mono)" letterSpacing="0.08em">
            OCEANIA
          </text>
        </g>
      )}

      {/* Attack Paths / Arcs */}
      <g className="map-trajectories">
        {filteredFlows.map((flow) => {
          const isSelected = selectedFlowId === flow.id;
          const isHovered = hoveredFlow?.id === flow.id;
          const opacity = selectedFlowId ? (isSelected ? 1 : 0.18) : (isHovered ? 1 : 0.75);

          return (
            <g
              key={flow.id}
              className="map-flow-group"
              onMouseEnter={() => setHoveredFlow(flow)}
              onMouseLeave={() => setHoveredFlow(null)}
              onClick={(e) => {
                e.stopPropagation();
                setSelectedFlowId(selectedFlowId === flow.id ? null : flow.id);
              }}
              cursor="pointer"
            >
              {/* Underlying trajectory arc */}
              <path
                d={flow.arc.path}
                className="map-arc-base"
                strokeWidth={isHovered || isSelected ? "1.8" : "1"}
              />

              {/* Active flowing threat line */}
              <path
                d={flow.arc.path}
                className="map-arc-active"
                stroke={flow.color}
                opacity={opacity}
                strokeWidth={isHovered || isSelected ? "2.6" : isLarge ? "2" : "1.6"}
              />

              {/* Flow particle: source to destination */}
              <circle
                r={isHovered || isSelected ? "3.6" : isLarge ? "3" : "2.5"}
                fill={flow.color}
                opacity={opacity}
              >
                <animateMotion
                  path={flow.arc.path}
                  dur={`${flow.duration}s`}
                  repeatCount="indefinite"
                />
              </circle>

              {/* Secondary flowing particle with staggered phase */}
              <circle
                r={isHovered || isSelected ? "2.6" : isLarge ? "2.2" : "1.8"}
                fill={flow.color}
                opacity={opacity * 0.65}
              >
                <animateMotion
                  path={flow.arc.path}
                  dur={`${flow.duration}s`}
                  begin={`${flow.duration * 0.48}s`}
                  repeatCount="indefinite"
                />
              </circle>
            </g>
          );
        })}
      </g>

      {/* Source and Destination Nodes */}
      <g className="map-nodes">
        {nodes.map((node, idx) => {
          const isDest = node.type === "destination";
          const radius = isLarge ? (isDest ? 5.5 : 4.5) : (isDest ? 4.5 : 3.5);

          return (
            <g
              key={`node-${node.x}-${node.y}-${idx}`}
              transform={`translate(${node.x}, ${node.y})`}
              className="map-node-item"
              pointerEvents="none"
            >
              {/* Subtle outer aura */}
              {!isDest && (
                <circle
                  r={radius * 1.8}
                  fill={node.color}
                  opacity="0.22"
                />
              )}

              {/* Pulsing ring for active threat sources */}
              {!isDest && (
                <circle
                  r={radius}
                  fill="none"
                  stroke={node.color}
                  strokeWidth="1.4"
                  className="map-node-pulse"
                />
              )}

              {/* Node base marker */}
              <circle
                r={radius}
                fill={isDest ? "var(--surface)" : node.color}
                stroke={isDest ? "var(--ink)" : "var(--surface)"}
                strokeWidth={isDest ? "2.2" : "1.2"}
              />

              {/* Destination center point */}
              {isDest && (
                <circle r={radius * 0.45} fill="var(--ink)" />
              )}

              {/* Node label in expanded mode */}
              {isLarge && (
                <text
                  x={node.lon > 80 ? -10 : 10}
                  y={node.lat < 0 ? 14 : -9}
                  textAnchor={node.lon > 80 ? "end" : "start"}
                  fontSize="10"
                  fontFamily="var(--mono)"
                  fontWeight="600"
                  fill="var(--ink)"
                  style={{ textShadow: "0 1px 3px var(--surface)" }}
                >
                  {node.name}
                </text>
              )}
            </g>
          );
        })}
      </g>
    </svg>
  );

  return (
    <section className={`panel attack-map-card ${isExpanded ? "is-expanded" : ""}`} ref={containerRef}>
      {/* Header */}
      <header className={`attack-map-header ${isExpanded ? "attack-map-modal-head" : ""}`}>
        <div className="attack-map-title-wrap">
          <div className="attack-map-title-row">
            <Globe size={isExpanded ? 18 : 16} strokeWidth={2.1} className="text-ink" />
            <h2 className="attack-map-title">
              {isExpanded ? "Global Attack Map — Focused Telemetry View" : "Global Attack Map"}
            </h2>
            {isExpanded && (
              <span className="attack-map-badge">
                {filteredFlows.length} Active Flow Trajectories
              </span>
            )}
          </div>
          <p className="attack-map-hint">
            {isExpanded
              ? "Detailed inspection of detected attack pathways crossing from global external networks into the protected sensor enclave."
              : "Observed threat vector paths: Geographic Origin → ShieldX Protected Enclave"}
          </p>
        </div>

        <div className="attack-map-actions" style={isExpanded ? { gap: 12 } : {}}>
          {/* Combined Detector Category Filters: All | DDoS | C2 | DGA/DNS */}
          <div className="attack-map-filters" role="tablist" aria-label="Detector category filter">
            {FILTER_OPTIONS.map((cat) => (
              <button
                key={cat}
                type="button"
                role="tab"
                aria-selected={activeFilter === cat}
                className={`attack-map-filter-btn ${activeFilter === cat ? "active" : ""}`}
                onClick={(e) => {
                  e.stopPropagation();
                  setActiveFilter(cat);
                }}
              >
                {cat}
              </button>
            ))}
          </div>

          {isExpanded ? (
            <button
              type="button"
              className="attack-map-close-btn"
              onClick={() => setIsExpanded(false)}
              title="Collapse view (Esc)"
            >
              <Minimize2 size={13} strokeWidth={2.2} />
              <span>Collapse view (Esc)</span>
            </button>
          ) : (
            <button
              type="button"
              className="attack-map-expand-btn"
              onClick={() => setIsExpanded(true)}
              title="Expand into focused telemetry view"
            >
              <Maximize2 size={13} strokeWidth={2.1} />
              <span>Expand</span>
            </button>
          )}
        </div>
      </header>

      {/* Map Canvas Wrap */}
      <div
        className="attack-map-canvas-wrap"
        onClick={() => !isExpanded && setIsExpanded(true)}
        onMouseMove={handleMouseMove}
        title={!isExpanded ? "Click to expand global attack map" : undefined}
      >
        {renderMapSvg(isExpanded)}

        {/* Interactive Hover Tooltip */}
        {hoveredFlow && (
          <div
            className="attack-map-tooltip"
            style={{
              left: `${mousePos.x}px`,
              top: `${mousePos.y}px`,
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
              <ThreatTag threat_class={hoveredFlow.threat} size="sm" />
              <span className="mono" style={{ fontSize: 10, color: "var(--ink-3)" }}>
                {hoveredFlow.confidence ? `${Math.round(hoveredFlow.confidence * 100)}% conf` : ""}
              </span>
            </div>
            <div style={{ fontSize: 11, marginBottom: 2 }}>
              <span style={{ color: "var(--ink-3)" }}>From: </span>
              <span className="mono" style={{ fontWeight: 600 }}>{hoveredFlow.srcIp}</span>
              <span style={{ color: "var(--ink-2)" }}> ({hoveredFlow.srcGeo.name})</span>
            </div>
            <div style={{ fontSize: 11 }}>
              <span style={{ color: "var(--ink-3)" }}>To: </span>
              <span className="mono" style={{ fontWeight: 600 }}>{hoveredFlow.dstIp}</span>
              <span style={{ color: "var(--ink-2)" }}> ({hoveredFlow.dstGeo.name})</span>
            </div>
          </div>
        )}

        {/* Click to expand prompt */}
        {!isExpanded && (
          <span className="attack-map-click-overlay">
            <Maximize2 size={11} strokeWidth={2} /> Click map to expand view
          </span>
        )}
      </div>

      {/* Footer: Legend & Summary Info */}
      <footer className="attack-map-footer">
        <div className="attack-map-legend">
          <span className="attack-map-legend-item">
            <span className="attack-map-legend-dot" style={{ background: THREAT_COLORS.DDOS }} />
            DDoS
          </span>
          <span className="attack-map-legend-item">
            <span className="attack-map-legend-dot" style={{ background: THREAT_COLORS.C2 }} />
            C2
          </span>
          <span className="attack-map-legend-item">
            <span className="attack-map-legend-dot" style={{ background: THREAT_COLORS.DGA }} />
            DGA
          </span>
          <span className="attack-map-legend-item">
            <span className="attack-map-legend-dot" style={{ background: THREAT_COLORS["DNS Tunnel"] }} />
            DNS Tunnel
          </span>
          <span className="attack-map-legend-item" style={{ borderLeft: "1px solid var(--line)", paddingLeft: 8 }}>
            <span className="attack-map-legend-dot" style={{ background: "transparent", border: "1.5px solid var(--ink)" }} />
            Protected Enclave
          </span>
        </div>

        <div className="attack-map-summary-meta">
          <span>
            <b>Observed Flows:</b> {filteredFlows.length}
          </span>
          <span>
            <b>Top Origin:</b> {topOrigin}
          </span>
          <span title="IP Geolocation resolved via Enclave passive subnet telemetry">
            <b>GeoIP:</b> Subnet-Assisted
          </span>
        </div>
      </footer>
    </section>
  );
}
