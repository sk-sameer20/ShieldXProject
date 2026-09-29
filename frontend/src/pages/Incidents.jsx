import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "@/lib/rr";
import { Check, ChevronDown, Lightbulb } from "lucide-react";
import { GlassButton } from "@/components/Glass";
import { EvidenceTable, KeyValue, Meter, Panel, SectionHead, SeverityTag, ThreatTag } from "@/components/ui";
import {
  THREAT_ORDER,
  confidenceBand,
  explainers,
  severityMeta,
  threatMeta,
} from "@/data/telemetry";
import { useAlerts } from "@/hooks/useShieldX";
import { formatLocalTimestamp, parseUtcDate } from "@/lib/time";

function JsonDisclosure({ record }) {
  const detailsRef = useRef(null);
  const wrapRef = useRef(null);
  const animRef = useRef(null);

  const onToggle = useCallback((event) => {
    const details = detailsRef.current;
    const wrap = wrapRef.current;
    if (!details || !wrap) return;

    event.preventDefault();

    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) {
      details.open = !details.open;
      return;
    }

    animRef.current?.cancel();
    const opening = !details.open;
    if (opening) details.open = true;

    const target = wrap.scrollHeight;
    const frames = [
      { height: "0px", opacity: 0 },
      { height: `${target}px`, opacity: 1 },
    ];

    const anim = wrap.animate(opening ? frames : [...frames].reverse(), {
      duration: opening ? 300 : 220,
      easing: opening ? "cubic-bezier(0.22, 1, 0.36, 1)" : "cubic-bezier(0.4, 0, 1, 1)",
      fill: "both",
    });
    animRef.current = anim;

    anim.onfinish = () => {
      if (!opening) details.open = false;
      anim.cancel();
      animRef.current = null;
    };
  }, []);

  return (
    <details className="json" ref={detailsRef}>
      <summary className="json__toggle" onClick={onToggle}>
        View JSON
      </summary>
      <div className="json__wrap" ref={wrapRef}>
        <pre className="json__body">
          <code>{JSON.stringify(record, null, 2)}</code>
        </pre>
      </div>
    </details>
  );
}

const FILTER_OPTIONS = [
  { value: "all", label: "All" },
  { value: "DDoS", label: "DDoS" },
  { value: "C2", label: "C2" },
  { value: "DGA", label: "DGA" },
  { value: "DNS", label: "DNS Tunnel" },
];

export function Incidents() {
  const [filter, setFilter] = useState("all");
  const [filterOpen, setFilterOpen] = useState(false);
  const filterRef = useRef(null);
  const [params] = useSearchParams();

  useEffect(() => {
    if (!filterOpen) return;
    const handleClickOutside = (e) => {
      if (filterRef.current && !filterRef.current.contains(e.target)) {
        setFilterOpen(false);
      }
    };
    const handleKeyDown = (e) => {
      if (e.key === "Escape") {
        setFilterOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handleClickOutside);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [filterOpen]);

  // Real backend alerts query
  const { data: alertsRes, isSuccess } = useAlerts({ page_size: 50 });

  // Map backend items or fallback when offline
  const alertsList = useMemo(() => {
    if (isSuccess && alertsRes?.items) {
      return alertsRes.items.map((a) => {
        const sev = String(a.severity || "low").toLowerCase();
        const conf = typeof a.confidence === "number" ? a.confidence : 0;
        const timeDisplay = formatLocalTimestamp(a.timestamp);

        // Extract evidence features matching EvidenceTable contract (k, v, means, threshold)
        let evidenceRows = [];
        if (Array.isArray(a.evidence)) {
          evidenceRows = a.evidence.map((e) => ({
            k: e.k || e.feature || "signal",
            v: e.v !== undefined ? e.v : (e.value !== undefined ? e.value : "—"),
            feature: e.feature || e.k || "signal",
            value: e.value !== undefined ? e.value : e.v,
            means: e.means || e.description || a.evidence?.why_flagged || a.whyFlagged || a.reason || "—",
            threshold: e.threshold ?? null,
            flag: Boolean(e.flag),
          }));
        } else if (a.evidence?.trigger_features && typeof a.evidence.trigger_features === "object") {
          evidenceRows = Object.entries(a.evidence.trigger_features).map(([k, v]) => ({
            k,
            v: typeof v === "object" ? JSON.stringify(v) : String(v),
            feature: k,
            value: v,
            means: a.evidence?.why_flagged || a.whyFlagged || a.reason || "Trigger feature metric",
            threshold: null,
          }));
        } else if (a.trigger_features && typeof a.trigger_features === "object") {
          evidenceRows = Object.entries(a.trigger_features).map(([k, v]) => ({
            k,
            v: typeof v === "object" ? JSON.stringify(v) : String(v),
            feature: k,
            value: v,
            means: a.whyFlagged || a.reason || "Trigger feature metric",
            threshold: null,
          }));
        }

        return {
          id: a.id || a.alert_id,
          raw: a,
          timestamp: a.timestamp,
          observed: timeDisplay,
          flow_id: a.alert_id || a.id,
          threat_class: a.threat_class || "ANOMALY",
          confidence: conf,
          severity: sev in severityMeta ? sev : "low",
          source_ip: a.source_ip || a.srcIp || "—",
          destination_ip: a.destination_ip || a.destIp || "—",
          window_start: a.window_start || timeDisplay,
          window_end: a.window_end || timeDisplay,
          model_version: a.model_version || a.detector_model || a.detectorModel || "v1.0.0",
          headline: a.attack_classification || a.classification || a.reason || a.headline || "Security Alert",
          whyFlagged: a.whyFlagged || a.reason || "Triggered detection threshold",
          mitre: a.mitre || a.mitre_technique || a.evidence?.mitre_technique_id || "—",
          evidence: evidenceRows,
          timeline: [
            { at: timeDisplay, text: a.whyFlagged || a.reason || "Incident detected and logged by sensor" },
          ],
        };
      });
    }
    return [];
  }, [isSuccess, alertsRes]);

  const [selectedId, setSelectedId] = useState(() => params.get("alert") || null);

  const matchesFilter = useCallback((threatClass, f) => {
    if (f === "all") return true;
    const tc = String(threatClass || "").toUpperCase();
    const filterKey = String(f || "").toUpperCase();
    if (tc === filterKey) return true;
    if (filterKey === "DDOS" && tc.includes("DDOS")) return true;
    if (filterKey === "C2" && tc.includes("C2")) return true;
    if (filterKey === "DGA") {
      return tc === "DGA" || (tc.includes("DGA") && !tc.includes("TUNNEL"));
    }
    if (filterKey === "DNS" || filterKey === "DNS_TUNNEL" || filterKey === "DNS-TUNNEL") {
      return tc.includes("DNS") || tc.includes("TUNNEL");
    }
    return false;
  }, []);

  const list = useMemo(() => {
    const rows = filter === "all" ? alertsList : alertsList.filter((a) => matchesFilter(a.threat_class, filter));
    return [...rows].sort((a, b) => {
      const tA = parseUtcDate(a.timestamp)?.getTime() ?? 0;
      const tB = parseUtcDate(b.timestamp)?.getTime() ?? 0;
      return (tB - tA) || ((b.confidence ?? 0) - (a.confidence ?? 0));
    });
  }, [filter, alertsList, matchesFilter]);

  const activeLabel = useMemo(() => {
    return FILTER_OPTIONS.find((opt) => opt.value === filter)?.label || "All";
  }, [filter]);

  const selected = (selectedId ? alertsList.find((a) => a.id === selectedId) : null) ?? list[0] ?? alertsList[0];

  return (
    <>
      <SectionHead
        eyebrow="Detections"
        title="Incidents"
        hint="Each alert carries the feature values that produced it. Pick one to see what the detector measured, why that crossed into an alert, and the record behind it."
      >
        <div ref={filterRef} style={{ position: "relative", display: "inline-block" }}>
          <GlassButton
            size="sm"
            onClick={() => setFilterOpen((prev) => !prev)}
            aria-haspopup="listbox"
            aria-expanded={filterOpen}
            aria-label={`Filter: ${activeLabel}`}
            style={{ gap: 6 }}
          >
            <span>Filter: {activeLabel}</span>
            <ChevronDown
              size={13}
              strokeWidth={2}
              style={{
                transition: "transform var(--t-fast) var(--ease-out)",
                transform: filterOpen ? "rotate(180deg)" : "rotate(0deg)",
                opacity: 0.7,
              }}
              aria-hidden
            />
          </GlassButton>

          {filterOpen && (
            <div
              role="listbox"
              aria-label="Filter incidents"
              style={{
                position: "absolute",
                right: 0,
                top: "calc(100% + 6px)",
                minWidth: 140,
                padding: 4,
                borderRadius: "var(--r-md, 11px)",
                background: "var(--surface)",
                border: "1px solid var(--line)",
                boxShadow: "var(--pop-shadow)",
                zIndex: 50,
                display: "flex",
                flexDirection: "column",
                gap: 2,
              }}
            >
              {FILTER_OPTIONS.map((opt) => {
                const isSelected = filter === opt.value;
                return (
                  <button
                    key={opt.value}
                    type="button"
                    role="option"
                    aria-selected={isSelected}
                    onClick={() => {
                      setFilter(opt.value);
                      setFilterOpen(false);
                    }}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      justifyContent: "space-between",
                      width: "100%",
                      height: 32,
                      padding: "0 10px",
                      border: 0,
                      borderRadius: "var(--r-sm, 8px)",
                      background: isSelected ? "var(--accent-wash)" : "transparent",
                      color: isSelected ? "var(--accent-ink, var(--accent))" : "var(--ink-2)",
                      fontWeight: isSelected ? 600 : 500,
                      fontSize: 12.5,
                      cursor: "pointer",
                      textAlign: "left",
                      transition: "color var(--t-fast) var(--ease-soft)",
                    }}
                    onMouseEnter={(e) => {
                      if (!isSelected) e.currentTarget.style.color = "var(--ink)";
                    }}
                    onMouseLeave={(e) => {
                      if (!isSelected) e.currentTarget.style.color = "var(--ink-2)";
                    }}
                  >
                    <span>{opt.label}</span>
                    {isSelected && (
                      <Check size={13} strokeWidth={2.5} style={{ color: "var(--accent)" }} aria-hidden />
                    )}
                  </button>
                );
              })}
            </div>
          )}
        </div>
      </SectionHead>

      <div className="inc">
        <div className="inc__list" data-stagger>
          {list.map((a) => {
            const tone = severityMeta[a.severity]?.color || "var(--accent)";
            return (
              <button
                key={a.id}
                type="button"
                onClick={() => setSelectedId(a.id)}
                className={`incrow ${selected && a.id === selected.id ? "incrow--on" : ""}`}
                aria-current={selected && a.id === selected.id}
              >
                <span className="incrow__bar" style={{ background: tone }} aria-hidden />
                <span className="incrow__body">
                  <span className="incrow__top">
                    <SeverityTag severity={a.severity} />
                    <span className="incrow__time mono tnum">{a.observed}</span>
                  </span>
                  <span className="incrow__head">{a.headline}</span>
                  <span className="incrow__meta">
                    <ThreatTag threat_class={a.threat_class} size="sm" />
                    <span className="mono">{a.source_ip}</span>
                  </span>
                </span>
              </button>
            );
          })}
          {list.length === 0 && (
            <p className="hint">
              {isSuccess
                ? "No alerts from this detector in the selected window."
                : "Offline · Unable to load incidents from enclave backend."}
            </p>
          )}
        </div>

        {selected && (
          <div className="inc__detail stack" style={{ gap: 16 }}>
            <Panel
              title={selected.headline}
              meta={`#${selected.id}`}
              hint={`${threatMeta[selected.threat_class]?.label || selected.threat_class} · window ${selected.window_start}–${selected.window_end}`}
            >
              <div className="verdict">
                <div className="verdict__cell">
                  <span className="verdict__label">Severity</span>
                  <SeverityTag severity={selected.severity} />
                </div>
                <div className="verdict__cell">
                  <span className="verdict__label">Confidence</span>
                  <span className="conf">
                    <span className="conf__num">{selected.confidence.toFixed(2)}</span>
                    <span className="conf__meter">
                      <Meter
                        value={selected.confidence * 100}
                        tone={severityMeta[selected.severity]?.color || "var(--accent)"}
                        label={`Confidence ${selected.confidence.toFixed(2)}`}
                      />
                    </span>
                    <span className="conf__band">{confidenceBand(selected.confidence)}</span>
                  </span>
                </div>
                <div className="verdict__cell">
                  <span className="verdict__label">Detector</span>
                  <ThreatTag threat_class={selected.threat_class} size="sm" />
                </div>
              </div>

              <p className="hint caveat">
                Confidence ranks how strongly the detector&apos;s signals agreed. It is not a calibrated probability.
              </p>

              <div className="why">
                <span className="why__icon">
                  <Lightbulb size={15} strokeWidth={2} aria-hidden />
                </span>
                <div>
                  <p className="why__head">Why this was flagged</p>
                  <p className="why__body">{selected.whyFlagged || explainers[selected.threat_class] || "Threshold criteria met"}</p>
                </div>
              </div>

              <dl className="facts">
                <KeyValue label="Source">
                  <span className="mono">{selected.source_ip}</span>
                </KeyValue>
                <KeyValue label="Destination">
                  <span className="mono">{selected.destination_ip}</span>
                </KeyValue>
                <KeyValue label="Flow ID" wide>
                  <span className="mono idval">{selected.flow_id}</span>
                </KeyValue>
                <KeyValue label="Window">
                  <span className="mono tnum">
                    {selected.window_start}–{selected.window_end}
                  </span>
                </KeyValue>
                <KeyValue label="Model">
                  <span className="mono">{selected.model_version}</span>
                </KeyValue>
                {selected.mitre && selected.mitre !== "—" && (
                  <KeyValue label="MITRE">
                    <span className="mono">{selected.mitre}</span>
                  </KeyValue>
                )}
              </dl>
            </Panel>

            <Panel
              title="Evidence"
              hint="The feature values this detector computed for the window. Values in red crossed a configured threshold."
              meta={`${selected.evidence.length} features`}
            >
              {selected.evidence.length > 0 ? (
                <EvidenceTable rows={selected.evidence} />
              ) : (
                <p className="hint" style={{ padding: "16px 0" }}>No discrete feature thresholds recorded for this incident.</p>
              )}
            </Panel>

            <div className="g2">
              <Panel title="How it unfolded" hint="Detector observations, in order.">
                <ol className="tl">
                  {selected.timeline.map((t, i) => (
                    <li key={`${t.at}-${i}`} className="tl__item">
                      <span className="tl__time mono tnum">{t.at}</span>
                      <span className="tl__text">{t.text}</span>
                    </li>
                  ))}
                </ol>
              </Panel>

              <Panel
                title="Structured alert"
                hint="The machine-readable record, in the shape the alert store holds it."
              >
                <JsonDisclosure key={selected.id} record={selected.raw || selected} />
              </Panel>
            </div>
          </div>
        )}
      </div>
    </>
  );
}
