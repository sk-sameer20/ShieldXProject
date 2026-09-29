import { AlertTriangle, CheckCircle2, Info, OctagonAlert } from "lucide-react";
import { severityMeta, threatMeta } from "@/data/telemetry";

export function SectionHead({ eyebrow, title, hint, children }) {
  return (
    <header className="sec-head">
      <div className="sec-head__text">
        {eyebrow && <span className="eyebrow">{eyebrow}</span>}
        <h1 className="sec-head__title">{title}</h1>
        {hint && <p className="lede sec-head__hint">{hint}</p>}
      </div>
      {children && <div className="sec-head__aside">{children}</div>}
    </header>
  );
}

export function Panel({ title, meta, hint, children, footer, className = "", ...rest }) {
  return (
    <section className={`panel ${className}`} {...rest}>
      {(title || meta) && (
        <div className="panel__head">
          <div>
            {title && <h2 className="panel__title">{title}</h2>}
            {hint && <p className="hint panel__hint">{hint}</p>}
          </div>
          {meta && <span className="panel__meta tnum">{meta}</span>}
        </div>
      )}
      <div className="panel__body">{children}</div>
      {footer && <div className="panel__foot">{footer}</div>}
    </section>
  );
}

/* Status always ships icon + label — colour never carries the meaning alone. */
const severityIcon = {
  critical: OctagonAlert,
  high: AlertTriangle,
  medium: Info,
  low: CheckCircle2,
};

export function SeverityTag({ severity }) {
  const meta = severityMeta[severity];
  const Icon = severityIcon[severity];
  return (
    <span className="sev" style={{ "--sev": meta.color }}>
      <Icon size={13} strokeWidth={2.2} aria-hidden />
      <span>{meta.label}</span>
    </span>
  );
}

export function ThreatTag({ threat_class, size = "md" }) {
  const tcUpper = String(threat_class || "").toUpperCase();
  const normKey =
    tcUpper === "DDOS" ? "DDoS" :
    (tcUpper === "C2" || tcUpper === "C2_BEACONING") ? "C2" :
    (tcUpper.includes("TUNNEL") || (tcUpper.includes("DNS") && !tcUpper.includes("DGA"))) ? "DNS-Tunnel" :
    tcUpper.includes("DGA") ? "DGA" :
    threat_class;

  const meta = threatMeta[normKey] || threatMeta[threat_class] || {
    short: normKey || threat_class || "Threat",
    label: normKey || threat_class || "Threat",
    series: "var(--series-3)",
  };

  return (
    <span className={`tt ${size === "sm" ? "tt--sm" : ""}`}>
      <i className="tt__dot" style={{ background: meta.series || "var(--series-3)" }} aria-hidden />
      {meta.short || normKey || threat_class}
    </span>
  );
}

/* Track is a lighter wash of the fill's own hue, so state reads across the bar. */
export function Meter({ value, tone = "var(--series-1)", label }) {
  const pct = Math.max(0, Math.min(100, value));
  return (
    <div className="meter" role="img" aria-label={label ?? `${pct} percent`}>
      <span
        className="meter__fill"
        style={{ width: `${pct}%`, background: tone }}
      />
    </div>
  );
}

/* A bare number is a comparison bound and gets labelled as one; a bound that is
 * already phrased (a minimum observation count, say) is shown as written. */
const boundLabel = (bound) => (/^[\d.]+$/.test(bound) ? `threshold ${bound}` : bound);

/*
 * Detector evidence: the feature, its value, and what that value means in
 * words. The third column is the point — a reader should not have to decode
 * `iat_cv = 0.03` to know it says the timing barely varies.
 */
export function EvidenceTable({ rows }) {
  return (
    <div className="evt">
      <div className="evt__head">
        <span>Feature</span>
        <span>Value</span>
        <span>What it means</span>
      </div>
      {rows.map((row) => (
        <div key={row.k} className={`evt__row ${row.flag ? "evt__row--flag" : ""}`}>
          <span className="evt__k mono">{row.k}</span>
          <span className="evt__v">
            <span className="evt__num tnum">{row.v}</span>
            {row.threshold && <span className="evt__th tnum">{boundLabel(row.threshold)}</span>}
          </span>
          <span className="evt__m">{row.means}</span>
        </div>
      ))}
    </div>
  );
}

export function KeyValue({ label, children, wide = false }) {
  return (
    <div className={`kv ${wide ? "kv--wide" : ""}`}>
      <dt className="kv__k">{label}</dt>
      <dd className="kv__v">{children}</dd>
    </div>
  );
}

export function Stat({ label, value, unit, note, accent, children }) {
  return (
    <div className="stat">
      <span className="stat__label">{label}</span>
      <div className="stat__value" style={accent ? { color: accent } : undefined}>
        {value}
        {unit && <span className="stat__unit">{unit}</span>}
      </div>
      {note && <p className="stat__note">{note}</p>}
      {children}
    </div>
  );
}

export function Dot({ tone = "var(--ok)", live = false }) {
  return <i className={`dot ${live ? "live" : ""}`} style={{ background: tone }} aria-hidden />;
}
