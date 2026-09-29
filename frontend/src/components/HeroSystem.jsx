import { useEffect, useState } from "react";

/*
 * Premium hero scene: packets stream in from the network, cross a one-way
 * glass diode, pass through a rotating detection lens with four detector
 * orbits, and a live verdict card cycles through what the lens just caught.
 * Pure SVG + CSS; all motion is disabled under prefers-reduced-motion.
 */

/*
 * Illustrative verdicts — one per detector, showing the feature each one
 * actually reads. These are examples of a verdict's shape, not readings from a
 * running system, and the panel is labelled as such: nothing here is live, so
 * nothing here claims to be.
 */
const VERDICTS = [
  { k: "DDoS", tone: "var(--series-1)", title: "Volumetric flood", ev: "pps · syn_ratio", score: 0.96 },
  { k: "C2", tone: "var(--series-2)", title: "Periodic beacon", ev: "periodicity_score · iat_cv", score: 0.91 },
  { k: "DGA", tone: "var(--series-3)", title: "Algorithmic domain", ev: "avg_shannon_entropy · nxdomain_ratio", score: 0.87 },
  { k: "DNS", tone: "var(--series-3)", title: "DNS tunnel", ev: "query_length · subdomain_entropy", score: 0.78 },
];

const LANES = [70, 110, 150, 190, 230];
const CYCLE_MS = 4200;

export function HeroSystem() {
  const [i, setI] = useState(0);

  useEffect(() => {
    /* Held still for readers who asked for less motion. */
    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) return;
    const t = setInterval(() => setI((v) => (v + 1) % VERDICTS.length), CYCLE_MS);
    return () => clearInterval(t);
  }, []);

  const v = VERDICTS[i];

  return (
    <figure className="hx">
      <div className="hx__head">
        <span className="hx__live">
          <i /> Detection example
        </span>
        <span className="mono hx__meta">receive-only</span>
      </div>

      <svg viewBox="0 0 480 300" className="hx__svg" role="img" aria-label="Traffic crosses a one-way boundary into the ShieldX detection lens">
        <defs>
          <radialGradient id="hxLens" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stopColor="var(--ink)" stopOpacity="0.10" />
            <stop offset="70%" stopColor="var(--ink)" stopOpacity="0.03" />
            <stop offset="100%" stopColor="var(--ink)" stopOpacity="0" />
          </radialGradient>
          <linearGradient id="hxFade" x1="0" x2="1">
            <stop offset="0%" stopColor="var(--ink)" stopOpacity="0" />
            <stop offset="100%" stopColor="var(--ink)" stopOpacity="0.35" />
          </linearGradient>
        </defs>

        {/* incoming lanes */}
        {LANES.map((y, n) => (
          <g key={y}>
            <path d={`M10 ${y} C 120 ${y}, 150 150, 250 150`} className="hx__lane" stroke="url(#hxFade)" />
            {[0, 1].map((d) => (
              <circle
                key={d}
                r="2.4"
                className="hx__pkt"
                style={{
                  offsetPath: `path("M10 ${y} C 120 ${y}, 150 150, 250 150")`,
                  /* Each lane runs at its own pace. Identical timing across
                   * five lanes read as a mechanism; a little variance reads as
                   * traffic. */
                  animationDuration: `${5.2 + n * 0.55 + d * 0.3}s`,
                  animationDelay: `${n * 640 + d * 2100}ms`,
                }}
              />
            ))}
          </g>
        ))}

        {/* one-way diode */}
        <g className="hx__diode">
          <rect x="164" y="40" width="14" height="220" rx="7" className="hx__wall" />
          {[80, 150, 220].map((y) => (
            <path key={y} d={`M167 ${y - 5} L175 ${y} L167 ${y + 5}`} className="hx__chev" />
          ))}
          <text x="171" y="30" textAnchor="middle" className="hx__lbl">one-way</text>
          <text x="171" y="280" textAnchor="middle" className="hx__lbl hx__lbl--dim">no return path</text>
        </g>

        {/* lens */}
        <g transform="translate(330 150)">
          <circle r="104" fill="url(#hxLens)" />
          <circle r="92" className="hx__ring" />
          <circle r="70" className="hx__ring hx__ring--dash hx__spin" />
          <circle r="48" className="hx__ring" />
          <g className="hx__sweep">
            <path d="M0 0 L0 -92 A92 92 0 0 1 65 -65 Z" className="hx__cone" />
          </g>
          {VERDICTS.map((d, n) => (
            <g key={d.k} className="hx__orbit" style={{ animationDelay: `${-n * 4}s` }}>
              <g transform="translate(0 -70)">
                <circle r={n === i ? 7 : 4.5} fill={d.tone} className={n === i ? "hx__dot is-on" : "hx__dot"} />
              </g>
            </g>
          ))}
          <text y="-4" textAnchor="middle" className="hx__core">ShieldX</text>
          <text y="12" textAnchor="middle" className="hx__lbl hx__lbl--dim">4 detectors</text>
        </g>
      </svg>

      <div className="hx__verdict" key={i} style={{ "--tone": v.tone }}>
        <span className="hx__vk">{v.k}</span>
        <div className="hx__vbody">
          <strong>{v.title}</strong>
          <span className="mono">{v.ev}</span>
        </div>
        <div className="hx__score">
          <span className="mono">{v.score.toFixed(2)}</span>
          <i><b style={{ width: `${v.score * 100}%` }} /></i>
        </div>
      </div>

      <figcaption className="hx__cap">
        Observe <span>→</span> Detect <span>→</span> Evidence <span>→</span> Alert
      </figcaption>
    </figure>
  );
}
