import { useEffect, useState } from "react";
import { Activity, ArrowRight, Award, Boxes, CheckCircle2, Cpu, Database, Eye, FileSearch, Gauge, Globe, Server, Shield, Zap } from "lucide-react";
import { GlassAnchor, GlassLink } from "@/components/Glass";
import { HeroSystem } from "@/components/HeroSystem";
import { Mark } from "@/components/Mark";
import { ThemeToggle } from "@/components/Shell";
import { THREAT_ORDER, datasets, pipeline, threatMeta } from "@/data/telemetry";

/* Verified Live Red-Team Hardware & Detection Benchmarks */
const heroFacts = [
  { value: "0.0%", label: "False Positive Rate" },
  { value: "1.70 Gbps", label: "Peak Wire Throughput" },
  { value: "11 / 11", label: "Red-Team Scenarios Passed" },
  { value: "100%", label: "In-RAM (0B Disk Wear)" },
];

/* Structured live benchmarks directly from BENCHMARK_REPORT.md */
const benchmarkHighlights = [
  {
    category: "Zero False Positives",
    metric: "0.0%",
    unit: "FP Rate",
    icon: Shield,
    badge: "PASS · CLEAN",
    badgeColor: "var(--success, #10b981)",
    desc: "Legitimate browsing, ICMP echoes, and TCP handshakes scored 12% confidence (safe watermark: <75%), guaranteeing zero operational alarm fatigue.",
  },
  {
    category: "Temporal Micro-Precision",
    metric: "±6 ms",
    unit: "Jitter Sensitivity",
    icon: Zap,
    badge: "97.2% CONFIDENCE",
    badgeColor: "var(--series-2, #f97316)",
    desc: "Unmasked APT C2 beaconing down to 1.2% timing distortion (CV = 0.012) via fast-Fourier transform (FFT) and inter-arrival time (IAT) analysis.",
  },
  {
    category: "Physical Wire Saturation",
    metric: "1.70 Gbps",
    unit: "Peak Line Rate",
    icon: Cpu,
    badge: "146.2k PPS",
    badgeColor: "var(--series-1, #ef4444)",
    desc: "Absorbed line-rate volumetric floods (16.0 GB genuine flow across 11.8M frames) forcing 100% ring-buffer saturation with zero server crashes.",
  },
  {
    category: "Algorithmic DGA Defense",
    metric: "3.78",
    unit: "Bits Shannon Entropy",
    icon: Server,
    badge: "94.2% MITIGATED",
    badgeColor: "var(--series-3, #8b5cf6)",
    desc: "Instant isolation of pseudo-random algorithm domains (e.g. qz8m2kxpvn.net with 0% vowel ratio) via N-gram transition anomaly scoring.",
  },
];

const principles = [
  {
    icon: Eye,
    title: "Nothing inline to break",
    body: "ShieldX reads a mirror of the traffic. There is no appliance in the path, so a failure here can never become an outage.",
  },
  {
    icon: Gauge,
    title: "Behaviour, not signatures",
    body: "Rates, timing and entropy carry the signal. Encrypted channels are classified from shape alone — no decryption, no agent on the host.",
  },
  {
    icon: FileSearch,
    title: "Every verdict shows its work",
    body: "Each alert ships with the exact feature values that produced it, and the threshold each one crossed.",
  },
];

/* A quiet category mark per dataset — capture, corpus, ranking. Falls back so
 * an added dataset still renders. */
const DATASET_ICON = {
  "CTU-13": Activity,
  "DGA archive": Boxes,
  "Tranco top 1M": Globe,
};

/* Illustrative domains, not observations — they rotate to show the shape a
 * generated name takes versus a tunnelled query. */
const DGA_SAMPLES = ["xq7vk2mpl9wz.biz", "kdn3wq8trbue.net", "p2mhxv6zqlca.top"];
const DNS_SAMPLES = ["aGVsbG8.d2F0.t.evil.io", "cGF5bG9h.ZGVk.t.evil.io", "c2VjcmV0.Zm8.t.evil.io"];

function useReveal() {
  useEffect(() => {
    const nodes = document.querySelectorAll("[data-reveal], [data-reveal-head]");
    if (!("IntersectionObserver" in window)) {
      nodes.forEach((n) => n.classList.add("is-in"));
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          entry.target.classList.add("is-in");
          io.unobserve(entry.target);
        });
      },
      { threshold: 0, rootMargin: "0px 0px -60px 0px" },
    );
    nodes.forEach((n) => io.observe(n));
    return () => io.disconnect();
  }, []);
}

/* Rotates a list slowly, and holds still under reduced motion. */
function useRotating(list, ms) {
  const [i, setI] = useState(0);
  useEffect(() => {
    if (window.matchMedia?.("(prefers-reduced-motion: reduce)").matches) return;
    const t = setInterval(() => setI((v) => (v + 1) % list.length), ms);
    return () => clearInterval(t);
  }, [list.length, ms]);
  return list[i];
}

/* Tiny animated fingerprint of each threat's behaviour. */
function Signature({ k, tone }) {
  const dga = useRotating(DGA_SAMPLES, 5200);
  const dns = useRotating(DNS_SAMPLES, 6100);

  if (k === "DDoS") {
    const bars = Array.from({ length: 24 }, (_, i) => i);
    return (
      <svg viewBox="0 0 120 36" className="sig" aria-hidden>
        {bars.map((i) => {
          const h = i > 12 ? 30 - (i % 3) * 3 : 4 + (i % 4) * 2;
          return (
            <rect
              key={i}
              x={i * 5}
              y={36 - h}
              width="3"
              height={h}
              rx="1"
              fill={tone}
              className="sig__bar"
              style={{ animationDelay: `${i * 90}ms` }}
            />
          );
        })}
      </svg>
    );
  }

  if (k === "C2") {
    return (
      <svg viewBox="0 0 120 36" className="sig" aria-hidden>
        <line x1="0" y1="30" x2="120" y2="30" className="sig__base" />
        {[8, 38, 68, 98].map((x, i) => (
          <rect
            key={x}
            x={x}
            y="8"
            width="4"
            height="22"
            rx="2"
            fill={tone}
            className="sig__beat"
            style={{ animationDelay: `${i * 620}ms` }}
          />
        ))}
      </svg>
    );
  }

  return (
    <div className="sig sig--txt mono" style={{ color: tone }} aria-hidden>
      <span key={k === "DGA" ? dga : dns} className="sig__type">
        {k === "DGA" ? dga : dns}
      </span>
    </div>
  );
}

function SectionTitle({ eyebrow, title, lead }) {
  return (
    <div className="lp__shead" data-reveal>
      <span className="eyebrow">{eyebrow}</span>
      <h2 className="lp__h2">{title}</h2>
      {lead && <p className="lp__chaplead">{lead}</p>}
    </div>
  );
}

export function Landing() {
  useReveal();

  return (
    <div className="lp">
      <div className="lp__ambient" aria-hidden />
      <div className="lp__gridbg" aria-hidden />

      <header className="lp__bar">
        <div className="wrap lp__barin">
          <span className="lp__brand">
            <Mark size={22} />
            <strong>ShieldX</strong>
          </span>
          <nav className="lp__navlinks">
            <a href="#benchmarks">Live Benchmarks</a>
            <a href="#detects">What it detects</a>
            <a href="#how">How it works</a>
            <a href="#evidence">Evidence</a>
            <a href="#data">Data</a>
          </nav>
          <div className="lp__baraside">
            <ThemeToggle size="sm" />
            <GlassLink to="/console" variant="ink" size="sm">
              Open console
              <ArrowRight size={14} />
            </GlassLink>
          </div>
        </div>
      </header>

      <section className="wrap lp__hero">
        <div className="lp__herotext rise">
          <span className="lp__badge">
            <Eye size={13} strokeWidth={2.1} aria-hidden />
            Passive · Receive-only · No return path
          </span>

          <h1 className="lp__h1">
            Find the attack in traffic you can only <span className="lp__h1em">watch</span>.
          </h1>

          <p className="lp__lede">
            Some networks can only be observed — a one-way mirror, no return path, no agent on the host. ShieldX takes
            that stream and finds threats hidden in traffic behaviour.
          </p>

          <div className="lp__cta">
            <GlassLink to="/console" variant="ink" size="lg">
              Open the console
              <ArrowRight size={16} />
            </GlassLink>
            <GlassAnchor href="#how" size="lg">
              See how detection works
            </GlassAnchor>
          </div>

          <dl className="lp__facts">
            {heroFacts.map((f) => (
              <div key={f.label} className="lp__fact">
                <dd>{f.value}</dd>
                <dt>{f.label}</dt>
              </div>
            ))}
          </dl>
        </div>

        <div className="lp__herovis rise">
          <HeroSystem />
        </div>
      </section>

      {/* --- Dedicated Red-Team Master Benchmarks Section --- */}
      <section className="wrap lp__section" id="benchmarks">
        <SectionTitle
          eyebrow="Hardware & Detection Benchmarks"
          title="Verified on hardware. Tested to the limit."
          lead="Direct observations from 11 isolated red-team evaluation phases on our physical and virtual testbed — from microsecond APT beaconing to 16.0 GB multi-gigabit wire floods."
        />

        <div className="bm__grid" data-reveal>
          {benchmarkHighlights.map((b) => (
            <article key={b.category} className="bm__card">
              <div className="bm__top">
                <span className="bm__icon">
                  <b.icon size={18} strokeWidth={2} aria-hidden />
                </span>
                <span className="bm__badge" style={{ color: b.badgeColor, borderColor: b.badgeColor }}>
                  {b.badge}
                </span>
              </div>
              <div className="bm__metricbox">
                <span className="bm__num">{b.metric}</span>
                <span className="bm__unit">{b.unit}</span>
              </div>
              <h3 className="bm__title">{b.category}</h3>
              <p className="bm__desc">{b.desc}</p>
            </article>
          ))}
        </div>

        {/* Live Matrix Summary Strip */}
        <div className="bm__strip" data-reveal>
          <div className="bm__stripitem">
            <span className="bm__striplabel">Total Evaluated Traffic</span>
            <strong className="bm__stripval">35.0+ GB In-RAM</strong>
          </div>
          <div className="bm__stripitem">
            <span className="bm__striplabel">Physical SSD Wear</span>
            <strong className="bm__stripval" style={{ color: "var(--success, #10b981)" }}>0 Bytes (100% RAM)</strong>
          </div>
          <div className="bm__stripitem">
            <span className="bm__striplabel">Max Packet Frequency</span>
            <strong className="bm__stripval">146,200 PPS Peak</strong>
          </div>
          <div className="bm__stripitem">
            <span className="bm__striplabel">Enclave Ingestion Latency</span>
            <strong className="bm__stripval">&lt; 20 ms Roundtrip</strong>
          </div>
        </div>

        <div className="lp__more" data-reveal-head style={{ marginTop: "32px" }}>
          <GlassLink to="/console/incidents" size="lg">
            Inspect all 11 benchmark detections in console
            <ArrowRight size={16} />
          </GlassLink>
          <span className="lp__morenote">
            Full telemetry evidence, feature vectors, and MITRE ATT&CK attributions for each test.
          </span>
        </div>
      </section>

      <section className="wrap lp__section" id="why">
        <SectionTitle
          eyebrow="Why ShieldX"
          title="Three commitments, before any detection happens."
          lead="What the platform will and will not do is fixed by its architecture, not by configuration."
        />
        <div className="lp__three" data-reveal>
          {principles.map((p) => (
            <article key={p.title} className="lp__pillar">
              <span className="lp__pillaricon">
                <p.icon size={17} strokeWidth={1.9} aria-hidden />
              </span>
              <h3>{p.title}</h3>
              <p>{p.body}</p>
            </article>
          ))}
        </div>
      </section>

      <section className="wrap lp__section" id="detects">
        <SectionTitle
          eyebrow="What it detects"
          title="Four detectors, one passive stream."
          lead="Every attack leaves a shape in traffic — even when you can only watch. These are the four shapes ShieldX is trained to see."
        />
        <div className="lp__four" data-reveal>
          {THREAT_ORDER.map((k) => (
            <article key={k} className="lp__threat">
              <span className="lp__threattop">
                <i style={{ background: threatMeta[k].series }} aria-hidden />
                <span className="lp__threatshort">{threatMeta[k].short}</span>
                <span className="mono lp__threatwin">{threatMeta[k].window}</span>
              </span>
              <Signature k={k} tone={threatMeta[k].series} />
              <h3 className="lp__threatname">{threatMeta[k].label}</h3>
              <p className="lp__threatbody">{threatMeta[k].blurb}</p>
            </article>
          ))}
        </div>

        {/* The full feature lists, thresholds and training details live in the
            console rather than on the landing page. */}
        <div className="lp__more" data-reveal-head>
          <GlassLink to="/console/detectors" size="lg">
            Explore detection architecture
            <ArrowRight size={16} />
          </GlassLink>
          <span className="lp__morenote">
            Features, configured thresholds and scoring windows for each engine.
          </span>
        </div>
      </section>

      <section className="wrap lp__section" id="how">
        <SectionTitle
          eyebrow="How it works"
          title="From mirrored packet to explained alert."
          lead="A packet crosses the one-way boundary and never goes back. Here is everything that happens to it next."
        />
        <ol className="lp__pipe" data-reveal>
          {pipeline.map((p, i) => (
            <li key={p.id} className="lp__pstep">
              <span className="lp__pmark" aria-hidden>
                <i />
              </span>
              <div className="lp__pbody">
                <h3 className="lp__plabel">{p.label}</h3>
                <p className="lp__pdetail">{p.detail}</p>
              </div>
              {i < pipeline.length - 1 && <span className="lp__pflow" aria-hidden />}
            </li>
          ))}
        </ol>
      </section>

      <section className="wrap lp__section" id="evidence">
        <SectionTitle
          eyebrow="Evidence"
          title="Every verdict shows its work."
          lead="A score on its own is not an answer. Each alert keeps the feature values that produced it, and the configured line each one crossed — so a verdict can always be traced back to a number."
        />
        <div className="lp__ev" data-reveal>
          <div className="lp__evrow">
            <span className="mono lp__evk">periodicity_score</span>
            <span className="lp__evv tnum">0.94</span>
            <span className="lp__evm">Connections repeat at a highly regular interval</span>
          </div>
          <div className="lp__evrow">
            <span className="mono lp__evk">iat_cv</span>
            <span className="lp__evv tnum">0.03</span>
            <span className="lp__evm">Very low variation in that timing</span>
          </div>
          <div className="lp__evrow">
            <span className="mono lp__evk">dominant_destination_ratio</span>
            <span className="lp__evv tnum">0.98</span>
            <span className="lp__evm">Nearly all connections target one destination</span>
          </div>
          <div className="lp__evfoot">
            <GlassLink to="/console/incidents" size="lg">
              Inspect an incident
              <ArrowRight size={16} />
            </GlassLink>
            <span className="lp__morenote">Confidence ranks how strongly signals agreed — not a calibrated probability.</span>
          </div>
        </div>
      </section>

      <section className="wrap lp__section" id="data">
        <SectionTitle eyebrow="Data" title="Built on public, citable datasets." />
        <ul className="lp__data" data-reveal>
          {datasets.map((d) => {
            const Icon = DATASET_ICON[d.name] ?? Database;
            return (
              <li key={d.name} className="lp__datarow">
                <span className="lp__dataname">
                  <span className="lp__dataicon" aria-hidden>
                    <Icon size={14} strokeWidth={1.9} />
                  </span>
                  {d.name}
                </span>
                <span className="lp__datause">{d.use}</span>
                <span className="lp__datadetail">{d.detail}</span>
              </li>
            );
          })}
        </ul>
      </section>

      <section className="wrap">
        <div className="lp__final" data-reveal-head>
          <span className="lp__finaleyebrow">See ShieldX in action</span>
          <h2 className="lp__finalh">
            Observe the traffic.
            <br />
            Understand the signal.
            <br />
            Inspect the evidence.
          </h2>
          <GlassLink to="/console" variant="ink" size="lg" className="lp__finalcta">
            Enter console
            <ArrowRight size={16} />
          </GlassLink>
        </div>
      </section>

      <footer className="wrap lp__foot">
        <span className="lp__footbrand">
          <Mark size={17} />
          ShieldX
        </span>
        <span className="lp__foottags">DDoS · C2 beaconing · DGA/DNS</span>
      </footer>
    </div>
  );
}
