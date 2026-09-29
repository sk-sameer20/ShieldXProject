import { useCallback, useEffect, useMemo, useRef, useState } from "react";

/*
 * Charts are hand-drawn SVG so the mark specs hold exactly:
 * 2px lines, 4px rounded data-ends square at the baseline, ~10% area wash,
 * hairline grid one step off the surface, >=8px markers with a 2px surface ring.
 * Every chart carries a hover layer; nothing is gated behind it.
 */

const niceCeil = (v) => {
  const pow = 10 ** Math.floor(Math.log10(v));
  const n = v / pow;
  const step = n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10;
  return step * pow;
};

/*
 * Monotone cubic interpolation over evenly-spaced samples (Fritsch–Butland
 * tangents, which reduce to a harmonic mean at unit spacing).
 *
 * Tangents are computed in VALUE space against the sample index, not in pixel
 * space. That matters: both axes map to pixels affinely, and Hermite
 * interpolation commutes with an affine transform, so the same tangents
 * describe the drawn curve AND let us read the curve's value at any fractional
 * index. The crosshair dot therefore always sits exactly on the line, and the
 * number in the tooltip is the height of the line under the pointer.
 */
function monotoneTangents(values) {
  const n = values.length;
  if (n < 2) return [0];

  const delta = [];
  for (let i = 0; i < n - 1; i++) delta[i] = values[i + 1] - values[i];

  const m = new Array(n);
  m[0] = delta[0];
  m[n - 1] = delta[n - 2];
  for (let i = 1; i < n - 1; i++) {
    const a = delta[i - 1];
    const b = delta[i];
    /* Opposite signs or a flat neighbour means this is a local extreme —
     * a zero tangent is what keeps the curve from overshooting it. */
    m[i] = a * b <= 0 ? 0 : (2 * a * b) / (a + b);
  }
  return m;
}

/* Value of the curve at a fractional sample index. */
function valueAt(values, m, f) {
  const n = values.length;
  if (n === 0) return 0;
  if (n === 1) return values[0];

  const clamped = Math.max(0, Math.min(n - 1, f));
  const i = Math.min(n - 2, Math.floor(clamped));
  const t = clamped - i;
  const t2 = t * t;
  const t3 = t2 * t;

  const h00 = 2 * t3 - 3 * t2 + 1;
  const h10 = t3 - 2 * t2 + t;
  const h01 = -2 * t3 + 3 * t2;
  const h11 = t3 - t2;

  return h00 * values[i] + h10 * m[i] + h01 * values[i + 1] + h11 * m[i + 1];
}

/* Linear value at a fractional index — used for the time axis, which is
 * evenly spaced across the plot and so interpolates straight. */
function lerpAt(arr, f) {
  const n = arr.length;
  if (n === 0) return 0;
  if (n === 1) return arr[0];
  const clamped = Math.max(0, Math.min(n - 1, f));
  const i = Math.min(n - 2, Math.floor(clamped));
  const t = clamped - i;
  return arr[i] + (arr[i + 1] - arr[i]) * t;
}

const CLOCK = /^(\d{1,2}):(\d{2})$/;

function parseClock(label) {
  const match = CLOCK.exec(String(label));
  if (!match) return null;
  const hours = Number(match[1]);
  const minutes = Number(match[2]);
  if (hours > 23 || minutes > 59) return null;
  return hours * 60 + minutes;
}

function formatClock(minutes) {
  const wrapped = ((Math.round(minutes) % 1440) + 1440) % 1440;
  return `${String(Math.floor(wrapped / 60)).padStart(2, "0")}:${String(wrapped % 60).padStart(2, "0")}`;
}

/*
 * Sample labels as minutes on a monotonically increasing line, unwrapped past
 * midnight — a 24h window runs 23:00 -> 01:00, and without unwrapping the
 * readout would count backwards across that boundary.
 *
 * Returns null when the labels are not clock times, in which case the caller
 * falls back to the nearest label rather than inventing a format.
 */
function unwrapClockLabels(labels) {
  if (!labels.length) return null;
  const first = parseClock(labels[0]);
  if (first == null) return null;

  const out = [first];
  for (let i = 1; i < labels.length; i++) {
    const raw = parseClock(labels[i]);
    if (raw == null) return null;
    let value = raw;
    while (value < out[i - 1]) value += 1440;
    out.push(value);
  }
  return out;
}

function resampleTo(values, n) {
  if (n <= 0) return [];
  if (n === 1) return new Array(1).fill(values[values.length - 1] ?? values[0] ?? 0);
  if (values.length === n) return values;
  if (values.length === 0) return new Array(n).fill(0);
  if (values.length === 1) return new Array(n).fill(values[0]);
  const out = [];
  for (let i = 0; i < n; i++) {
    const f = (i / (n - 1)) * (values.length - 1);
    const lo = Math.floor(f);
    const hi = Math.min(values.length - 1, lo + 1);
    out.push(values[lo] + (values[hi] - values[lo]) * (f - lo));
  }
  return out;
}

/*
 * Eases the drawn line from the previous series to the next one.
 *
 * This is the mechanism that makes both cases smooth with no extra code: a
 * range change swaps the whole window, and an appended observation shifts it by
 * one sample. Either way the series prop changes and the line morphs, so a
 * backend feeding samples in needs no change here.
 */
function useSeriesTween(target) {
  const reduced =
    typeof window !== "undefined" &&
    window.matchMedia?.("(prefers-reduced-motion: reduce)").matches === true;

  const [shown, setShown] = useState(target);
  const fromRef = useRef(target);
  const rafRef = useRef(0);

  useEffect(() => {
    if (reduced || fromRef.current === target || target.length <= 1) {
      fromRef.current = target;
      setShown(target);
      return;
    }

    const from = resampleTo(fromRef.current, target.length);
    const start = performance.now();
    const duration = 420;
    /* Ease-out cubic: quick to commit, gentle to settle. */
    const ease = (t) => 1 - (1 - t) ** 3;

    const step = (now) => {
      const p = Math.min(1, (now - start) / duration);
      const e = ease(p);
      setShown(target.map((v, i) => {
        const base = from[i] ?? v;
        return isNaN(base) ? v : base + (v - base) * e;
      }));
      if (p < 1) {
        rafRef.current = requestAnimationFrame(step);
      } else {
        fromRef.current = target;
      }
    };

    rafRef.current = requestAnimationFrame(step);
    return () => cancelAnimationFrame(rafRef.current);
  }, [target, reduced]);

  return shown.length === target.length ? shown : target;
}

/* ---------------------------------------------------------------- Trend */

export function Trend({
  data,
  xKey = "t",
  yKey = "gbps",
  unit = "",
  height = 236,
  label = "Observed traffic",
  /* Streaming presentation: marks the leading sample and labels it instead of
   * the peak. Left off while the page runs on a fixed demo series; this is the
   * hook for rolling data once the backend supplies it. */
  live = false,
  onInspect,
  /* Flags samples at or above this value in place. Nothing is passed while the
   * data is demo — an anomaly line belongs to real detector output, not to the
   * chart. */
  alertAbove,
}) {
  const wrapRef = useRef(null);
  /* Fractional sample index under the pointer — not a rounded index, which is
   * what used to make the readout jump a whole timestamp at a time. */
  const [cursor, setCursor] = useState(null);

  const pad = { top: 18, right: 20, bottom: 26, left: 40 };
  const vw = 760;
  const vh = height;
  const plotW = vw - pad.left - pad.right;
  const plotH = vh - pad.top - pad.bottom;

  const targetValues = useMemo(() => data.map((d) => d[yKey]), [data, yKey]);
  /* Drawn values lag the target briefly while the line morphs. */
  const values = useSeriesTween(targetValues);
  const tangents = useMemo(() => monotoneTangents(values), [values]);
  const clockMinutes = useMemo(() => unwrapClockLabels(data.map((d) => d[xKey])), [data, xKey]);

  /* Scale comes from the target, not the tween, so the axis holds still while
   * the line moves. */
  const max = useMemo(() => {
    const valid = targetValues.filter((v) => typeof v === "number" && !isNaN(v));
    if (!valid.length) return 100;
    const peak = Math.max(...valid, alertAbove ?? 0);
    return niceCeil(Math.max(peak, 10) * 1.12);
  }, [targetValues, alertAbove]);

  const ticks = useMemo(() => [0, max / 2, max], [max]);

  /* x accepts a fractional index, so the guide can sit anywhere. */
  const x = useCallback(
    (i) => (data.length < 2 ? pad.left + plotW / 2 : pad.left + (i / (data.length - 1)) * plotW),
    [data.length, plotW, pad.left],
  );
  const y = useCallback((v) => pad.top + plotH - (v / max) * plotH, [max, plotH, pad.top]);

  const linePath = useMemo(() => {
    const n = values.length;
    if (n < 2) return "";
    let d = `M${x(0).toFixed(2)} ${y(values[0]).toFixed(2)}`;
    const step = plotW / (n - 1);
    for (let i = 0; i < n - 1; i++) {
      const c1x = x(i) + step / 3;
      const c1y = y(values[i] + tangents[i] / 3);
      const c2x = x(i + 1) - step / 3;
      const c2y = y(values[i + 1] - tangents[i + 1] / 3);
      d += ` C${c1x.toFixed(2)} ${c1y.toFixed(2)} ${c2x.toFixed(2)} ${c2y.toFixed(2)} ${x(i + 1).toFixed(2)} ${y(values[i + 1]).toFixed(2)}`;
    }
    return d;
  }, [values, tangents, x, y, plotW]);

  const areaPath = useMemo(() => {
    if (!linePath) return "";
    const base = (pad.top + plotH).toFixed(2);
    return `${linePath} L${x(values.length - 1).toFixed(2)} ${base} L${x(0).toFixed(2)} ${base} Z`;
  }, [linePath, values.length, x, plotH, pad.top]);

  const peakIndex = useMemo(() => {
    let best = 0;
    values.forEach((v, i) => {
      if (v > values[best]) best = i;
    });
    return best;
  }, [values]);

  const bursts = useMemo(
    () => (alertAbove == null ? [] : values.map((v, i) => (v >= alertAbove ? i : -1)).filter((i) => i >= 0)),
    [values, alertAbove],
  );

  const onMove = (e) => {
    const el = wrapRef.current;
    if (!el || data.length < 2) return;
    const rect = el.getBoundingClientRect();
    if (!rect.width) return;
    /* Pointer -> viewBox units -> fractional index, clamped to the plot so the
     * guide stops at the edges instead of running into the axis gutter. */
    const px = ((e.clientX - rect.left) / rect.width) * vw;
    const f = ((px - pad.left) / plotW) * (data.length - 1);
    setCursor(Math.max(0, Math.min(data.length - 1, f)));
  };

  const leave = () => {
    setCursor(null);
    onInspect?.(false);
  };

  if (!data.length) {
    return (
      <figure className="chart">
        <p className="chart__empty" style={{ height }}>
          No traffic samples in this window.
        </p>
      </figure>
    );
  }

  const lastIndex = data.length - 1;
  const stride = Math.max(1, Math.ceil(data.length / 6));
  const cursorValue = cursor == null ? null : valueAt(values, tangents, cursor);
  /* Time is read off the cursor position too, so the readout moves as one:
   * position -> interpolated time -> interpolated value. */
  const cursorLabel =
    cursor == null
      ? null
      : clockMinutes
        ? formatClock(lerpAt(clockMinutes, cursor))
        : data[Math.round(cursor)][xKey];

  return (
    <figure className="chart">
      <div className="chart__plot" ref={wrapRef}>
        <svg
          viewBox={`0 0 ${vw} ${vh}`}
          className="chart__svg"
          role="img"
          aria-label={`${label} over time, latest ${values[lastIndex].toFixed(1)}${unit}`}
          onPointerMove={onMove}
          onPointerEnter={() => onInspect?.(true)}
          onPointerLeave={leave}
          onPointerCancel={leave}
        >
          <defs>
            <linearGradient id="trendWash" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="var(--series-1)" stopOpacity="0.16" />
              <stop offset="100%" stopColor="var(--series-1)" stopOpacity="0.01" />
            </linearGradient>
          </defs>

          {ticks.map((t) => (
            <g key={t}>
              <line x1={pad.left} x2={vw - pad.right} y1={y(t)} y2={y(t)} stroke="var(--grid)" strokeWidth="1" />
              <text x={pad.left - 10} y={y(t) + 4} className="chart__tick" textAnchor="end">
                {t}
              </text>
            </g>
          ))}

          {data.map((d, i) =>
            i % stride === 0 ? (
              <text key={`${d[xKey]}-${i}`} x={x(i)} y={vh - 8} className="chart__tick" textAnchor="middle">
                {d[xKey]}
              </text>
            ) : null,
          )}

          {alertAbove != null && (
            <g>
              <line
                x1={pad.left}
                x2={vw - pad.right}
                y1={y(alertAbove)}
                y2={y(alertAbove)}
                stroke="var(--critical)"
                strokeWidth="1"
                opacity="0.38"
              />
              <text x={vw - pad.right} y={y(alertAbove) - 6} className="chart__thresh tnum" textAnchor="end">
                alert {alertAbove}
              </text>
            </g>
          )}

          <path d={areaPath} fill="url(#trendWash)" />
          <path
            d={linePath}
            fill="none"
            stroke="var(--series-1)"
            strokeWidth="2"
            strokeLinejoin="round"
            strokeLinecap="round"
            className="chart__line"
          />

          {bursts.map((i) => (
            <circle
              key={`burst-${i}`}
              cx={x(i)}
              cy={y(values[i])}
              r="3.5"
              fill="var(--critical)"
              stroke="var(--surface)"
              strokeWidth="2"
            />
          ))}

          {/* One direct label. Live: the leading value. Static: the extreme. */}
          {live ? (
            <g>
              <circle cx={x(lastIndex)} cy={y(values[lastIndex])} r="8" fill="var(--series-1)" className="chart__pulse" />
              <circle
                cx={x(lastIndex)}
                cy={y(values[lastIndex])}
                r="4.5"
                fill="var(--series-1)"
                stroke="var(--surface)"
                strokeWidth="2"
              />
              <text x={x(lastIndex) - 11} y={y(values[lastIndex] || 0) - 11} className="chart__peak tnum" textAnchor="end">
                {typeof values[lastIndex] === "number" && !isNaN(values[lastIndex]) ? values[lastIndex].toFixed(1) : "—"}
                {unit}
              </text>
            </g>
          ) : (
            <text
              x={x(peakIndex)}
              y={y(values[peakIndex] || 0) - 12}
              className="chart__peak tnum"
              textAnchor={peakIndex > data.length - 5 ? "end" : "middle"}
            >
              {typeof values[peakIndex] === "number" && !isNaN(values[peakIndex]) ? Number(values[peakIndex]).toFixed(1) : "—"}
              {unit}
            </text>
          )}

          {cursor != null && (
            <g>
              <line
                x1={x(cursor)}
                x2={x(cursor)}
                y1={pad.top}
                y2={pad.top + plotH}
                stroke="var(--ink-4)"
                strokeWidth="1"
              />
              <circle
                cx={x(cursor)}
                cy={y(cursorValue)}
                r="4.5"
                fill="var(--series-1)"
                stroke="var(--surface)"
                strokeWidth="2"
              />
            </g>
          )}
        </svg>

        {cursor != null && (
          <div
            className="tip"
            style={{ left: `${(x(cursor) / vw) * 100}%`, top: `${(y(cursorValue) / vh) * 100}%` }}
          >
            <span className="tip__v tnum">
              {cursorValue.toFixed(1)}
              {unit}
            </span>
            <span className="tip__row">
              <i className="tip__key" style={{ background: "var(--series-1)" }} />
              {label}
            </span>
            <span className="tip__t tnum">{cursorLabel}</span>
          </div>
        )}
      </div>

      {alertAbove != null && (
        <figcaption className="chart__note">
          <i className="dot" style={{ background: bursts.length ? "var(--critical)" : "var(--ok)" }} aria-hidden />
          {bursts.length
            ? `${bursts.length} sample${bursts.length > 1 ? "s" : ""} crossed ${alertAbove} Gbps in this window`
            : `No sample crossed ${alertAbove} Gbps in this window`}
        </figcaption>
      )}
    </figure>
  );
}

/* ---------------------------------------------------------------- Donut */

/*
 * Part-to-whole for a handful of categories. The centre carries the total and
 * swaps to the hovered slice, so the exact number is always one place — no
 * floating tooltip chasing the pointer around a circle.
 */
export function Donut({ rows, unit = "", centreLabel = "total", size = 168 }) {
  const [active, setActive] = useState(null);

  const total = rows.reduce((sum, r) => sum + r.value, 0);
  const r = size / 2 - 13;
  const circumference = 2 * Math.PI * r;
  const gap = 3; /* surface gap between segments, in px of arc */

  let cursor = 0;
  const arcs = rows.map((row) => {
    const share = total ? row.value / total : 0;
    const len = Math.max(0, share * circumference - gap);
    const arc = { ...row, share, len, offset: cursor };
    cursor += share * circumference;
    return arc;
  });

  const shown = active != null ? arcs[active] : null;

  return (
    <div className="donut">
      <div className="donut__ring" style={{ width: size, height: size }}>
        <svg
          viewBox={`0 0 ${size} ${size}`}
          width={size}
          height={size}
          role="img"
          aria-label={rows.map((row) => `${row.label}: ${row.value}`).join(", ")}
        >
          <g transform={`rotate(-90 ${size / 2} ${size / 2})`}>
            <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--plane-deep)" strokeWidth="14" />
            {arcs.map((arc, i) => (
              <circle
                key={arc.label}
                cx={size / 2}
                cy={size / 2}
                r={r}
                fill="none"
                stroke={arc.color}
                strokeWidth={active === i ? 18 : 14}
                strokeLinecap="butt"
                strokeDasharray={`${arc.len} ${circumference - arc.len}`}
                strokeDashoffset={-arc.offset}
                className="donut__arc"
                onPointerEnter={() => setActive(i)}
                onPointerLeave={() => setActive(null)}
              />
            ))}
          </g>
        </svg>

        <div className="donut__centre">
          <span className="donut__num">{shown ? shown.value : total}</span>
          <span className="donut__cap">{shown ? shown.label : centreLabel}</span>
          {shown && <span className="donut__pct tnum">{Math.round(shown.share * 100)}%</span>}
        </div>
      </div>

      {/* Values printed here are the relief channel: two of these hues sit
          below the contrast floor on white, so identity never rests on colour. */}
      <ul className="donut__legend">
        {arcs.map((arc, i) => (
          <li
            key={arc.label}
            className={`donut__item ${active === i ? "donut__item--on" : ""}`}
            onPointerEnter={() => setActive(i)}
            onPointerLeave={() => setActive(null)}
          >
            <i className="donut__sw" style={{ background: arc.color }} aria-hidden />
            <span className="donut__name">{arc.label}</span>
            <span className="donut__val tnum">
              {arc.value}
              {unit}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

/* ------------------------------------------------------------- Bar list */

/*
 * Magnitude bars. Rows become selectable when `onSelect` is supplied — passing
 * the already-selected key clears it, so the selection is its own toggle.
 */
export function BarList({ rows, max: maxProp, unit = "", onSelect, selected }) {
  const max = maxProp ?? niceCeil(Math.max(...rows.map((r) => r.value)));
  const interactive = typeof onSelect === "function";

  return (
    <ul className="bars">
      {rows.map((r) => {
        const key = r.key ?? r.label;
        const on = interactive && selected === key;
        const toggle = () => onSelect(on ? null : key);
        return (
          <li
            key={key}
            className={`bars__row ${interactive ? "bars__row--click" : ""} ${on ? "bars__row--on" : ""}`}
            {...(interactive && {
              role: "button",
              tabIndex: 0,
              "aria-pressed": on,
              onClick: toggle,
              onKeyDown: (e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  toggle();
                }
              },
            })}
          >
            <span className="bars__label">
              {r.color && <i className="bars__dot" style={{ background: r.color }} aria-hidden />}
              {r.label}
            </span>
            <span className="bars__track">
              <span
                className="bars__fill"
                style={{ width: `${(r.value / max) * 100}%`, background: r.color ?? "var(--series-1)" }}
              />
            </span>
            <span className="bars__value tnum">
              {r.value}
              {unit}
            </span>
          </li>
        );
      })}
    </ul>
  );
}
