import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { Link } from "@/lib/rr";

/*
 * Tracks the pointer inside a glass control and writes it to --mx / --my,
 * which positions the specular highlight. One listener per control, values
 * written straight to the style attribute so React never re-renders on move.
 */
export function useSheen() {
  const ref = useRef(null);

  const onPointerMove = useCallback((e) => {
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    el.style.setProperty("--mx", `${((e.clientX - r.left) / r.width) * 100}%`);
    el.style.setProperty("--my", `${((e.clientY - r.top) / r.height) * 100}%`);
  }, []);

  const onPointerLeave = useCallback(() => {
    const el = ref.current;
    if (!el) return;
    el.style.setProperty("--mx", "50%");
    el.style.setProperty("--my", "0%");
  }, []);

  return { ref, onPointerMove, onPointerLeave };
}

function classes(...parts) {
  return parts.filter(Boolean).join(" ");
}

function variantClass({ variant = "default", size, icon, block }) {
  return classes(
    "glass",
    variant === "ink" && "glass--ink",
    variant === "quiet" && "glass--quiet",
    size === "sm" && "glass--sm",
    size === "lg" && "glass--lg",
    icon && "glass--icon",
    block && "glass--block",
  );
}

export function GlassButton({ children, variant, size, icon, block, className, ...rest }) {
  const sheen = useSheen();
  return (
    <button
      type="button"
      ref={sheen.ref}
      onPointerMove={sheen.onPointerMove}
      onPointerLeave={sheen.onPointerLeave}
      className={classes(variantClass({ variant, size, icon, block }), className)}
      {...rest}
    >
      {children}
    </button>
  );
}

export function GlassLink({ children, to, variant, size, icon, block, className, ...rest }) {
  const sheen = useSheen();
  return (
    <Link
      to={to}
      ref={sheen.ref}
      onPointerMove={sheen.onPointerMove}
      onPointerLeave={sheen.onPointerLeave}
      className={classes(variantClass({ variant, size, icon, block }), className)}
      {...rest}
    >
      {children}
    </Link>
  );
}

/* Same material as GlassLink, for in-page anchors that a router Link cannot do. */
export function GlassAnchor({ children, href, variant, size, icon, block, className, ...rest }) {
  const sheen = useSheen();
  return (
    <a
      href={href}
      ref={sheen.ref}
      onPointerMove={sheen.onPointerMove}
      onPointerLeave={sheen.onPointerLeave}
      className={classes(variantClass({ variant, size, icon, block }), className)}
      {...rest}
    >
      {children}
    </a>
  );
}

/* Segmented control — the thumb measures the active button and slides to it. */
export function Segmented({ options, value, onChange, ariaLabel }) {
  const wrapRef = useRef(null);
  const [thumb, setThumb] = useState({ left: 3, width: 0 });

  const measure = useCallback(() => {
    const wrap = wrapRef.current;
    if (!wrap) return;
    const active = wrap.querySelector('[data-on="true"]');
    if (!active) return;
    /* Measured off rects, then shifted by the border, because the thumb is
     * anchored at left:0 — i.e. the track's padding box. */
    const wrapRect = wrap.getBoundingClientRect();
    const rect = active.getBoundingClientRect();
    setThumb({ left: rect.left - wrapRect.left - wrap.clientLeft, width: rect.width });
  }, []);

  useLayoutEffect(measure, [measure, value, options]);

  useEffect(() => {
    if (!("ResizeObserver" in window)) return;
    const ro = new ResizeObserver(measure);
    if (wrapRef.current) ro.observe(wrapRef.current);
    return () => ro.disconnect();
  }, [measure]);

  return (
    <div className="seg" ref={wrapRef} role="tablist" aria-label={ariaLabel}>
      <span
        className="seg__thumb"
        style={{ transform: `translateX(${thumb.left}px)`, width: thumb.width }}
      />
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="tab"
          aria-selected={value === o.value}
          data-on={value === o.value}
          className="seg__btn"
          onClick={() => onChange(o.value)}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}
