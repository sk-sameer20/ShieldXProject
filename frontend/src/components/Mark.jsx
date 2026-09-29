/* Brand mark: a shield aperture drawn in ink. Flat, no gradient. */
export function Mark({ size = 26 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" aria-hidden className="mark">
      <path
        d="M12 2.6 20 5.4v6.1c0 4.7-3.2 8.6-8 9.9-4.8-1.3-8-5.2-8-9.9V5.4L12 2.6Z"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <path d="M12 8.2v7.6" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
      <path d="M8.6 11.1h6.8" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  );
}
