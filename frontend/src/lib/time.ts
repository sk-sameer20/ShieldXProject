/**
 * Shared timezone-aware timestamp formatter for ShieldX.
 * Parses backend UTC timestamps (including ISO strings with or without trailing 'Z')
 * and converts them to the browser user's local timezone.
 */

export function parseUtcDate(val: string | number | null | undefined): Date | null {
  if (val == null || val === "") return null;
  if (typeof val === "number") {
    return new Date(val > 1e11 ? val : val * 1000);
  }
  let s = String(val).trim();
  if (!s) return null;

  // Preserve legacy/demo time strings like '13:54:55' without conversion
  if (/^\d{1,2}:\d{2}(:\d{2})?$/.test(s)) {
    return null;
  }

  // Replace space separator with T if SQL format like "2026-09-28 04:02:55"
  if (s.includes(" ") && !s.includes("T")) {
    s = s.replace(" ", "T");
  }

  // If timestamp lacks timezone offset (e.g. from SQLite/FastAPI), treat as UTC
  if (!s.endsWith("Z") && !/[+-]\d{2}(:?\d{2})?$/.test(s)) {
    s = s + "Z";
  }

  const d = new Date(s);
  return isNaN(d.getTime()) ? null : d;
}

export function formatLocalTimestamp(val: string | number | null | undefined): string {
  if (val == null || val === "") return "—";
  const d = parseUtcDate(val);
  if (!d) return String(val);

  const pad = (v: number) => String(Math.abs(v)).padStart(2, "0");
  const year = d.getFullYear();
  const month = pad(d.getMonth() + 1);
  const day = pad(d.getDate());
  const hours = pad(d.getHours());
  const minutes = pad(d.getMinutes());
  const seconds = pad(d.getSeconds());

  return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
}
