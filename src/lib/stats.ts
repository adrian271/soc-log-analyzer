/**
 * Small statistics helpers shared by the detectors.
 *
 * Everything here is deliberately *robust* (median / MAD rather than mean /
 * standard deviation). Log data is heavy-tailed and the outliers are exactly
 * what we are hunting for — a mean-based z-score gets dragged toward the
 * attacker's own traffic and hides the thing it is supposed to surface.
 */

export function clamp01(x: number): number {
  return x < 0 ? 0 : x > 1 ? 1 : x;
}

export function median(values: number[]): number {
  if (values.length === 0) return 0;
  const s = [...values].sort((a, b) => a - b);
  const mid = s.length >> 1;
  return s.length % 2 === 0 ? (s[mid - 1] + s[mid]) / 2 : s[mid];
}

/**
 * Median Absolute Deviation — the robust analogue of standard deviation.
 * Scaled by 1.4826 so that for normally-distributed data MAD ≈ σ.
 */
export function mad(values: number[], med = median(values)): number {
  if (values.length === 0) return 0;
  return 1.4826 * median(values.map((v) => Math.abs(v - med)));
}

/**
 * Robust z-score: how many MADs above the median a value sits.
 *
 * When MAD is 0 (more than half the population is identical — common when most
 * clients make exactly the same small number of requests) the ratio is
 * undefined, so we fall back to a scale derived from the median itself. That
 * keeps the score finite instead of returning Infinity for every outlier.
 */
export function robustZ(x: number, values: number[]): number {
  const med = median(values);
  const scale = mad(values, med);
  if (scale > 0) return (x - med) / scale;
  const fallback = Math.max(1, med * 0.5);
  return (x - med) / fallback;
}

/** Shannon entropy in bits per character — used to spot DGA-style hostnames. */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Groups items by a string key, skipping items whose key is null. */
export function groupBy<T>(
  items: T[],
  key: (item: T) => string | null,
): Map<string, T[]> {
  const out = new Map<string, T[]>();
  for (const item of items) {
    const k = key(item);
    if (k === null) continue;
    const bucket = out.get(k);
    if (bucket) bucket.push(item);
    else out.set(k, [item]);
  }
  return out;
}

/** Descending count of each distinct value, truncated to `limit`. */
export function topN(values: (string | null)[], limit: number) {
  const counts = new Map<string, number>();
  for (const v of values) {
    if (v === null) continue;
    counts.set(v, (counts.get(v) ?? 0) + 1);
  }
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([key, count]) => ({ key, count }));
}

/** Formats a byte count for use inside analyst-facing explanation text. */
export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let v = n / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`;
}

/**
 * Formats a ratio or z-score for analyst-facing prose.
 *
 * These can be enormous — an 887 MB upload against a 3.8 KB median is a
 * genuine 124,511× — and printing `124511.0×` reads as a broken number rather
 * than a finding. Large values lose their decimals and gain separators; beyond
 * 10,000 the exact figure stops carrying information, so it is bucketed.
 */
export function formatMultiple(x: number): string {
  if (!Number.isFinite(x)) return "effectively infinitely";
  if (x >= 10_000) return "over 10,000×";
  if (x >= 100) return `${Math.round(x).toLocaleString()}×`;
  if (x >= 10) return `${x.toFixed(0)}×`;
  return `${x.toFixed(1)}×`;
}

/**
 * Collapses a sorted hour list into readable ranges:
 * [8,9,10,16,17] -> "08:00–10:00, 16:00–17:00".
 */
export function formatHourRanges(hours: number[]): string {
  if (hours.length === 0) return "none";
  const sorted = [...hours].sort((a, b) => a - b);
  const pad = (h: number) => `${String(h).padStart(2, "0")}:00`;

  const parts: string[] = [];
  let start = sorted[0];
  let prev = sorted[0];

  for (let i = 1; i <= sorted.length; i++) {
    const h = sorted[i];
    if (h === prev + 1) {
      prev = h;
      continue;
    }
    parts.push(start === prev ? pad(start) : `${pad(start)}–${pad(prev)}`);
    start = h;
    prev = h;
  }
  return parts.join(", ");
}

/** e.g. "1m 0s", "2h 15m" — used when describing beacon intervals. */
export function formatDuration(ms: number): string {
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return s % 60 === 0 ? `${m}m` : `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  return m % 60 === 0 ? `${h}h` : `${h}h ${m % 60}m`;
}
