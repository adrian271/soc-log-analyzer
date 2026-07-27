import type { Anomaly, LogEvent, TimelineBucket, UploadStats } from "./types";
import { topN } from "./stats";

/** Number of buckets in the timeline chart. */
const TIMELINE_BUCKETS = 60;

/**
 * Computes the aggregate rollups shown on the results dashboard.
 *
 * This runs once at ingest and the result is stored as JSON on the upload row,
 * so opening a report is a single indexed read rather than a re-scan of every
 * event.
 */
export function computeStats(
  events: LogEvent[],
  anomalies: Anomaly[],
): UploadStats {
  const anomalousLines = new Set<number>();
  for (const a of anomalies) for (const n of a.eventLineNos) anomalousLines.add(n);

  let blocked = 0;
  let threats = 0;
  let bytesSent = 0;
  let bytesReceived = 0;

  for (const e of events) {
    if (e.action?.toLowerCase() === "blocked") blocked++;
    if (e.threatName) threats++;
    bytesSent += e.bytesSent ?? 0;
    bytesReceived += e.bytesReceived ?? 0;
  }

  return {
    totalEvents: events.length,
    uniqueClientIps: new Set(events.map((e) => e.clientIp).filter(Boolean)).size,
    uniqueUsers: new Set(events.map((e) => e.username).filter(Boolean)).size,
    uniqueHosts: new Set(events.map((e) => e.host).filter(Boolean)).size,
    blockedCount: blocked,
    allowedCount: events.length - blocked,
    threatCount: threats,
    bytesSent,
    bytesReceived,
    timeline: buildTimeline(events, anomalousLines),
    topHosts: topN(events.map((e) => e.host), 10),
    topCategories: topN(events.map((e) => e.category), 10),
    topClientIps: topN(events.map((e) => e.clientIp), 10),
    topThreats: topN(events.map((e) => e.threatName), 10),
    statusBreakdown: topN(
      events.map((e) => (e.statusCode === null ? null : String(e.statusCode))),
      10,
    ),
  };
}

/**
 * Buckets events into a fixed number of equal-width slots spanning the log's
 * time range. Fixed count (rather than fixed width) keeps the chart readable
 * whether the file covers ten minutes or a week.
 */
function buildTimeline(
  events: LogEvent[],
  anomalousLines: Set<number>,
): TimelineBucket[] {
  if (events.length === 0) return [];

  let min = events[0].ts.getTime();
  let max = min;
  for (const e of events) {
    const t = e.ts.getTime();
    if (t < min) min = t;
    if (t > max) max = t;
  }

  // A log covering a single instant would give a zero-width bucket.
  const span = Math.max(1, max - min);
  const width = Math.ceil(span / TIMELINE_BUCKETS);

  const buckets: TimelineBucket[] = Array.from(
    { length: TIMELINE_BUCKETS },
    (_, i) => ({
      start: new Date(min + i * width).toISOString(),
      total: 0,
      blocked: 0,
      threats: 0,
      anomalous: 0,
    }),
  );

  for (const e of events) {
    const idx = Math.min(
      TIMELINE_BUCKETS - 1,
      Math.floor((e.ts.getTime() - min) / width),
    );
    const b = buckets[idx];
    b.total++;
    if (e.action?.toLowerCase() === "blocked") b.blocked++;
    if (e.threatName) b.threats++;
    if (anomalousLines.has(e.lineNo)) b.anomalous++;
  }

  return buckets;
}
