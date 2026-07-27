import { z } from "zod";

/**
 * Runtime schemas for the values that cross a trust boundary.
 *
 * TypeScript checks what we *wrote*; it cannot check what actually comes back
 * out of a `JSONB` column at runtime. Everywhere else in this codebase the
 * shape of a value is guaranteed by the code that produced it — but
 * `uploads.stats` and `anomalies.evidence` are written as JSON, read back
 * later, and asserted into a type. If a row were written by an older version
 * of the code (a renamed field, a different bucket count), `tsc` would still
 * be perfectly happy and the report page would throw on first access.
 *
 * These schemas turn that silent failure into a caught one. They are
 * deliberately *only* applied at the database read-back — request bodies are
 * validated by hand at their handlers, where the field count is small enough
 * that a schema would add indirection without adding safety.
 */

export const CountPairSchema = z.object({
  key: z.string(),
  count: z.number(),
});

export const TimelineBucketSchema = z.object({
  /** ISO timestamp of the bucket's start. */
  start: z.string(),
  total: z.number(),
  blocked: z.number(),
  threats: z.number(),
  anomalous: z.number(),
});

/** Aggregate rollups computed once at ingest and stored on the upload row. */
export const UploadStatsSchema = z.object({
  totalEvents: z.number(),
  uniqueClientIps: z.number(),
  uniqueUsers: z.number(),
  uniqueHosts: z.number(),
  blockedCount: z.number(),
  allowedCount: z.number(),
  threatCount: z.number(),
  bytesSent: z.number(),
  bytesReceived: z.number(),
  timeline: z.array(TimelineBucketSchema),
  topHosts: z.array(CountPairSchema),
  topCategories: z.array(CountPairSchema),
  topClientIps: z.array(CountPairSchema),
  topThreats: z.array(CountPairSchema),
  statusBreakdown: z.array(CountPairSchema),
});

/**
 * Detector-specific supporting numbers. The keys differ per detector by
 * design, so the only thing worth asserting is that it really is an object —
 * which is exactly the case that would break the UI's `Object.keys()` call.
 */
export const EvidenceSchema = z.record(z.string(), z.unknown());

// The application types are inferred from the schemas rather than declared
// alongside them, so the two cannot drift apart.
export type CountPair = z.infer<typeof CountPairSchema>;
export type TimelineBucket = z.infer<typeof TimelineBucketSchema>;
export type UploadStats = z.infer<typeof UploadStatsSchema>;
export type Evidence = z.infer<typeof EvidenceSchema>;

/**
 * Validates a `uploads.stats` value read back from Postgres.
 *
 * Returns null rather than throwing: a report whose rollups fail to parse
 * should still render its findings and event table, which is strictly more
 * useful to an analyst than an error page. The UI already treats a null
 * `stats` as "no aggregate sections", so this degrades into an existing path.
 */
export function parseUploadStats(raw: unknown): UploadStats | null {
  if (raw === null || raw === undefined) return null;
  const result = UploadStatsSchema.safeParse(raw);
  if (result.success) return result.data;

  console.error(
    "[schema] uploads.stats did not match the expected shape:",
    z.prettifyError(result.error),
  );
  return null;
}

/** As above, for `anomalies.evidence`. */
export function parseEvidence(raw: unknown): Evidence | null {
  if (raw === null || raw === undefined) return null;
  const result = EvidenceSchema.safeParse(raw);
  if (result.success) return result.data;

  console.error(
    "[schema] anomalies.evidence was not an object:",
    z.prettifyError(result.error),
  );
  return null;
}
