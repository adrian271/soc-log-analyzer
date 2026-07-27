import type { PoolClient } from "pg";
import { transaction } from "./db";
import { parseLogFile } from "./parser";
import { detectAnomalies } from "./detectors";
import { computeStats } from "./analysis";
import { writeNarrative } from "./narrative";
import type { Anomaly, LogEvent } from "./types";

/** Rows per multi-row INSERT. Keeps us well under Postgres' parameter limit. */
const BATCH_SIZE = 500;

export interface IngestResult {
  uploadId: string;
  totalLines: number;
  parsedLines: number;
  malformedLines: number;
  anomalyCount: number;
}

/**
 * The full ingest pipeline for one uploaded file:
 *
 *   parse -> detect anomalies -> aggregate stats -> persist -> (optional) LLM
 *
 * Everything through `persist` is deterministic. The LLM narrative is written
 * afterwards and is allowed to fail without failing the upload.
 */
export async function ingestLogFile(
  userId: number,
  filename: string,
  content: string,
): Promise<IngestResult> {
  const { events, malformed, totalLines } = parseLogFile(content);

  if (events.length === 0) {
    throw new IngestError(
      malformed.length > 0
        ? `No parsable log lines found. ${malformed.length} line(s) failed, first error: ${malformed[0].reason}`
        : "The file contained no log lines.",
    );
  }

  const anomalies = detectAnomalies(events);
  const stats = computeStats(events, anomalies);

  const range = events.reduce(
    (acc, e) => ({
      start: e.ts < acc.start ? e.ts : acc.start,
      end: e.ts > acc.end ? e.ts : acc.end,
    }),
    { start: events[0].ts, end: events[0].ts },
  );

  const uploadId = await transaction(async (client) => {
    const upload = await client.query<{ id: string }>(
      `INSERT INTO uploads
         (user_id, filename, size_bytes, status, total_lines, parsed_lines,
          malformed_lines, range_start, range_end, stats)
       VALUES ($1, $2, $3, 'ready', $4, $5, $6, $7, $8, $9)
       RETURNING id`,
      [
        userId,
        filename,
        Buffer.byteLength(content, "utf8"),
        totalLines,
        events.length,
        malformed.length,
        range.start,
        range.end,
        JSON.stringify(stats),
      ],
    );
    const id = upload.rows[0].id;

    await insertEvents(client, id, events);
    await insertAnomalies(client, id, anomalies);
    return id;
  });

  // Best-effort: a missing API key or a model error must not lose the upload,
  // which is already fully analysed and persisted at this point.
  await writeNarrative(uploadId, stats, anomalies, range).catch((err) => {
    console.error(`[narrative] skipped for upload ${uploadId}:`, err?.message);
  });

  return {
    uploadId,
    totalLines,
    parsedLines: events.length,
    malformedLines: malformed.length,
    anomalyCount: anomalies.length,
  };
}

const EVENT_COLUMNS = 23;

async function insertEvents(
  client: PoolClient,
  uploadId: string,
  events: LogEvent[],
): Promise<void> {
  for (let start = 0; start < events.length; start += BATCH_SIZE) {
    const batch = events.slice(start, start + BATCH_SIZE);
    const values: unknown[] = [];
    const tuples: string[] = [];

    batch.forEach((e, i) => {
      const base = i * EVENT_COLUMNS;
      tuples.push(
        `(${Array.from({ length: EVENT_COLUMNS }, (_, k) => `$${base + k + 1}`).join(",")})`,
      );
      values.push(
        uploadId, e.lineNo, e.ts, e.username, e.department, e.location,
        e.clientIp, e.serverIp, e.host, e.url, e.method, e.statusCode,
        e.action, e.reason, e.bytesSent, e.bytesReceived, e.category,
        e.threatName, e.riskScore, e.userAgent, e.referer, e.appName, e.raw,
      );
    });

    await client.query(
      `INSERT INTO log_events
         (upload_id, line_no, ts, username, department, location, client_ip,
          server_ip, host, url, method, status_code, action, reason,
          bytes_sent, bytes_received, category, threat_name, risk_score,
          user_agent, referer, app_name, raw)
       VALUES ${tuples.join(",")}`,
      values,
    );
  }
}

async function insertAnomalies(
  client: PoolClient,
  uploadId: string,
  anomalies: Anomaly[],
): Promise<void> {
  for (const a of anomalies) {
    await client.query(
      `INSERT INTO anomalies
         (upload_id, detector, title, severity, confidence, explanation, entity,
          entity_kind, first_seen, last_seen, event_count, event_line_nos, evidence)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
      [
        uploadId, a.detector, a.title, a.severity, a.confidence, a.explanation,
        a.entity, a.entityKind, a.firstSeen, a.lastSeen, a.eventCount,
        a.eventLineNos, JSON.stringify(a.evidence),
      ],
    );
  }
}

export class IngestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IngestError";
  }
}
