import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { currentUser } from "@/lib/auth";
import { query } from "@/lib/db";
import { parseEvidence, parseUploadStats } from "@/lib/schemas";

interface UploadRow extends Record<string, unknown> {
  id: string;
  filename: string;
  size_bytes: number;
  status: string;
  total_lines: number;
  parsed_lines: number;
  malformed_lines: number;
  range_start: Date | null;
  range_end: Date | null;
  /** Raw JSONB — validated through parseUploadStats before it leaves here. */
  stats: unknown;
  narrative: string | null;
  narrative_model: string | null;
  created_at: Date;
}

interface AnomalyRow extends Record<string, unknown> {
  id: number;
  detector: string;
  title: string;
  severity: string;
  confidence: number;
  explanation: string;
  entity: string | null;
  entity_kind: string | null;
  first_seen: Date | null;
  last_seen: Date | null;
  event_count: number;
  event_line_nos: number[];
  /** Raw JSONB — validated through parseEvidence before it leaves here. */
  evidence: unknown;
  source: string;
}

/**
 * GET /api/uploads/:id — the full report for one upload.
 *
 * Every query is scoped by user_id as well as id, so a valid session cannot
 * read another user's report by guessing a UUID.
 */
export async function GET(
  _request: NextRequest,
  context: RouteContext<"/api/uploads/[id]">,
) {
  const user = await currentUser();
  if (!user) {
    return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  }

  const { id } = await context.params;

  const uploads = await query<UploadRow>(
    `SELECT id, filename, size_bytes, status, total_lines, parsed_lines,
            malformed_lines, range_start, range_end, stats, narrative,
            narrative_model, created_at
       FROM uploads
      WHERE id = $1 AND user_id = $2`,
    [id, user.id],
  );

  if (uploads.length === 0) {
    return NextResponse.json({ error: "Upload not found" }, { status: 404 });
  }
  const u = uploads[0];

  const anomalies = await query<AnomalyRow>(
    `SELECT id, detector, title, severity, confidence, explanation, entity,
            entity_kind, first_seen, last_seen, event_count, event_line_nos,
            evidence, source
       FROM anomalies
      WHERE upload_id = $1
      ORDER BY confidence DESC, id ASC`,
    [id],
  );

  return NextResponse.json({
    upload: {
      id: u.id,
      filename: u.filename,
      sizeBytes: u.size_bytes,
      status: u.status,
      totalLines: u.total_lines,
      parsedLines: u.parsed_lines,
      malformedLines: u.malformed_lines,
      rangeStart: u.range_start,
      rangeEnd: u.range_end,
      createdAt: u.created_at,
      narrative: u.narrative,
      narrativeModel: u.narrative_model,
    },
    // Validated on the way out, so a client of this API can trust the shape.
    stats: parseUploadStats(u.stats),
    // The two detection layers are returned as separate collections rather
    // than one list with a flag, so a consumer cannot accidentally rank a
    // model-proposed lead alongside a measured finding.
    anomalies: anomalies.filter((a) => a.source !== "model").map(toApi),
    modelFindings: anomalies.filter((a) => a.source === "model").map(toApi),
  });
}

function toApi(a: AnomalyRow) {
  return {
    id: a.id,
    detector: a.detector,
    title: a.title,
    severity: a.severity,
    confidence: a.confidence,
    explanation: a.explanation,
    entity: a.entity,
    entityKind: a.entity_kind,
    firstSeen: a.first_seen,
    lastSeen: a.last_seen,
    eventCount: a.event_count,
    eventLineNos: a.event_line_nos,
    evidence: parseEvidence(a.evidence),
    source: a.source,
  };
}

/** DELETE /api/uploads/:id — cascades to events and anomalies. */
export async function DELETE(
  _request: NextRequest,
  context: RouteContext<"/api/uploads/[id]">,
) {
  const user = await currentUser();
  if (!user) {
    return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  }

  const { id } = await context.params;
  const deleted = await query<{ id: string }>(
    "DELETE FROM uploads WHERE id = $1 AND user_id = $2 RETURNING id",
    [id, user.id],
  );

  if (deleted.length === 0) {
    return NextResponse.json({ error: "Upload not found" }, { status: 404 });
  }
  return NextResponse.json({ ok: true });
}
