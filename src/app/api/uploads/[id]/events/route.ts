import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { currentUser } from "@/lib/auth";
import { query } from "@/lib/db";

const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 500;

interface EventRow extends Record<string, unknown> {
  line_no: number;
  ts: Date;
  username: string | null;
  client_ip: string | null;
  host: string | null;
  url: string | null;
  method: string | null;
  status_code: number | null;
  action: string | null;
  category: string | null;
  threat_name: string | null;
  bytes_sent: string | null;
  bytes_received: string | null;
  user_agent: string | null;
}

/**
 * GET /api/uploads/:id/events — the paginated event table.
 *
 * Filters: `q` (free text over host/url/user/ip), `action`, `anomalousOnly`.
 * `anomalousOnly` joins against the line numbers recorded on each finding,
 * which is what lets the UI show "only the rows that triggered something".
 */
export async function GET(
  request: NextRequest,
  context: RouteContext<"/api/uploads/[id]/events">,
) {
  const user = await currentUser();
  if (!user) {
    return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  }

  const { id } = await context.params;

  // Ownership check before touching the (much larger) events table.
  const owned = await query<{ id: string }>(
    "SELECT id FROM uploads WHERE id = $1 AND user_id = $2",
    [id, user.id],
  );
  if (owned.length === 0) {
    return NextResponse.json({ error: "Upload not found" }, { status: 404 });
  }

  const params = request.nextUrl.searchParams;
  const limit = Math.min(
    MAX_LIMIT,
    Math.max(1, Number.parseInt(params.get("limit") ?? "", 10) || DEFAULT_LIMIT),
  );
  const offset = Math.max(0, Number.parseInt(params.get("offset") ?? "", 10) || 0);
  const search = params.get("q")?.trim() ?? "";
  const action = params.get("action")?.trim() ?? "";
  const anomalousOnly = params.get("anomalousOnly") === "true";

  const where: string[] = ["e.upload_id = $1"];
  const values: unknown[] = [id];

  if (search) {
    values.push(`%${search}%`);
    const p = `$${values.length}`;
    where.push(
      `(e.host ILIKE ${p} OR e.url ILIKE ${p} OR e.username ILIKE ${p} OR e.client_ip ILIKE ${p} OR e.threat_name ILIKE ${p})`,
    );
  }

  if (action) {
    values.push(action);
    where.push(`e.action = $${values.length}`);
  }

  if (anomalousOnly) {
    where.push(
      `EXISTS (SELECT 1 FROM anomalies a
                WHERE a.upload_id = e.upload_id
                  AND e.line_no = ANY(a.event_line_nos))`,
    );
  }

  const whereSql = where.join(" AND ");

  const [{ count }] = await query<{ count: string }>(
    `SELECT count(*)::text AS count FROM log_events e WHERE ${whereSql}`,
    values,
  );

  values.push(limit, offset);
  const rows = await query<EventRow>(
    `SELECT e.line_no, e.ts, e.username, e.client_ip, e.host, e.url, e.method,
            e.status_code, e.action, e.category, e.threat_name,
            e.bytes_sent::text, e.bytes_received::text, e.user_agent
       FROM log_events e
      WHERE ${whereSql}
      ORDER BY e.ts ASC, e.line_no ASC
      LIMIT $${values.length - 1} OFFSET $${values.length}`,
    values,
  );

  // Which of the returned lines are implicated in a finding — used to
  // highlight rows and show the detector name inline.
  const lineNos = rows.map((r) => r.line_no);
  const flags =
    lineNos.length === 0
      ? []
      : await query<{ line_no: number; detectors: string[] }>(
          `SELECT l.line_no, array_agg(DISTINCT a.detector) AS detectors
             FROM anomalies a
             JOIN unnest(a.event_line_nos) AS l(line_no) ON TRUE
            WHERE a.upload_id = $1 AND l.line_no = ANY($2::int[])
            GROUP BY l.line_no`,
          [id, lineNos],
        );

  const detectorsByLine = new Map(flags.map((f) => [f.line_no, f.detectors]));

  return NextResponse.json({
    total: Number(count),
    limit,
    offset,
    events: rows.map((r) => ({
      lineNo: r.line_no,
      ts: r.ts,
      username: r.username,
      clientIp: r.client_ip,
      host: r.host,
      url: r.url,
      method: r.method,
      statusCode: r.status_code,
      action: r.action,
      category: r.category,
      threatName: r.threat_name,
      bytesSent: r.bytes_sent === null ? null : Number(r.bytes_sent),
      bytesReceived: r.bytes_received === null ? null : Number(r.bytes_received),
      userAgent: r.user_agent,
      detectors: detectorsByLine.get(r.line_no) ?? [],
    })),
  });
}
