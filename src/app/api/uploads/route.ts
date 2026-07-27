import { NextResponse } from "next/server";
import { currentUser } from "@/lib/auth";
import { query } from "@/lib/db";
import { IngestError, ingestLogFile } from "@/lib/ingest";

/**
 * `pg` is a TCP client, so this route cannot run on the edge runtime.
 * Being explicit stops a future config change from silently breaking it.
 */
export const runtime = "nodejs";

/**
 * Ingest is synchronous — parse, detect, then write events and findings. That
 * is fast locally but slower against a remote database on a cold start, so the
 * default function timeout is raised rather than left to chance.
 */
export const maxDuration = 60;

/**
 * Refuse anything larger than this outright rather than OOM the process.
 *
 * 4 MB, not more: serverless platforms cap request bodies around 4.5 MB, so a
 * larger advertised limit would be a promise the deployed app can't keep. The
 * example logs are well under 1 MB.
 */
const MAX_BYTES = 4 * 1024 * 1024;
const ALLOWED_EXTENSIONS = [".log", ".txt", ".tsv", ".csv"];

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
  created_at: Date;
  anomaly_count: string;
}

/** GET /api/uploads — the signed-in user's uploads, newest first. */
export async function GET() {
  const user = await currentUser();
  if (!user) {
    return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  }

  const rows = await query<UploadRow>(
    `SELECT u.id, u.filename, u.size_bytes, u.status, u.total_lines,
            u.parsed_lines, u.malformed_lines, u.range_start, u.range_end,
            u.created_at,
            (SELECT count(*) FROM anomalies a WHERE a.upload_id = u.id) AS anomaly_count
       FROM uploads u
      WHERE u.user_id = $1
      ORDER BY u.created_at DESC
      LIMIT 100`,
    [user.id],
  );

  return NextResponse.json({
    uploads: rows.map((r) => ({
      id: r.id,
      filename: r.filename,
      sizeBytes: r.size_bytes,
      status: r.status,
      totalLines: r.total_lines,
      parsedLines: r.parsed_lines,
      malformedLines: r.malformed_lines,
      rangeStart: r.range_start,
      rangeEnd: r.range_end,
      createdAt: r.created_at,
      anomalyCount: Number(r.anomaly_count),
    })),
  });
}

/** POST /api/uploads — multipart form upload of a single log file. */
export async function POST(request: Request) {
  const user = await currentUser();
  if (!user) {
    return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
  }

  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    return NextResponse.json(
      { error: "Expected a multipart/form-data upload" },
      { status: 400 },
    );
  }

  const file = form.get("file");
  if (!(file instanceof File)) {
    return NextResponse.json(
      { error: "No file provided under the 'file' field" },
      { status: 400 },
    );
  }

  if (file.size === 0) {
    return NextResponse.json({ error: "The file is empty" }, { status: 400 });
  }
  if (file.size > MAX_BYTES) {
    return NextResponse.json(
      { error: `File exceeds the ${MAX_BYTES / 1024 / 1024} MB limit` },
      { status: 413 },
    );
  }

  const name = file.name.toLowerCase();
  if (!ALLOWED_EXTENSIONS.some((ext) => name.endsWith(ext))) {
    return NextResponse.json(
      { error: `Expected one of ${ALLOWED_EXTENSIONS.join(", ")}` },
      { status: 400 },
    );
  }

  const content = await file.text();

  try {
    const result = await ingestLogFile(user.id, file.name, content);
    return NextResponse.json(result, { status: 201 });
  } catch (err) {
    if (err instanceof IngestError) {
      return NextResponse.json({ error: err.message }, { status: 422 });
    }
    console.error("[upload] ingest failed:", err);
    return NextResponse.json(
      { error: "Failed to process the log file" },
      { status: 500 },
    );
  }
}
