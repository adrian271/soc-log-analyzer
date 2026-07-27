import Link from "next/link";
import { notFound, redirect } from "next/navigation";
import { currentUser } from "@/lib/auth";
import { query } from "@/lib/db";
import { formatBytes } from "@/lib/stats";
import { parseEvidence, parseUploadStats } from "@/lib/schemas";
import { AppHeader } from "@/components/AppHeader";
import { TimelineChart } from "@/components/TimelineChart";
import { AnomalyCard, type AnomalyView } from "@/components/AnomalyCard";
import { EventTable } from "@/components/EventTable";

interface UploadRow extends Record<string, unknown> {
  id: string;
  filename: string;
  parsed_lines: number;
  malformed_lines: number;
  range_start: Date | null;
  range_end: Date | null;
  /** Raw JSONB — validated through parseUploadStats before use, never cast. */
  stats: unknown;
  narrative: string | null;
  narrative_model: string | null;
}

interface AnomalyRow extends Record<string, unknown> {
  id: number;
  detector: string;
  title: string;
  severity: string;
  confidence: number;
  explanation: string;
  entity: string | null;
  first_seen: Date | null;
  last_seen: Date | null;
  event_count: number;
  /** Raw JSONB — validated through parseEvidence before use. */
  evidence: unknown;
}

export default async function ReportPage({
  params,
}: PageProps<"/uploads/[id]">) {
  const user = await currentUser();
  if (!user) redirect("/login");

  const { id } = await params;

  // Scoped by user_id: a valid session cannot read someone else's report.
  const rows = await query<UploadRow>(
    `SELECT id, filename, parsed_lines, malformed_lines, range_start, range_end,
            stats, narrative, narrative_model
       FROM uploads
      WHERE id = $1 AND user_id = $2`,
    [id, user.id],
  );
  if (rows.length === 0) notFound();

  const upload = rows[0];
  // Validated, not asserted. A stats blob that no longer matches the schema
  // parses to null, and the page renders without the aggregate sections rather
  // than throwing on first property access.
  const stats = parseUploadStats(upload.stats);

  const anomalyRows = await query<AnomalyRow>(
    `SELECT id, detector, title, severity, confidence, explanation, entity,
            first_seen, last_seen, event_count, evidence
       FROM anomalies
      WHERE upload_id = $1
      ORDER BY confidence DESC, id ASC`,
    [id],
  );

  const anomalies: AnomalyView[] = anomalyRows.map((a) => ({
    id: a.id,
    detector: a.detector,
    title: a.title,
    severity: a.severity,
    confidence: a.confidence,
    explanation: a.explanation,
    entity: a.entity,
    firstSeen: a.first_seen,
    lastSeen: a.last_seen,
    eventCount: a.event_count,
    evidence: parseEvidence(a.evidence),
  }));

  const critical = anomalies.filter((a) => a.severity === "critical").length;
  const high = anomalies.filter((a) => a.severity === "high").length;

  return (
    <>
      <AppHeader email={user.email} />

      <main className="flex-1 mx-auto w-full max-w-6xl px-4 py-8 space-y-8">
        <div>
          <Link
            href="/"
            className="text-xs text-[var(--text-secondary)] hover:underline"
          >
            ← All analyses
          </Link>
          <h1 className="mt-2 text-xl font-semibold tracking-tight break-all">
            {upload.filename}
          </h1>
          <p className="mt-1 text-sm text-[var(--text-secondary)] tabular">
            {upload.parsed_lines.toLocaleString()} events
            {upload.malformed_lines > 0 && (
              <> · {upload.malformed_lines.toLocaleString()} unparsable lines</>
            )}
            {upload.range_start && upload.range_end && (
              <>
                {" · "}
                {fmt(upload.range_start)} – {fmt(upload.range_end)} UTC
              </>
            )}
          </p>
        </div>

        {/* The brief: what an analyst reads first. */}
        {upload.narrative && (
          <section className="card p-5">
            <div className="flex items-baseline justify-between gap-4 mb-3">
              <h2 className="text-sm font-medium">Shift handover brief</h2>
              <span className="text-[10px] uppercase tracking-wide text-[var(--text-muted)]">
                {upload.narrative_model === "deterministic-fallback"
                  ? "rule-generated"
                  : `written by ${upload.narrative_model}`}
              </span>
            </div>
            <Markdownish text={upload.narrative} />
          </section>
        )}

        {stats && (
          <>
            <section>
              <h2 className="text-sm font-medium text-[var(--text-secondary)] mb-3">
                At a glance
              </h2>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                <Stat label="Events" value={stats.totalEvents.toLocaleString()} />
                <Stat label="Client IPs" value={String(stats.uniqueClientIps)} />
                <Stat label="Users" value={String(stats.uniqueUsers)} />
                <Stat label="Hosts" value={String(stats.uniqueHosts)} />
                <Stat
                  label="Blocked"
                  value={stats.blockedCount.toLocaleString()}
                  accent={stats.blockedCount > 0 ? "var(--status-warning)" : undefined}
                />
                <Stat
                  label="Threat hits"
                  value={stats.threatCount.toLocaleString()}
                  accent={stats.threatCount > 0 ? "var(--status-critical)" : undefined}
                />
              </div>
              <p className="mt-2 text-xs text-[var(--text-muted)] tabular">
                {formatBytes(stats.bytesSent)} uploaded ·{" "}
                {formatBytes(stats.bytesReceived)} downloaded
              </p>
            </section>

            <section className="card p-5">
              <h2 className="text-sm font-medium mb-1">Timeline of events</h2>
              <p className="text-xs text-[var(--text-muted)] mb-4">
                Volume per interval. Hover a column for the exact counts.
              </p>
              <TimelineChart buckets={stats.timeline} />
            </section>
          </>
        )}

        <section>
          <div className="flex items-baseline justify-between gap-4 mb-1">
            <h2 className="text-sm font-medium text-[var(--text-secondary)]">
              Findings
            </h2>
            <span className="text-xs text-[var(--text-muted)] tabular">
              {anomalies.length} total
              {critical > 0 && ` · ${critical} critical`}
              {high > 0 && ` · ${high} high`}
            </span>
          </div>
          <p className="text-xs text-[var(--text-muted)] mb-4">
            Ordered by confidence — highest first is triage order.
          </p>

          {anomalies.length === 0 ? (
            <div className="card p-8 text-center">
              <p className="text-sm text-[var(--status-good)]">
                ✓ No anomalies detected
              </p>
              <p className="mt-1 text-xs text-[var(--text-muted)]">
                Every detector ran and none fired on this file.
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {anomalies.map((a) => (
                <AnomalyCard key={a.id} anomaly={a} />
              ))}
            </div>
          )}
        </section>

        {stats && (
          <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <TopList title="Top hosts" items={stats.topHosts} />
            <TopList title="Top categories" items={stats.topCategories} />
            <TopList title="Busiest client IPs" items={stats.topClientIps} />
          </section>
        )}

        <section>
          <h2 className="text-sm font-medium text-[var(--text-secondary)] mb-1">
            Raw events
          </h2>
          <p className="text-xs text-[var(--text-muted)] mb-4">
            Rows that triggered a finding are highlighted and tagged with the
            detector responsible.
          </p>
          <EventTable uploadId={upload.id} />
        </section>
      </main>
    </>
  );
}

function Stat({
  label,
  value,
  accent,
}: {
  label: string;
  value: string;
  accent?: string;
}) {
  return (
    <div className="card px-3 py-2.5">
      <div
        className="text-xl font-semibold leading-tight"
        style={accent ? { color: accent } : undefined}
      >
        {value}
      </div>
      <div className="text-[11px] text-[var(--text-muted)] mt-0.5">{label}</div>
    </div>
  );
}

function TopList({
  title,
  items,
}: {
  title: string;
  items: { key: string; count: number }[];
}) {
  const max = Math.max(1, ...items.map((i) => i.count));
  return (
    <div className="card p-4">
      <h3 className="text-xs font-medium text-[var(--text-secondary)] mb-3">
        {title}
      </h3>
      {items.length === 0 ? (
        <p className="text-xs text-[var(--text-muted)]">No data.</p>
      ) : (
        <ul className="space-y-1.5">
          {items.slice(0, 8).map((i) => (
            <li key={i.key} className="text-xs">
              <div className="flex justify-between gap-3">
                <span className="truncate" title={i.key}>
                  {i.key}
                </span>
                <span className="tabular text-[var(--text-muted)] shrink-0">
                  {i.count.toLocaleString()}
                </span>
              </div>
              <div className="mt-1 h-0.5 rounded-full bg-[var(--surface-2)]">
                <div
                  className="h-full rounded-full"
                  style={{
                    width: `${(i.count / max) * 100}%`,
                    background: "var(--series-1)",
                  }}
                />
              </div>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/**
 * Minimal Markdown rendering for the brief — headings, bullets, `code` and
 * **bold** only.
 *
 * Deliberately not a full Markdown library: the text may come from a model, so
 * rendering it as a small, closed set of elements (rather than raw HTML) means
 * nothing in that string can inject markup into the page.
 */
function Markdownish({ text }: { text: string }) {
  const lines = text.split("\n");

  return (
    <div className="space-y-2 text-sm leading-relaxed text-[var(--text-secondary)]">
      {lines.map((line, i) => {
        const trimmed = line.trim();
        if (trimmed === "") return null;

        if (trimmed.startsWith("## ")) {
          return (
            <h3
              key={i}
              className="text-xs font-semibold uppercase tracking-wide text-[var(--text-muted)] pt-2"
            >
              {trimmed.slice(3)}
            </h3>
          );
        }
        if (trimmed.startsWith("# ")) {
          return (
            <h3 key={i} className="font-medium text-[var(--text-primary)]">
              {trimmed.slice(2)}
            </h3>
          );
        }
        if (/^[-*] /.test(trimmed)) {
          return (
            <p key={i} className="pl-4 -indent-4">
              <span aria-hidden>• </span>
              <Inline text={trimmed.slice(2)} />
            </p>
          );
        }
        if (/^\d+\.\s/.test(trimmed)) {
          const [, num, rest] = /^(\d+)\.\s(.*)$/.exec(trimmed)!;
          return (
            <p key={i} className="pl-5 -indent-5">
              <span className="tabular">{num}. </span>
              <Inline text={rest} />
            </p>
          );
        }
        return (
          <p key={i}>
            <Inline text={trimmed} />
          </p>
        );
      })}
    </div>
  );
}

/** Splits on **bold** and `code` runs; everything else stays plain text. */
function Inline({ text }: { text: string }) {
  const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
  return (
    <>
      {parts.map((part, i) => {
        if (part.startsWith("**") && part.endsWith("**")) {
          return (
            <strong key={i} className="text-[var(--text-primary)] font-semibold">
              {part.slice(2, -2)}
            </strong>
          );
        }
        if (part.startsWith("`") && part.endsWith("`")) {
          return (
            <code
              key={i}
              className="bg-[var(--surface-2)] px-1 py-0.5 rounded text-[0.9em]"
            >
              {part.slice(1, -1)}
            </code>
          );
        }
        return <span key={i}>{part}</span>;
      })}
    </>
  );
}

function fmt(d: Date | string): string {
  return new Date(d).toISOString().replace("T", " ").slice(0, 16);
}
