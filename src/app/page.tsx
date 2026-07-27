import Link from "next/link";
import { redirect } from "next/navigation";
import { currentUser } from "@/lib/auth";
import { query } from "@/lib/db";
import { AppHeader } from "@/components/AppHeader";
import { UploadPanel } from "@/components/UploadPanel";

interface Row extends Record<string, unknown> {
  id: string;
  filename: string;
  parsed_lines: number;
  malformed_lines: number;
  range_start: Date | null;
  range_end: Date | null;
  created_at: Date;
  anomaly_count: string;
  critical_count: string;
}

export default async function DashboardPage() {
  // The proxy already redirects unauthenticated browsers; this is the
  // authoritative check, and it also gives us the user record.
  const user = await currentUser();
  if (!user) redirect("/login");

  const uploads = await query<Row>(
    `SELECT u.id, u.filename, u.parsed_lines, u.malformed_lines,
            u.range_start, u.range_end, u.created_at,
            (SELECT count(*) FROM anomalies a WHERE a.upload_id = u.id) AS anomaly_count,
            (SELECT count(*) FROM anomalies a
              WHERE a.upload_id = u.id AND a.severity = 'critical') AS critical_count
       FROM uploads u
      WHERE u.user_id = $1
      ORDER BY u.created_at DESC
      LIMIT 50`,
    [user.id],
  );

  return (
    <>
      <AppHeader email={user.email} />

      <main className="flex-1 mx-auto w-full max-w-6xl px-4 py-8 space-y-8">
        <section>
          <h1 className="text-xl font-semibold tracking-tight">
            Analyse a log file
          </h1>
          <p className="mt-1 mb-4 text-sm text-[var(--text-secondary)]">
            Parsing, detection and scoring all run on upload.
          </p>
          <UploadPanel />
        </section>

        <section>
          <h2 className="text-sm font-medium text-[var(--text-secondary)] mb-3">
            Previous analyses
          </h2>

          {uploads.length === 0 ? (
            <div className="card p-8 text-center text-sm text-[var(--text-muted)]">
              Nothing analysed yet. Try{" "}
              <code className="text-[var(--text-secondary)]">
                examples/zscaler-sample.log
              </code>{" "}
              from the repository.
            </div>
          ) : (
            <ul className="space-y-2">
              {uploads.map((u) => {
                const anomalies = Number(u.anomaly_count);
                const critical = Number(u.critical_count);
                return (
                  <li key={u.id}>
                    <Link
                      href={`/uploads/${u.id}`}
                      className="card px-4 py-3 flex items-center justify-between gap-4 hover:bg-[var(--surface-2)] transition-colors"
                    >
                      <div className="min-w-0">
                        <p className="font-medium truncate">{u.filename}</p>
                        <p className="text-xs text-[var(--text-muted)] tabular mt-0.5">
                          {u.parsed_lines.toLocaleString()} events
                          {u.malformed_lines > 0 &&
                            ` · ${u.malformed_lines} unparsed`}
                          {u.range_start &&
                            ` · ${new Date(u.range_start).toISOString().slice(0, 10)}`}
                        </p>
                      </div>

                      <div className="shrink-0 text-right">
                        {anomalies === 0 ? (
                          <span className="text-xs text-[var(--status-good)]">
                            ✓ Clean
                          </span>
                        ) : (
                          <span className="text-xs">
                            <span className="tabular font-medium">
                              {anomalies}
                            </span>{" "}
                            finding{anomalies === 1 ? "" : "s"}
                            {critical > 0 && (
                              <span className="text-[var(--status-critical)]">
                                {" "}
                                · {critical} critical
                              </span>
                            )}
                          </span>
                        )}
                      </div>
                    </Link>
                  </li>
                );
              })}
            </ul>
          )}
        </section>
      </main>
    </>
  );
}
