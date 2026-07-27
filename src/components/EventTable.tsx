"use client";

import { useCallback, useEffect, useState } from "react";

interface EventRow {
  lineNo: number;
  ts: string;
  username: string | null;
  clientIp: string | null;
  host: string | null;
  url: string | null;
  method: string | null;
  statusCode: number | null;
  action: string | null;
  category: string | null;
  threatName: string | null;
  bytesSent: number | null;
  bytesReceived: number | null;
  detectors: string[];
}

const PAGE_SIZE = 50;

/**
 * The raw event view, fed by GET /api/uploads/:id/events.
 *
 * Rows implicated in a finding are highlighted and tagged with the detector
 * that flagged them, so an analyst can go from "there is a beacon" to "these
 * are the actual requests" without leaving the page.
 */
export function EventTable({ uploadId }: { uploadId: string }) {
  const [rows, setRows] = useState<EventRow[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [search, setSearch] = useState("");
  const [anomalousOnly, setAnomalousOnly] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = new URLSearchParams({
        limit: String(PAGE_SIZE),
        offset: String(offset),
      });
      if (search.trim()) params.set("q", search.trim());
      if (anomalousOnly) params.set("anomalousOnly", "true");

      const res = await fetch(`/api/uploads/${uploadId}/events?${params}`);
      if (!res.ok) throw new Error(`Request failed (${res.status})`);
      const body = await res.json();
      setRows(body.events);
      setTotal(body.total);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load events");
    } finally {
      setLoading(false);
    }
  }, [uploadId, offset, search, anomalousOnly]);

  // Debounce so typing in the search box doesn't fire a request per keystroke.
  useEffect(() => {
    const t = setTimeout(load, 250);
    return () => clearTimeout(t);
  }, [load]);

  const page = Math.floor(offset / PAGE_SIZE) + 1;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <section>
      {/* Filters sit in one row above the table. */}
      <div className="flex flex-wrap items-center gap-3 mb-3">
        <input
          type="search"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setOffset(0);
          }}
          placeholder="Filter by host, URL, user, IP, threat…"
          aria-label="Filter events"
          className="flex-1 min-w-56 rounded-md border border-[var(--border)] bg-[var(--surface)] px-3 py-1.5 text-sm outline-none focus:border-[var(--series-1)]"
        />
        <label className="flex items-center gap-2 text-sm text-[var(--text-secondary)] select-none">
          <input
            type="checkbox"
            checked={anomalousOnly}
            onChange={(e) => {
              setAnomalousOnly(e.target.checked);
              setOffset(0);
            }}
          />
          Flagged rows only
        </label>
        <span className="text-xs text-[var(--text-muted)] tabular">
          {total.toLocaleString()} event{total === 1 ? "" : "s"}
        </span>
      </div>

      {error && (
        <p role="alert" className="text-sm text-[var(--status-critical)] mb-3">
          ⚠ {error}
        </p>
      )}

      <div className="card overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="text-[var(--text-muted)] border-b border-[var(--border)]">
            <tr>
              <Th>Time (UTC)</Th>
              <Th>Client</Th>
              <Th>User</Th>
              <Th>Host</Th>
              <Th>Method</Th>
              <Th>Status</Th>
              <Th>Action</Th>
              <Th>Sent</Th>
              <Th>Flagged by</Th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => {
              const flagged = r.detectors.length > 0;
              return (
                <tr
                  key={r.lineNo}
                  className="border-b border-[var(--border)] last:border-0"
                  style={
                    flagged
                      ? { background: "color-mix(in srgb, var(--status-critical) 8%, transparent)" }
                      : undefined
                  }
                >
                  <Td mono>{r.ts.replace("T", " ").slice(0, 19)}</Td>
                  <Td mono>{r.clientIp ?? "—"}</Td>
                  <Td>{r.username ?? "—"}</Td>
                  <Td title={r.url ?? undefined}>{r.host ?? "—"}</Td>
                  <Td>{r.method ?? "—"}</Td>
                  <Td mono>{r.statusCode ?? "—"}</Td>
                  <Td>
                    {r.action === "Blocked" ? (
                      <span className="text-[var(--status-critical)]">
                        ⨯ Blocked
                      </span>
                    ) : (
                      (r.action ?? "—")
                    )}
                  </Td>
                  <Td mono>{formatBytesShort(r.bytesSent)}</Td>
                  <Td>
                    {flagged ? (
                      <span className="flex flex-wrap gap-1">
                        {r.detectors.map((d) => (
                          <code
                            key={d}
                            className="bg-[var(--surface-2)] px-1 py-0.5 rounded text-[10px]"
                          >
                            {d}
                          </code>
                        ))}
                      </span>
                    ) : (
                      "—"
                    )}
                  </Td>
                </tr>
              );
            })}

            {rows.length === 0 && !loading && (
              <tr>
                <td
                  colSpan={9}
                  className="px-3 py-8 text-center text-[var(--text-muted)]"
                >
                  No events match these filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between mt-3 text-xs text-[var(--text-secondary)]">
        <span className="tabular">
          {loading ? "Loading…" : `Page ${page} of ${pages}`}
        </span>
        <div className="flex gap-2">
          <PagerButton
            disabled={offset === 0 || loading}
            onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
          >
            ← Previous
          </PagerButton>
          <PagerButton
            disabled={offset + PAGE_SIZE >= total || loading}
            onClick={() => setOffset(offset + PAGE_SIZE)}
          >
            Next →
          </PagerButton>
        </div>
      </div>
    </section>
  );
}

function Th({ children }: { children: React.ReactNode }) {
  return <th className="px-3 py-2 font-medium whitespace-nowrap">{children}</th>;
}

function Td({
  children,
  mono,
  title,
}: {
  children: React.ReactNode;
  mono?: boolean;
  title?: string;
}) {
  return (
    <td
      title={title}
      className={`px-3 py-1.5 whitespace-nowrap max-w-64 truncate ${mono ? "tabular" : ""}`}
    >
      {children}
    </td>
  );
}

function PagerButton({
  children,
  disabled,
  onClick,
}: {
  children: React.ReactNode;
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="rounded-md border border-[var(--border)] px-2.5 py-1 disabled:opacity-40 hover:bg-[var(--surface-2)]"
    >
      {children}
    </button>
  );
}

function formatBytesShort(n: number | null): string {
  if (n === null) return "—";
  if (n < 1024) return `${n}`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(0)}K`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)}M`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)}G`;
}
