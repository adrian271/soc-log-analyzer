import type { Severity } from "@/lib/types";

export interface AnomalyView {
  id: number;
  detector: string;
  title: string;
  severity: string;
  confidence: number;
  explanation: string;
  entity: string | null;
  firstSeen: string | Date | null;
  lastSeen: string | Date | null;
  eventCount: number;
  evidence: Record<string, unknown> | null;
}

/**
 * Status colours are never the only signal: each severity ships with a glyph
 * and the word itself, so the badge is readable in greyscale and to a
 * colourblind analyst.
 */
const SEVERITY: Record<Severity, { glyph: string; color: string; label: string }> = {
  critical: { glyph: "◆", color: "var(--status-critical)", label: "Critical" },
  high: { glyph: "▲", color: "var(--status-serious)", label: "High" },
  medium: { glyph: "●", color: "var(--status-warning)", label: "Medium" },
  low: { glyph: "▪", color: "var(--text-muted)", label: "Low" },
};

export function AnomalyCard({ anomaly }: { anomaly: AnomalyView }) {
  const sev = SEVERITY[anomaly.severity as Severity] ?? SEVERITY.low;
  const pct = Math.round(anomaly.confidence * 100);

  return (
    <article className="card p-4">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span
              className="inline-flex items-center gap-1 text-xs font-medium"
              style={{ color: sev.color }}
            >
              <span aria-hidden>{sev.glyph}</span>
              {sev.label}
            </span>
            <code className="text-[11px] text-[var(--text-muted)] bg-[var(--surface-2)] px-1.5 py-0.5 rounded">
              {anomaly.detector}
            </code>
          </div>
          <h3 className="mt-1.5 font-medium leading-snug break-words">
            {anomaly.title}
          </h3>
        </div>

        <ConfidenceMeter value={pct} />
      </div>

      <p className="mt-3 text-sm leading-relaxed text-[var(--text-secondary)]">
        {anomaly.explanation}
      </p>

      <dl className="mt-3 flex flex-wrap gap-x-6 gap-y-1 text-xs text-[var(--text-muted)]">
        <Meta label="Events" value={String(anomaly.eventCount)} />
        {anomaly.entity && <Meta label="Entity" value={anomaly.entity} />}
        {anomaly.firstSeen && (
          <Meta label="First seen" value={hhmmss(anomaly.firstSeen)} />
        )}
        {anomaly.lastSeen && (
          <Meta label="Last seen" value={hhmmss(anomaly.lastSeen)} />
        )}
      </dl>

      {anomaly.evidence && Object.keys(anomaly.evidence).length > 0 && (
        <details className="mt-3">
          <summary className="text-xs text-[var(--text-secondary)] cursor-pointer select-none">
            Evidence
          </summary>
          <pre className="mt-2 text-[11px] leading-relaxed overflow-x-auto bg-[var(--surface-2)] rounded-md p-3 text-[var(--text-secondary)]">
            {JSON.stringify(anomaly.evidence, null, 2)}
          </pre>
        </details>
      )}
    </article>
  );
}

/**
 * The confidence score, as a number plus a bar. The number is authoritative;
 * the bar just makes scanning a list of findings faster.
 */
function ConfidenceMeter({ value }: { value: number }) {
  return (
    <div className="shrink-0 text-right">
      <div className="text-lg font-semibold tabular leading-none">{value}%</div>
      <div className="text-[10px] uppercase tracking-wide text-[var(--text-muted)] mt-0.5">
        confidence
      </div>
      <div
        className="mt-1.5 h-1 w-20 rounded-full overflow-hidden bg-[var(--surface-2)]"
        role="meter"
        aria-valuenow={value}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label="Detector confidence"
      >
        <div
          className="h-full rounded-full"
          style={{ width: `${value}%`, background: "var(--series-1)" }}
        />
      </div>
    </div>
  );
}

function Meta({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-1.5">
      <dt>{label}:</dt>
      <dd className="text-[var(--text-secondary)] tabular break-all">{value}</dd>
    </div>
  );
}

function hhmmss(v: string | Date): string {
  return new Date(v).toISOString().slice(11, 19);
}
