"use client";

import { useId, useState } from "react";
import type { TimelineBucket } from "@/lib/types";

/**
 * Stacked column chart of event volume over the log's time range, split into
 * normal vs anomalous traffic.
 *
 * Hand-rolled SVG rather than a charting library: it is ~100 lines, has no
 * dependency, and lets the marks follow the spec exactly (thin columns, a 2px
 * surface gap between stacked segments so the split reads even at small sizes,
 * rounded data-ends, recessive gridlines, hover tooltip).
 *
 * Colours: two validated series hues. Identity is never carried by colour
 * alone — there is a legend, and the tooltip names each value.
 */

const HEIGHT = 190;
const PAD_TOP = 12;
const PAD_BOTTOM = 26;
const PAD_LEFT = 40;
const PAD_RIGHT = 8;
const SEGMENT_GAP = 2;

interface Props {
  buckets: TimelineBucket[];
}

export function TimelineChart({ buckets }: Props) {
  const clipId = useId();
  const [hover, setHover] = useState<number | null>(null);

  if (buckets.length === 0) {
    return (
      <p className="text-sm text-[var(--text-muted)]">
        No events to plot.
      </p>
    );
  }

  const width = 900;
  const plotW = width - PAD_LEFT - PAD_RIGHT;
  const plotH = HEIGHT - PAD_TOP - PAD_BOTTOM;
  const slot = plotW / buckets.length;
  const barW = Math.max(1, slot - 1.5);

  const max = Math.max(...buckets.map((b) => b.total), 1);
  // Round the axis top to something readable rather than the raw max.
  const step = niceStep(max);
  const axisMax = Math.ceil(max / step) * step;
  const ticks: number[] = [];
  for (let v = 0; v <= axisMax; v += step) ticks.push(v);

  const y = (v: number) => PAD_TOP + plotH - (v / axisMax) * plotH;

  const active = hover === null ? null : buckets[hover];

  return (
    <div className="relative">
      <div className="flex items-center gap-4 mb-3 text-xs text-[var(--text-secondary)]">
        <LegendSwatch color="var(--series-1)" label="Normal" />
        <LegendSwatch color="var(--series-anomalous)" label="Anomalous" />
      </div>

      <svg
        viewBox={`0 0 ${width} ${HEIGHT}`}
        className="w-full h-auto"
        role="img"
        aria-label={`Event volume over time across ${buckets.length} intervals, split into normal and anomalous traffic.`}
        onMouseLeave={() => setHover(null)}
      >
        <defs>
          <clipPath id={clipId}>
            <rect x={PAD_LEFT} y={0} width={plotW} height={HEIGHT} />
          </clipPath>
        </defs>

        {/* Recessive gridlines and value axis */}
        {ticks.map((t) => (
          <g key={t}>
            <line
              x1={PAD_LEFT}
              x2={width - PAD_RIGHT}
              y1={y(t)}
              y2={y(t)}
              stroke="var(--grid)"
              strokeWidth={1}
            />
            <text
              x={PAD_LEFT - 8}
              y={y(t) + 3.5}
              textAnchor="end"
              className="tabular"
              fontSize={10}
              fill="var(--text-muted)"
            >
              {t}
            </text>
          </g>
        ))}

        <g clipPath={`url(#${clipId})`}>
          {buckets.map((b, i) => {
            const x = PAD_LEFT + i * slot;
            const normal = b.total - b.anomalous;

            // Heights in pixels, then a 2px surface gap carved out between the
            // two stacked segments when both are present.
            const totalH = (b.total / axisMax) * plotH;
            const anomH = (b.anomalous / axisMax) * plotH;
            const bothPresent = b.anomalous > 0 && normal > 0;
            const normalH = Math.max(
              0,
              totalH - anomH - (bothPresent ? SEGMENT_GAP : 0),
            );

            return (
              <g
                key={b.start}
                onMouseEnter={() => setHover(i)}
                style={{ cursor: "default" }}
              >
                {/* Generous invisible hit target — bigger than the mark. */}
                <rect
                  x={x}
                  y={PAD_TOP}
                  width={Math.max(slot, 3)}
                  height={plotH}
                  fill={hover === i ? "var(--surface-2)" : "transparent"}
                />
                {normal > 0 && (
                  <rect
                    x={x}
                    y={PAD_TOP + plotH - normalH}
                    width={barW}
                    height={normalH}
                    rx={Math.min(2, barW / 2)}
                    fill="var(--series-1)"
                  />
                )}
                {b.anomalous > 0 && (
                  <rect
                    x={x}
                    y={PAD_TOP + plotH - totalH}
                    width={barW}
                    height={Math.max(1.5, anomH)}
                    rx={Math.min(2, barW / 2)}
                    fill="var(--series-anomalous)"
                  />
                )}
              </g>
            );
          })}
        </g>

        {/* Baseline */}
        <line
          x1={PAD_LEFT}
          x2={width - PAD_RIGHT}
          y1={y(0)}
          y2={y(0)}
          stroke="var(--axis)"
          strokeWidth={1}
        />

        {/* Only the endpoints are labelled — a tick per column would be noise. */}
        <text
          x={PAD_LEFT}
          y={HEIGHT - 8}
          fontSize={10}
          fill="var(--text-muted)"
          className="tabular"
        >
          {shortTime(buckets[0].start)}
        </text>
        <text
          x={width - PAD_RIGHT}
          y={HEIGHT - 8}
          textAnchor="end"
          fontSize={10}
          fill="var(--text-muted)"
          className="tabular"
        >
          {shortTime(buckets[buckets.length - 1].start)}
        </text>
      </svg>

      {active && (
        <div className="mt-2 text-xs text-[var(--text-secondary)] tabular">
          <span className="text-[var(--text-primary)] font-medium">
            {new Date(active.start).toISOString().replace("T", " ").slice(0, 19)}{" "}
            UTC
          </span>
          {" — "}
          {active.total} events
          {active.anomalous > 0 && (
            <>
              {", "}
              <span className="text-[var(--status-critical)]">
                {active.anomalous} anomalous
              </span>
            </>
          )}
          {active.blocked > 0 && <>{`, ${active.blocked} blocked`}</>}
        </div>
      )}
    </div>
  );
}

function LegendSwatch({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span
        aria-hidden
        className="inline-block h-2.5 w-2.5 rounded-sm"
        style={{ background: color }}
      />
      {label}
    </span>
  );
}

/** 1 / 2 / 5 × 10ⁿ so axis labels land on readable numbers. */
function niceStep(max: number): number {
  const target = max / 4;
  const mag = Math.pow(10, Math.floor(Math.log10(Math.max(1, target))));
  for (const m of [1, 2, 5, 10]) {
    if (mag * m >= target) return mag * m;
  }
  return mag * 10;
}

function shortTime(iso: string): string {
  return new Date(iso).toISOString().slice(5, 16).replace("T", " ");
}
