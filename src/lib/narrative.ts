import Anthropic from "@anthropic-ai/sdk";
import { query } from "./db";
import { formatBytes } from "./stats";
import type { Anomaly, UploadStats } from "./types";

/**
 * The one place an LLM is used in this application.
 *
 * ## What the model does
 * It writes the analyst-facing *shift handover brief* — the paragraph at the
 * top of the report that says, in plain English, what happened in this log and
 * what to look at first.
 *
 * ## What the model does NOT do
 * It does not detect anything, and it cannot change a score. Detection,
 * severity, and confidence are all produced deterministically in
 * `src/lib/detectors.ts` before this runs. That separation is deliberate:
 *
 *  - a SOC analyst must be able to ask "why did this fire?" and get a numeric
 *    answer they can re-derive from the log themselves;
 *  - findings stay identical across runs, which makes them testable
 *    (see tests/detectors.test.ts);
 *  - an LLM that hallucinates prose is a cosmetic problem, whereas an LLM that
 *    hallucinates a severity score is a security problem.
 *
 * ## What it is given
 * Only the aggregate statistics and the finished findings — never raw log
 * lines. That keeps the prompt small and bounded regardless of file size, and
 * avoids shipping the full contents of a customer's proxy log to a third party.
 *
 * ## When it is skipped
 * The narrative is optional by design. With no ANTHROPIC_API_KEY set, on an API
 * error, or if the model declines the request, the app falls back to
 * `deterministicBrief()` below and everything else still works.
 */

const MODEL = "claude-opus-5";

const SYSTEM_PROMPT = `You are a senior SOC analyst writing the handover brief that starts the next shift.

You will be given the aggregate statistics for one proxy log file and a list of findings that a deterministic detection engine has already produced. Each finding already has a severity and a confidence score.

Write the brief in Markdown. Requirements:
- Open with one sentence stating the overall assessment: is this log clean, suspicious, or does it show active compromise?
- Then a short "What happened" section narrating the events in time order, naming the specific hosts, IPs and users involved.
- Then a "Start here" section: an ordered list of the concrete next investigative steps, most urgent first.
- Where several findings involve the same IP or user, say so explicitly — correlating them is the most useful thing you can add.
- Be specific and quantitative. Use the numbers you were given.
- Keep it under 350 words. An analyst reads this in under a minute.

Hard rules:
- Do NOT invent findings, hosts, IPs, users, or numbers that are not in the input.
- Do NOT change or restate any severity or confidence value incorrectly; the numbers given are authoritative.
- If the findings list is empty, say plainly that nothing of concern was detected and keep it to two sentences.`;

interface TimeRange {
  start: Date;
  end: Date;
}

/** Compact, bounded prompt input. Raw log lines are deliberately excluded. */
function buildPromptPayload(
  stats: UploadStats,
  anomalies: Anomaly[],
  range: TimeRange,
) {
  return {
    timeRange: { from: range.start.toISOString(), to: range.end.toISOString() },
    totals: {
      events: stats.totalEvents,
      uniqueClientIps: stats.uniqueClientIps,
      uniqueUsers: stats.uniqueUsers,
      uniqueHosts: stats.uniqueHosts,
      blocked: stats.blockedCount,
      threatHits: stats.threatCount,
      bytesUploaded: stats.bytesSent,
      bytesDownloaded: stats.bytesReceived,
    },
    topHosts: stats.topHosts.slice(0, 5),
    topCategories: stats.topCategories.slice(0, 5),
    findings: anomalies.map((a) => ({
      detector: a.detector,
      title: a.title,
      severity: a.severity,
      confidence: Number(a.confidence.toFixed(2)),
      entity: a.entity,
      firstSeen: a.firstSeen?.toISOString() ?? null,
      lastSeen: a.lastSeen?.toISOString() ?? null,
      eventCount: a.eventCount,
      explanation: a.explanation,
      evidence: a.evidence,
    })),
  };
}

/**
 * Writes the brief onto the upload row. Never throws in a way that would fail
 * the upload — the caller treats this as best-effort.
 */
export async function writeNarrative(
  uploadId: string,
  stats: UploadStats,
  anomalies: Anomaly[],
  range: TimeRange,
): Promise<void> {
  let text = deterministicBrief(stats, anomalies, range);
  let model = "deterministic-fallback";

  if (process.env.ANTHROPIC_API_KEY) {
    try {
      const client = new Anthropic();
      const payload = buildPromptPayload(stats, anomalies, range);

      const response = await client.messages.create({
        model: MODEL,
        max_tokens: 4000,
        // Low effort: this is a summarisation task over already-structured
        // input, not a reasoning problem. Keeps latency and cost down.
        output_config: { effort: "low" },
        system: SYSTEM_PROMPT,
        messages: [
          {
            role: "user",
            content: `Here is the analysis of one uploaded proxy log file. Write the shift handover brief.\n\n${JSON.stringify(payload, null, 2)}`,
          },
        ],
      });

      // Log analysis is security-adjacent, so a safety refusal is a real
      // possibility. It arrives as a normal 200 with an empty/partial body —
      // check stop_reason before reading content.
      if (response.stop_reason === "refusal") {
        console.warn(
          `[narrative] model declined for upload ${uploadId}; using deterministic brief`,
        );
      } else {
        const written = response.content
          .filter((b) => b.type === "text")
          .map((b) => b.text)
          .join("")
          .trim();
        if (written.length > 0) {
          text = written;
          model = response.model;
        }
      }
    } catch (err) {
      // Network error, bad key, rate limit — fall back rather than fail.
      console.warn(
        `[narrative] generation failed for upload ${uploadId}:`,
        err instanceof Error ? err.message : err,
      );
    }
  }

  await query(
    "UPDATE uploads SET narrative = $1, narrative_model = $2 WHERE id = $3",
    [text, model, uploadId],
  );
}

/**
 * The no-LLM path: a readable brief assembled from the same findings.
 *
 * It is plainer than the model's prose, but it is always available, costs
 * nothing, and never invents anything — so the product is fully usable with no
 * API key configured at all.
 */
export function deterministicBrief(
  stats: UploadStats,
  anomalies: Anomaly[],
  range: TimeRange,
): string {
  const window = `${range.start.toISOString().replace("T", " ").slice(0, 16)} – ${range.end
    .toISOString()
    .replace("T", " ")
    .slice(0, 16)} UTC`;

  if (anomalies.length === 0) {
    return (
      `**No findings.** ${stats.totalEvents.toLocaleString()} events from ` +
      `${stats.uniqueClientIps} client IPs over ${window} produced no anomalies. ` +
      `${stats.blockedCount.toLocaleString()} request(s) were blocked by policy.`
    );
  }

  const critical = anomalies.filter((a) => a.severity === "critical");
  const high = anomalies.filter((a) => a.severity === "high");
  const headline =
    critical.length > 0
      ? `**Active compromise indicators present.** ${critical.length} critical and ${high.length} high-severity finding(s) require immediate attention.`
      : high.length > 0
        ? `**Suspicious activity detected.** ${high.length} high-severity finding(s) warrant investigation.`
        : `**Low-severity findings only.** Nothing here indicates active compromise, but ${anomalies.length} item(s) are worth a look.`;

  // Correlating findings by entity is the single most useful thing to surface.
  const byEntity = new Map<string, Anomaly[]>();
  for (const a of anomalies) {
    if (!a.entity) continue;
    const list = byEntity.get(a.entity);
    if (list) list.push(a);
    else byEntity.set(a.entity, [a]);
  }
  const multi = [...byEntity.entries()].filter(([, list]) => list.length > 1);

  const lines: string[] = [
    headline,
    "",
    "## What happened",
    "",
    `Across ${window}, ${stats.totalEvents.toLocaleString()} proxy events were recorded from ` +
      `${stats.uniqueClientIps} client IPs and ${stats.uniqueUsers} users, reaching ${stats.uniqueHosts} distinct hosts. ` +
      `${stats.blockedCount.toLocaleString()} request(s) were blocked and ${stats.threatCount.toLocaleString()} carried a named threat. ` +
      `${formatBytes(stats.bytesSent)} was uploaded and ${formatBytes(stats.bytesReceived)} downloaded.`,
    "",
  ];

  if (multi.length > 0) {
    lines.push("**Correlated entities** — the same host or user appears in several findings:", "");
    for (const [entity, list] of multi) {
      lines.push(
        `- \`${entity}\` — ${list.map((a) => a.detector).join(", ")} (${list.length} findings)`,
      );
    }
    lines.push("");
  }

  lines.push("## Start here", "");
  anomalies.slice(0, 6).forEach((a, i) => {
    lines.push(
      `${i + 1}. **${a.title}** — ${a.severity}, confidence ${(a.confidence * 100).toFixed(0)}%. ${a.explanation.split(". ")[0]}.`,
    );
  });

  if (anomalies.length > 6) {
    lines.push("", `${anomalies.length - 6} further finding(s) are listed below.`);
  }

  return lines.join("\n");
}
