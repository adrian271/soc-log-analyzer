import Anthropic from "@anthropic-ai/sdk";
import { zodOutputFormat } from "@anthropic-ai/sdk/helpers/zod";
import { z } from "zod";
import { groupBy, topN } from "./stats";
import type { Anomaly, LogEvent } from "./types";

/**
 * The second detection layer: model-based hunting for patterns nobody encoded.
 *
 * ## Why this exists
 * The eight detectors in `detectors.ts` are excellent at what they were written
 * for and structurally blind to everything else. They catch beaconing because
 * someone thought to measure inter-arrival regularity. They will never catch a
 * pattern nobody anticipated — that is the honest limitation of a rules engine.
 *
 * So this layer runs *after* them, over the events they did **not** flag, and
 * asks a model to look for anything odd in the residue.
 *
 * ## Why its output is treated differently
 * These findings are a different kind of claim to a deterministic one, and the
 * product never lets you confuse the two:
 *
 *  - **Confidence is capped at 0.60.** A deterministic finding's score is a
 *    measurement that can be re-derived from the log. This one is a model's
 *    opinion, and it should never outrank a measurement.
 *  - **They are labelled `model-proposed, unverified`** and rendered in their
 *    own section of the report, never mixed into the ranked findings list.
 *  - **They never suppress or modify a deterministic finding.** This layer is
 *    strictly additive.
 *  - **Output is schema-constrained** (structured outputs), so a malformed
 *    response is impossible rather than merely unlikely.
 *
 * ## What the model is given
 * Aggregate rollups of the residue plus a bounded, field-reduced sample of at
 * most SAMPLE_SIZE rows — never the whole file. The payload is roughly the same
 * size for a 4 MB upload as for a 600 KB one.
 */

/** Hard ceiling on any model-proposed confidence. See the note above. */
export const MAX_MODEL_CONFIDENCE = 0.6;

/** Rows of residue shown to the model. Bounds both cost and prompt size. */
const SAMPLE_SIZE = 120;

/** Refuse to bother the model for a handful of events. */
const MIN_RESIDUE = 40;

const MODEL = "claude-opus-5";

const FindingSchema = z.object({
  title: z
    .string()
    .describe("Short specific headline, naming the host, IP or user involved."),
  explanation: z
    .string()
    .describe(
      "2-4 sentences: what the pattern is, which observations support it, and what would confirm or rule it out.",
    ),
  entity: z
    .string()
    .describe("The single client IP, username or hostname this is about."),
  entityKind: z.enum(["client_ip", "username", "host"]),
  confidence: z
    .number()
    .describe("0 to 1. Be conservative; most log traffic is benign."),
  lineNos: z
    .array(z.number())
    .describe("Line numbers from the sample that support this. May be empty."),
});

const ResponseSchema = z.object({
  findings: z
    .array(FindingSchema)
    .describe("Anything genuinely anomalous. Return an empty array if nothing is."),
});

const SYSTEM_PROMPT = `You are a threat-detection analyst reviewing web proxy traffic that a deterministic rules engine has ALREADY screened.

Everything obvious has been removed before you see it. The rules engine already detects: named malware and phishing signatures, request-rate spikes, regular-interval C2 beaconing, bulk data uploads, authentication-failure bursts, algorithmically-generated domains, off-hours activity, and attack-tool user agents. Do NOT report those categories — they are handled, and re-reporting them is noise.

Your job is what a rules engine structurally cannot do: notice patterns nobody wrote a rule for. Things worth looking for include, but are not limited to:
- A host or user whose behaviour is internally inconsistent (a browser user-agent making machine-like requests, a workstation acting like a server)
- Traffic to destinations that don't fit the organisation's profile
- Sequences that only look wrong in combination — a category, a timing and a volume that are each unremarkable alone
- Small, quiet, repeated behaviour that stays under every threshold
- Anything that simply doesn't belong in a corporate browsing pattern

Rules you must follow:
- Report only what the data you were given supports. Never invent a hostname, IP, user or number that is not present.
- Be conservative with confidence. Most proxy traffic is benign, and a false positive costs an analyst real time. Above 0.5 means you would genuinely escalate this.
- If nothing in the residue is anomalous, return an empty findings array. That is a correct and useful answer, and a much better one than a speculative finding.
- Do not repeat a category the rules engine already covers.`;

/**
 * The events the deterministic layer left untouched — the only thing the model
 * ever sees. Exported so the boundary is directly testable.
 */
export function computeResidue(
  events: LogEvent[],
  deterministic: Anomaly[],
): LogEvent[] {
  const flagged = new Set(deterministic.flatMap((a) => a.eventLineNos));
  return events.filter((e) => !flagged.has(e.lineNo));
}

export interface AiDetectionResult {
  anomalies: Anomaly[];
  /** Null when the layer did not run, with the reason. */
  skipped: string | null;
  model: string | null;
  residueSize: number;
}

/**
 * Builds the bounded payload. Aggregates first — they describe all of the
 * residue — then a stratified sample so the model can cite specific lines.
 */
function buildPayload(residue: LogEvent[]) {
  // Stratified by client IP rather than random, so a quiet host with three odd
  // requests isn't drowned out by a chatty one with four hundred.
  const byIp = groupBy(residue, (e) => e.clientIp);
  const perIp = Math.max(1, Math.floor(SAMPLE_SIZE / Math.max(1, byIp.size)));
  const sample: LogEvent[] = [];
  for (const [, list] of byIp) {
    const step = Math.max(1, Math.floor(list.length / perIp));
    for (let i = 0; i < list.length && sample.length < SAMPLE_SIZE; i += step) {
      sample.push(list[i]);
    }
  }

  const hourHistogram = new Array(24).fill(0) as number[];
  for (const e of residue) hourHistogram[e.ts.getUTCHours()]++;

  return {
    residueSize: residue.length,
    note: "These are the events a deterministic rules engine did NOT flag.",
    rollups: {
      topHosts: topN(residue.map((e) => e.host), 15),
      topCategories: topN(residue.map((e) => e.category), 10),
      topClientIps: topN(residue.map((e) => e.clientIp), 15),
      topUserAgents: topN(residue.map((e) => e.userAgent), 8),
      statusCodes: topN(
        residue.map((e) => (e.statusCode === null ? null : String(e.statusCode))),
        10,
      ),
      methods: topN(residue.map((e) => e.method), 6),
      requestsByHourUtc: hourHistogram,
    },
    sample: sample.map((e) => ({
      lineNo: e.lineNo,
      ts: e.ts.toISOString(),
      user: e.username,
      clientIp: e.clientIp,
      host: e.host,
      method: e.method,
      status: e.statusCode,
      action: e.action,
      category: e.category,
      up: e.bytesSent,
      down: e.bytesReceived,
      ua: e.userAgent?.slice(0, 60) ?? null,
    })),
  };
}

export async function detectWithModel(
  events: LogEvent[],
  deterministic: Anomaly[],
): Promise<AiDetectionResult> {
  if (!process.env.ANTHROPIC_API_KEY) {
    return { anomalies: [], skipped: "no ANTHROPIC_API_KEY configured", model: null, residueSize: 0 };
  }

  const residue = computeResidue(events, deterministic);

  if (residue.length < MIN_RESIDUE) {
    return {
      anomalies: [],
      skipped: `only ${residue.length} unflagged events — not worth a model pass`,
      model: null,
      residueSize: residue.length,
    };
  }

  const payload = buildPayload(residue);
  const byLineNo = new Map(events.map((e) => [e.lineNo, e]));

  try {
    const client = new Anthropic();
    const response = await client.messages.parse({
      model: MODEL,
      max_tokens: 8000,
      output_config: {
        effort: "medium",
        format: zodOutputFormat(ResponseSchema),
      },
      system: SYSTEM_PROMPT,
      messages: [
        {
          role: "user",
          content: `Review this residue for anything the rules engine would have missed.\n\n${JSON.stringify(payload)}`,
        },
      ],
    });

    if (response.stop_reason === "refusal") {
      return { anomalies: [], skipped: "model declined the request", model: MODEL, residueSize: residue.length };
    }

    const parsed = response.parsed_output;
    if (!parsed) {
      return { anomalies: [], skipped: "model returned no parsable output", model: MODEL, residueSize: residue.length };
    }

    return {
      anomalies: parsed.findings.map((f) => toAnomaly(f, byLineNo)),
      skipped: null,
      model: response.model,
      residueSize: residue.length,
    };
  } catch (err) {
    // Never fail an upload because the optional layer had a bad day.
    return {
      anomalies: [],
      skipped: err instanceof Error ? err.message : "model call failed",
      model: MODEL,
      residueSize: residue.length,
    };
  }
}

/**
 * Converts a model finding into the same Anomaly shape the deterministic
 * detectors emit — with the guardrails applied here, not trusted from the
 * model: confidence clamped, severity derived rather than model-chosen, and
 * cited line numbers verified to actually exist.
 */
export function toAnomaly(
  f: z.infer<typeof FindingSchema>,
  byLineNo: Map<number, LogEvent>,
): Anomaly {
  const confidence = Math.min(
    MAX_MODEL_CONFIDENCE,
    Math.max(0.05, Number.isFinite(f.confidence) ? f.confidence : 0.3),
  );

  // A model can hallucinate a line number; drop any that isn't real.
  const lineNos = [...new Set(f.lineNos)].filter((n) => byLineNo.has(n));
  const cited = lineNos.map((n) => byLineNo.get(n)!);
  const times = cited.map((e) => e.ts.getTime()).sort((a, b) => a - b);

  return {
    detector: "llm_novel_pattern",
    title: f.title,
    // Severity is derived from the clamped confidence, never taken from the
    // model — it should not be able to escalate its own finding.
    severity: confidence >= 0.5 ? "medium" : "low",
    confidence,
    explanation:
      `${f.explanation}\n\n` +
      `This finding was proposed by a language model reviewing the events the deterministic ` +
      `detectors did not flag. It is a lead, not a measurement: the score reflects the model's ` +
      `judgement rather than a computed deviation, and it is capped at ${MAX_MODEL_CONFIDENCE} ` +
      `so it can never outrank a measured finding. Verify before acting on it.`,
    entity: f.entity || null,
    entityKind: f.entityKind,
    firstSeen: times.length ? new Date(times[0]) : null,
    lastSeen: times.length ? new Date(times[times.length - 1]) : null,
    eventCount: lineNos.length,
    eventLineNos: lineNos,
    evidence: {
      source: "model",
      model: MODEL,
      citedLines: lineNos.length,
      droppedInvalidLines: f.lineNos.length - lineNos.length,
      rawConfidence: f.confidence,
      cappedAt: MAX_MODEL_CONFIDENCE,
    },
  };
}
