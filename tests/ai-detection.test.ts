import { test } from "vitest";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseLogFile } from "@/lib/parser";
import { detectAnomalies } from "@/lib/detectors";
import {
  MAX_MODEL_CONFIDENCE,
  computeResidue,
  toAnomaly,
} from "@/lib/ai-detection";
import type { LogEvent } from "@/lib/types";

/**
 * The live model call can't be unit-tested without a network dependency, so
 * these cover the parts that actually enforce the design: what the model is
 * allowed to see, and what it is allowed to claim.
 */

const sample = readFileSync(
  new URL("../examples/zscaler-sample.log", import.meta.url),
  "utf8",
);
const events = parseLogFile(sample).events;
const deterministic = detectAnomalies(events);
const byLineNo = new Map(events.map((e) => [e.lineNo, e]));

test("the model only ever sees events the rules engine did not flag", () => {
  const residue = computeResidue(events, deterministic);
  const flagged = new Set(deterministic.flatMap((a) => a.eventLineNos));

  assert.equal(residue.length, events.length - flagged.size);
  assert.ok(residue.length > 1500, `residue was only ${residue.length}`);
  for (const e of residue) {
    assert.ok(!flagged.has(e.lineNo), `line ${e.lineNo} was already flagged`);
  }
});

test("residue is empty when everything is already flagged", () => {
  const all = [
    { ...deterministic[0], eventLineNos: events.map((e) => e.lineNo) },
  ];
  assert.equal(computeResidue(events, all).length, 0);
});

const base = {
  title: "Something odd",
  explanation: "A pattern.",
  entity: "10.10.1.20",
  entityKind: "client_ip" as const,
  lineNos: [] as number[],
};

test("an over-confident model claim is capped, not trusted", () => {
  for (const claimed of [0.99, 1, 5, 0.85]) {
    const a = toAnomaly({ ...base, confidence: claimed }, byLineNo);
    assert.ok(
      a.confidence <= MAX_MODEL_CONFIDENCE,
      `claimed ${claimed} → stored ${a.confidence}`,
    );
  }
});

test("a model finding can never outrank the weakest measured finding it competes with", () => {
  const a = toAnomaly({ ...base, confidence: 1 }, byLineNo);
  const strongest = Math.max(...deterministic.map((d) => d.confidence));
  assert.ok(a.confidence < strongest);
});

test("garbage confidence falls back rather than producing NaN", () => {
  const a = toAnomaly({ ...base, confidence: Number.NaN }, byLineNo);
  assert.ok(Number.isFinite(a.confidence));
  assert.ok(a.confidence > 0 && a.confidence <= MAX_MODEL_CONFIDENCE);
});

test("severity is derived from the capped score, never taken from the model", () => {
  assert.equal(toAnomaly({ ...base, confidence: 0.9 }, byLineNo).severity, "medium");
  assert.equal(toAnomaly({ ...base, confidence: 0.2 }, byLineNo).severity, "low");
  // Nothing the model proposes can reach the top two severities.
  for (const c of [0, 0.3, 0.6, 1]) {
    const s = toAnomaly({ ...base, confidence: c }, byLineNo).severity;
    assert.ok(s === "low" || s === "medium", `got ${s}`);
  }
});

test("hallucinated line numbers are dropped, real ones kept", () => {
  const real = events[500].lineNo;
  const a = toAnomaly(
    { ...base, confidence: 0.4, lineNos: [real, 999999, -1, real] },
    byLineNo,
  );
  assert.deepEqual(a.eventLineNos, [real]);
  assert.equal(a.eventCount, 1);
  assert.equal(a.evidence.droppedInvalidLines, 3);
});

test("timestamps come from the cited events, not from the model", () => {
  const lines = [events[10].lineNo, events[400].lineNo];
  const a = toAnomaly({ ...base, confidence: 0.4, lineNos: lines }, byLineNo);
  const cited = lines.map((n) => (byLineNo.get(n) as LogEvent).ts.getTime());
  assert.equal(a.firstSeen?.getTime(), Math.min(...cited));
  assert.equal(a.lastSeen?.getTime(), Math.max(...cited));
});

test("every model finding is labelled as such and carries the caveat", () => {
  const a = toAnomaly({ ...base, confidence: 0.5 }, byLineNo);
  assert.equal(a.detector, "llm_novel_pattern");
  assert.equal(a.evidence.source, "model");
  assert.match(a.explanation, /lead, not a measurement/);
  assert.match(a.explanation, /Verify before acting/);
});
