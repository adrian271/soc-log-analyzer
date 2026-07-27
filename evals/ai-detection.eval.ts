import { test, beforeAll } from "vitest";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseLogFile } from "@/lib/parser";
import { detectAnomalies } from "@/lib/detectors";
import { computeResidue, detectWithModel } from "@/lib/ai-detection";
import type { Anomaly } from "@/lib/types";

/**
 * Does the model layer actually earn its place?
 *
 * The deterministic detectors had to clear one bar before they shipped: an
 * independent draw of purely benign traffic must come back clean. A layer that
 * invents findings in traffic where nothing is wrong is not a detector, it is a
 * noise generator — and it would be worse than nothing, because an analyst
 * learns to ignore the section it lives in.
 *
 * This applies the same bar. Run it with a valid ANTHROPIC_API_KEY:
 *
 *     npm run eval:ai
 *
 * It makes real API calls. It is deliberately excluded from `npm test`.
 */

/** Above this the prompt tells the model it would genuinely escalate. */
const ESCALATION_THRESHOLD = 0.5;

/** Some low-confidence musing on benign traffic is tolerable. This much isn't. */
const MAX_BENIGN_FINDINGS = 2;

function load(file: string) {
  const content = readFileSync(
    new URL(`../examples/${file}`, import.meta.url),
    "utf8",
  );
  const events = parseLogFile(content).events;
  const deterministic = detectAnomalies(events);
  return { events, deterministic };
}

function report(label: string, findings: Anomaly[]) {
  console.log(`\n  ── ${label} ──`);
  if (findings.length === 0) {
    console.log("     (no findings)");
    return;
  }
  for (const f of findings) {
    console.log(
      `     ${f.confidence.toFixed(2)}  ${f.severity.padEnd(6)}  ${f.entity ?? "—"}  ${f.title}`,
    );
    console.log(`            ${f.explanation.split("\n")[0].slice(0, 150)}`);
  }
}

beforeAll(() => {
  if (!process.env.ANTHROPIC_API_KEY) {
    throw new Error(
      "ANTHROPIC_API_KEY is not set. This eval makes real API calls — " +
        "add a valid key to .env and re-run `npm run eval:ai`.",
    );
  }
});

test("benign traffic stays quiet — the false-positive bar", async () => {
  const { events, deterministic } = load("zscaler-benign.log");

  // Sanity: the deterministic layer already finds nothing here, so the whole
  // file is residue and the model sees all of it.
  assert.equal(deterministic.length, 0, "benign file should be deterministically clean");
  const residue = computeResidue(events, deterministic);
  console.log(`\n  benign: ${residue.length} events, all of them residue`);

  const result = await detectWithModel(events, deterministic);
  assert.equal(result.skipped, null, `layer did not run: ${result.skipped}`);
  report("model findings on BENIGN traffic", result.anomalies);

  const escalating = result.anomalies.filter(
    (a) => a.confidence >= ESCALATION_THRESHOLD,
  );

  assert.equal(
    escalating.length,
    0,
    `The model would escalate ${escalating.length} finding(s) in traffic with nothing wrong:\n` +
      escalating.map((a) => `  ${a.confidence.toFixed(2)} ${a.title}`).join("\n") +
      "\n\nThis is the bar the deterministic detectors had to clear. If the model " +
      "cannot, the layer is noise and should be reverted rather than shipped.",
  );

  assert.ok(
    result.anomalies.length <= MAX_BENIGN_FINDINGS,
    `${result.anomalies.length} findings on clean traffic (max ${MAX_BENIGN_FINDINGS}). ` +
      "Even low-confidence, a section that is never empty trains analysts to ignore it.",
  );
});

test("on the attack file it adds something, without re-reporting the rules engine", async () => {
  const { events, deterministic } = load("zscaler-sample.log");
  const residue = computeResidue(events, deterministic);
  console.log(
    `\n  sample: ${events.length} events, ${deterministic.length} deterministic findings, ${residue.length} residue`,
  );

  const result = await detectWithModel(events, deterministic);
  assert.equal(result.skipped, null, `layer did not run: ${result.skipped}`);
  report("model findings on the ATTACK file", result.anomalies);

  // Every cited line must be one the rules engine left alone. If the model is
  // citing already-flagged lines, the residue boundary is broken.
  const flagged = new Set(deterministic.flatMap((a) => a.eventLineNos));
  for (const a of result.anomalies) {
    for (const n of a.eventLineNos) {
      assert.ok(
        !flagged.has(n),
        `model cited line ${n}, which the deterministic layer had already flagged`,
      );
    }
  }

  // The prompt forbids re-reporting the eight covered categories. This can't be
  // checked mechanically, so surface it for a human instead of failing.
  const known = /beacon|exfiltrat|brute|credential.stuff|port scan|nmap|malware|phish|dga|domain.generat|off.hours|rate.spike|user.agent/i;
  const echoes = result.anomalies.filter((a) => known.test(a.title));
  if (echoes.length) {
    console.log(
      `\n  ⚠ ${echoes.length} finding(s) look like they restate a covered category — read them:`,
    );
    for (const e of echoes) console.log(`     ${e.title}`);
  }

  console.log(
    `\n  → ${result.anomalies.length} lead(s) from ${result.residueSize} events the rules engine ignored.`,
  );
  console.log(
    "    Judge these by hand. Zero is an acceptable answer; plausible-but-unverifiable is not.",
  );
});

test("the cap holds against whatever the model actually returned", async () => {
  const { events, deterministic } = load("zscaler-sample.log");
  const result = await detectWithModel(events, deterministic);
  assert.equal(result.skipped, null, `layer did not run: ${result.skipped}`);

  const strongestDeterministic = Math.max(
    ...deterministic.map((d) => d.confidence),
  );
  for (const a of result.anomalies) {
    assert.ok(a.confidence <= 0.6, `${a.confidence} exceeded the cap`);
    assert.ok(a.confidence < strongestDeterministic);
    assert.ok(a.severity === "low" || a.severity === "medium");
  }
});
