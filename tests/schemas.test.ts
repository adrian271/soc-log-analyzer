import { test } from "vitest";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseLogFile } from "@/lib/parser";
import { detectAnomalies } from "@/lib/detectors";
import { computeStats } from "@/lib/analysis";
import { parseEvidence, parseUploadStats } from "@/lib/schemas";

/**
 * These cover the one place TypeScript can't help: values written to a JSONB
 * column and read back later. The point of each failing case is schema drift —
 * a row written by an older version of the code.
 */

const sample = readFileSync(
  new URL("../examples/zscaler-sample.log", import.meta.url),
  "utf8",
);
const events = parseLogFile(sample).events;
const anomalies = detectAnomalies(events);
const realStats = computeStats(events, anomalies);

/** What Postgres actually hands back: JSON round-tripped, not the live object. */
const roundTripped = JSON.parse(JSON.stringify(realStats));

test("stats produced by the pipeline survive a JSON round trip", () => {
  const parsed = parseUploadStats(roundTripped);
  assert.ok(parsed, "the real rollup failed its own schema");
  assert.equal(parsed.totalEvents, realStats.totalEvents);
  assert.equal(parsed.timeline.length, 60);
  assert.equal(parsed.topHosts.length, realStats.topHosts.length);
});

test("null and undefined pass through as null, not as an error", () => {
  assert.equal(parseUploadStats(null), null);
  assert.equal(parseUploadStats(undefined), null);
});

test("a dropped field is caught rather than surfacing as undefined later", () => {
  const drifted = { ...roundTripped };
  delete drifted.timeline;
  assert.equal(
    parseUploadStats(drifted),
    null,
    "missing `timeline` should not parse — the chart would throw on it",
  );
});

test("a field that changed type is caught", () => {
  assert.equal(parseUploadStats({ ...roundTripped, totalEvents: "2293" }), null);
});

test("a malformed timeline bucket is caught, not just the top level", () => {
  const drifted = {
    ...roundTripped,
    timeline: [{ start: "2024-05-14T08:00:00Z", total: 5 }], // missing 3 fields
  };
  assert.equal(parseUploadStats(drifted), null);
});

test("garbage in the column does not become a typed object", () => {
  for (const junk of ["not json", 42, [], true]) {
    assert.equal(parseUploadStats(junk), null, `accepted ${JSON.stringify(junk)}`);
  }
});

test("evidence must be an object, since the UI calls Object.keys on it", () => {
  const real = anomalies[0].evidence;
  assert.deepEqual(parseEvidence(JSON.parse(JSON.stringify(real))), real);

  assert.equal(parseEvidence(null), null);
  assert.equal(parseEvidence("a string"), null);
  assert.equal(parseEvidence(7), null);
});

test("every real finding's evidence validates", () => {
  for (const a of anomalies) {
    const parsed = parseEvidence(JSON.parse(JSON.stringify(a.evidence)));
    assert.ok(parsed, `${a.detector} evidence failed to parse`);
  }
});
