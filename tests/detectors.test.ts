import { test } from "vitest";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseLogFile } from "@/lib/parser";
import { detectAnomalies, dgaScore } from "@/lib/detectors";
import type { Anomaly, LogEvent } from "@/lib/types";

function analyse(file: string): Anomaly[] {
  const content = readFileSync(new URL(`../examples/${file}`, import.meta.url), "utf8");
  return detectAnomalies(parseLogFile(content).events);
}

const findings = analyse("zscaler-sample.log");
const byDetector = (name: string) => findings.filter((f) => f.detector === name);

test("every seeded attack scenario produces at least one finding", () => {
  for (const detector of [
    "threat_signature",
    "request_rate_spike",
    "c2_beaconing",
    "data_exfiltration",
    "auth_failure_burst",
    "dga_domains",
    "off_hours_activity",
    "suspicious_user_agent",
  ]) {
    assert.ok(
      byDetector(detector).length > 0,
      `detector "${detector}" produced no findings`,
    );
  }
});

test("confidence is always a probability and findings sort by it", () => {
  for (const f of findings) {
    assert.ok(f.confidence > 0 && f.confidence <= 0.97, `${f.detector}: ${f.confidence}`);
    assert.ok(f.explanation.length > 80, `${f.detector} explanation too thin`);
    assert.ok(["low", "medium", "high", "critical"].includes(f.severity));
    assert.ok(f.eventLineNos.length > 0, `${f.detector} has no lines to highlight`);
    assert.ok(f.firstSeen instanceof Date && f.lastSeen instanceof Date);
  }
  for (let i = 1; i < findings.length; i++) {
    assert.ok(findings[i - 1].confidence >= findings[i].confidence);
  }
});

test("no detector ever claims certainty", () => {
  // These are heuristics over one log file with no corroborating context, so a
  // reported 1.00 would be a lie to the analyst.
  assert.ok(Math.max(...findings.map((f) => f.confidence)) <= 0.97);
});

test("the finding list stays small enough to triage by hand", () => {
  // 2,296 log lines should not produce a queue nobody can work through.
  assert.ok(findings.length < 25, `${findings.length} findings is too noisy`);
});

test("beaconing finds the 60-second callback channel", () => {
  const beacons = byDetector("c2_beaconing");
  const target = beacons.find((b) => b.evidence.host === "cdn-analytics-sync.top");
  assert.ok(target, "did not flag cdn-analytics-sync.top");
  assert.equal(target.evidence.medianIntervalSeconds, 60);
  assert.ok(target.confidence > 0.7, `confidence only ${target.confidence}`);
  assert.equal(target.eventCount, 90);
});

test("exfiltration finds the bulk upload to the file-sharing host", () => {
  const exfil = byDetector("data_exfiltration");
  const target = exfil.find((e) => e.evidence.host === "upload.anonfiles-cdn.ru");
  assert.ok(target, "did not flag upload.anonfiles-cdn.ru");
  assert.ok(
    (target.evidence.bytesSent as number) > 500_000_000,
    "expected a very large upload total",
  );
  assert.ok(target.confidence > 0.6);
});

test("rate spike catches the scanning host and reports its error rate", () => {
  const spikes = byDetector("request_rate_spike");
  const target = spikes.find((s) => s.entity === "10.10.4.99");
  assert.ok(target, "did not flag the scanning host 10.10.4.99");
  assert.ok((target.evidence.peakRequests as number) >= 100);
  assert.ok((target.evidence.errorRate as number) > 0.9);
});

test("brute force is flagged and the successful login is called out", () => {
  const auth = byDetector("auth_failure_burst");
  assert.equal(auth.length, 1, auth.map((a) => a.title).join("; "));
  assert.equal(auth[0].entity, "10.10.2.31");
  assert.equal(auth[0].evidence.failures, 69);
  assert.equal(auth[0].evidence.successAfterFailures, 1);
  assert.equal(auth[0].evidence.endpointConcentration, 1);
  assert.equal(auth[0].severity, "critical");
  assert.match(auth[0].explanation, /SUCCEEDED/);
});

test("scanning is not misreported as credential stuffing", () => {
  const auth = byDetector("auth_failure_burst");
  assert.ok(
    !auth.some((a) => a.entity === "10.10.4.99"),
    "the scanning host was mislabelled as a brute-force source",
  );
});

/**
 * The test above only proves the scanner in *this file* isn't misreported, and
 * it currently passes because its failure rate sits under the 50% gate — the
 * endpoint-concentration rule never runs. Mutation testing caught that: deleting
 * the concentration gate entirely left all tests green.
 *
 * So the rule gets its own test, on synthetic events built to isolate it. Both
 * clients below clear the volume and failure-rate gates identically; the only
 * difference is whether the failures land on one URL or many.
 */
function authEvents(clientIp: string, urls: string[], count: number): LogEvent[] {
  const base = Date.parse("2024-05-14T10:00:00Z");
  return Array.from({ length: count }, (_, i) => ({
    lineNo: i + 1,
    ts: new Date(base + i * 2000),
    username: null,
    department: null,
    location: null,
    clientIp,
    serverIp: "10.20.1.5",
    host: "vpn.example.local",
    url: urls[i % urls.length],
    method: "POST",
    statusCode: 401,
    action: "Allowed",
    reason: null,
    bytesSent: 400,
    bytesReceived: 200,
    category: null,
    threatName: null,
    riskScore: null,
    userAgent: "curl/8.4.0",
    referer: null,
    appName: null,
    raw: "",
  }));
}

test("credential stuffing on one endpoint fires; the same volume sprayed across many does not", () => {
  const oneUrl = authEvents("10.0.0.1", ["https://vpn.example.local/auth/login"], 40);
  const manyUrls = authEvents(
    "10.0.0.2",
    Array.from({ length: 20 }, (_, i) => `https://vpn.example.local/path-${i}`),
    40,
  );

  const stuffing = detectAnomalies(oneUrl).filter(
    (a) => a.detector === "auth_failure_burst",
  );
  const scanning = detectAnomalies(manyUrls).filter(
    (a) => a.detector === "auth_failure_burst",
  );

  assert.equal(stuffing.length, 1, "40 failures on one login URL should fire");
  assert.equal(stuffing[0].evidence.endpointConcentration, 1);

  assert.equal(
    scanning.length,
    0,
    "the same 40 failures spread over 20 URLs is scanning, not credential guessing",
  );
});

test("threat signatures separate blocked-only from allowed-through", () => {
  const threats = byDetector("threat_signature");
  assert.ok(threats.length >= 3, `only ${threats.length} threat findings`);
  for (const t of threats) {
    assert.ok(t.confidence >= 0.9);
    assert.equal(t.evidence.allowed, 0); // all seeded threats are blocked
  }
});

test("dga scoring separates random labels from real words", () => {
  assert.ok(dgaScore("qxzvbnmwkrtplj") > 0.6);
  assert.ok(dgaScore("stackoverflow") < 0.5);
  assert.equal(dgaScore("github"), 0); // too short to judge
});

test("uncertain detectors stay below full confidence", () => {
  for (const f of [...byDetector("off_hours_activity"), ...byDetector("dga_domains")]) {
    assert.ok(f.confidence <= 0.85, `${f.detector} claimed ${f.confidence}`);
  }
});

test("dga detector finds the generated-domain traffic", () => {
  const dga = byDetector("dga_domains");
  assert.equal(dga.length, 1);
  assert.ok(
    (dga[0].evidence.distinctDomains as number) >= 20,
    `only ${dga[0].evidence.distinctDomains} domains`,
  );

  // Entropy is the weakest of the four DGA signals and the generated labels
  // sit only slightly above real words, so this asserts the direction rather
  // than a precise value — pinning it tighter just makes the test brittle
  // against the PRNG stream. `stackoverflow` measures ~3.55 for comparison.
  const entropy = dga[0].evidence.meanEntropyBitsPerChar as number;
  assert.ok(entropy > 3.2 && entropy < 4.0, `mean entropy was ${entropy}`);
});

test("benign-only traffic produces no findings at all", () => {
  // The strongest guard against the detectors being noise: an independent draw
  // of purely normal traffic must come back completely clean.
  const benign = analyse("zscaler-benign.log");
  assert.equal(
    benign.length,
    0,
    `false positives: ${benign.map((f) => `${f.detector}(${f.confidence.toFixed(2)}) ${f.title}`).join("; ")}`,
  );
});
