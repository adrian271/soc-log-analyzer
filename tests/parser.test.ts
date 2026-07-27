import { test } from "vitest";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseLogFile, parseTimestamp, hostFromUrl } from "@/lib/parser";

const sample = readFileSync(
  new URL("../examples/zscaler-sample.log", import.meta.url),
  "utf8",
);

test("parses the full sample file with no malformed lines", () => {
  const r = parseLogFile(sample);
  assert.equal(r.malformed.length, 0);
  assert.ok(r.events.length > 2000, `only ${r.events.length} events`);
  assert.equal(r.events.length, r.totalLines);
});

test("maps header fields onto typed values", () => {
  const r = parseLogFile(sample);
  const e = r.events[0];
  assert.ok(e.ts instanceof Date);
  assert.match(e.clientIp ?? "", /^10\.10\./);
  assert.equal(typeof e.statusCode, "number");
  assert.equal(typeof e.bytesSent, "number");
  assert.ok(e.host && e.host.length > 0);
});

test("header row overrides the default column order", () => {
  const log = [
    "#Fields: clientip\tdatetime\thost",
    "192.0.2.5\t2024-05-14 08:00:00\texample.com",
  ].join("\n");
  const r = parseLogFile(log);
  assert.equal(r.events.length, 1);
  assert.equal(r.events[0].clientIp, "192.0.2.5");
  assert.equal(r.events[0].host, "example.com");
  assert.equal(r.events[0].ts.toISOString(), "2024-05-14T08:00:00.000Z");
});

test("rejects only lines whose timestamp is unusable", () => {
  const log = [
    "#Fields: datetime\tclientip\thost",
    "not-a-date\t192.0.2.5\texample.com",
    "2024-05-14 08:00:00\t192.0.2.6\texample.org",
  ].join("\n");
  const r = parseLogFile(log);
  assert.equal(r.events.length, 1);
  assert.equal(r.malformed.length, 1);
  assert.equal(r.malformed[0].lineNo, 2);
  assert.match(r.malformed[0].reason, /unparseable timestamp/);
});

test("short rows still parse the columns that are present", () => {
  const log = [
    "#Fields: datetime\tuser\tclientip\thost\tstatuscode",
    "2024-05-14 08:00:00\tbob@x.io\t10.0.0.1",
  ].join("\n");
  const r = parseLogFile(log);
  assert.equal(r.events.length, 1);
  assert.equal(r.events[0].username, "bob@x.io");
  assert.equal(r.events[0].host, null);
  assert.equal(r.events[0].statusCode, null);
});

test('treats "-" as null rather than a value', () => {
  const log = [
    "#Fields: datetime\tuser\tthreatname",
    "2024-05-14 08:00:00\t-\t-",
  ].join("\n");
  const r = parseLogFile(log);
  assert.equal(r.events[0].username, null);
  assert.equal(r.events[0].threatName, null);
});

test("naive timestamps are read as UTC, not local time", () => {
  assert.equal(
    parseTimestamp("2024-05-14 08:00:00")?.toISOString(),
    "2024-05-14T08:00:00.000Z",
  );
  assert.equal(parseTimestamp("1715673600")?.toISOString(), "2024-05-14T08:00:00.000Z");
  assert.equal(parseTimestamp("garbage"), null);
});

test("derives host from url when the host column is absent", () => {
  assert.equal(hostFromUrl("https://a.example.com/x?y=1"), "a.example.com");
  assert.equal(hostFromUrl("a.example.com/x"), "a.example.com");
  assert.equal(hostFromUrl(""), null);
});
