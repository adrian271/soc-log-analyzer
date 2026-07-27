import type { LogEvent, MalformedLine, ParseResult } from "./types";

/**
 * Parser for ZScaler NSS Web Proxy logs in tab-separated feed format.
 *
 * Two things make this tolerant enough for real-world files:
 *
 *  1. It is *header-driven* when possible. A `#Fields:` line (which ZScaler NSS
 *     emits, and which our sample logs include) defines the column order, so a
 *     feed configured with a different field set still parses correctly.
 *  2. It falls back to DEFAULT_FIELDS when no header is present, and a line
 *     that is short, over-long, or has junk in a numeric column still yields an
 *     event — only an unparseable timestamp rejects a line outright, because
 *     without a timestamp the row is useless for timeline and rate analysis.
 */

/** Column order assumed when a file has no `#Fields:` header. */
export const DEFAULT_FIELDS = [
  "datetime",
  "user",
  "department",
  "location",
  "clientip",
  "serverip",
  "method",
  "host",
  "url",
  "action",
  "reason",
  "statuscode",
  "requestsize",
  "responsesize",
  "urlcategory",
  "threatname",
  "riskscore",
  "useragent",
  "referer",
  "appname",
] as const;

/**
 * Maps the many names a field can carry in a ZScaler feed onto our canonical
 * keys. Header names are normalised to lowercase alphanumerics before lookup,
 * so `Client IP`, `client_ip` and `cip` all land on the same entry.
 */
const FIELD_ALIASES: Record<string, keyof LogEvent> = {
  datetime: "ts",
  date: "ts",
  time: "ts",
  timestamp: "ts",
  recordid: "lineNo",

  user: "username",
  username: "username",
  login: "username",

  department: "department",
  dept: "department",
  location: "location",

  clientip: "clientIp",
  cip: "clientIp",
  srcip: "clientIp",
  sourceip: "clientIp",
  clientinternalip: "clientIp",

  serverip: "serverIp",
  sip: "serverIp",
  dstip: "serverIp",
  destip: "serverIp",
  destinationip: "serverIp",

  host: "host",
  hostname: "host",
  url: "url",
  fullurl: "url",
  method: "method",
  reqmethod: "method",
  requestmethod: "method",

  action: "action",
  reason: "reason",

  statuscode: "statusCode",
  status: "statusCode",
  respcode: "statusCode",
  responsecode: "statusCode",

  requestsize: "bytesSent",
  reqsize: "bytesSent",
  bytesout: "bytesSent",
  sentbytes: "bytesSent",

  responsesize: "bytesReceived",
  respsize: "bytesReceived",
  bytesin: "bytesReceived",
  receivedbytes: "bytesReceived",

  urlcategory: "category",
  category: "category",
  urlclass: "category",

  threatname: "threatName",
  threat: "threatName",
  malwarename: "threatName",

  riskscore: "riskScore",
  risk: "riskScore",

  useragent: "userAgent",
  ua: "userAgent",
  referer: "referer",
  referrer: "referer",

  appname: "appName",
  app: "appName",
  application: "appName",
  cloudapp: "appName",
};

function normaliseFieldName(raw: string): string {
  return raw.toLowerCase().replace(/[^a-z0-9]/g, "");
}

/** Resolves a header row into canonical LogEvent keys (null = ignore column). */
function resolveColumns(fields: readonly string[]): (keyof LogEvent | null)[] {
  return fields.map((f) => FIELD_ALIASES[normaliseFieldName(f)] ?? null);
}

/**
 * ZScaler writes `-` (and occasionally `""` or `None`) for "no value". Treat
 * those as null rather than letting them pollute top-N aggregations.
 */
function cleanValue(v: string | undefined): string | null {
  if (v === undefined) return null;
  const t = v.trim().replace(/^"(.*)"$/s, "$1");
  if (t === "" || t === "-" || t === "None" || t === "NA") return null;
  return t;
}

function toInt(v: string | null): number | null {
  if (v === null) return null;
  const n = Number.parseInt(v, 10);
  return Number.isFinite(n) ? n : null;
}

/**
 * Accepts the timestamp shapes we actually see in proxy feeds. A bare
 * `YYYY-MM-DD HH:MM:SS` has no zone marker; ZScaler NSS emits UTC, so we pin it
 * to UTC rather than letting it drift with the server's local timezone.
 */
export function parseTimestamp(value: string | null): Date | null {
  if (!value) return null;
  const v = value.trim();

  // Epoch seconds or milliseconds.
  if (/^\d{10}$/.test(v)) return new Date(Number(v) * 1000);
  if (/^\d{13}$/.test(v)) return new Date(Number(v));

  // `YYYY-MM-DD HH:MM:SS[.mmm]` with no zone -> interpret as UTC.
  const naive = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d+)?)$/.exec(v);
  if (naive) {
    const d = new Date(`${naive[1]}T${naive[2]}Z`);
    return Number.isNaN(d.getTime()) ? null : d;
  }

  // Anything already carrying a zone (ISO-8601 with Z or ±HH:MM).
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** Splits on tabs, falling back to 2+ spaces for space-aligned exports. */
function splitRow(line: string): string[] {
  return line.includes("\t") ? line.split("\t") : line.split(/ {2,}/);
}

function emptyEvent(lineNo: number, raw: string, ts: Date): LogEvent {
  return {
    lineNo,
    ts,
    username: null,
    department: null,
    location: null,
    clientIp: null,
    serverIp: null,
    host: null,
    url: null,
    method: null,
    statusCode: null,
    action: null,
    reason: null,
    bytesSent: null,
    bytesReceived: null,
    category: null,
    threatName: null,
    riskScore: null,
    userAgent: null,
    referer: null,
    appName: null,
    raw,
  };
}

/** Fields that must be coerced to a number rather than kept as text. */
const NUMERIC_FIELDS = new Set<keyof LogEvent>([
  "statusCode",
  "bytesSent",
  "bytesReceived",
  "riskScore",
]);

export function parseLogFile(content: string): ParseResult {
  const lines = content.split(/\r?\n/);
  const events: LogEvent[] = [];
  const malformed: MalformedLine[] = [];
  let totalLines = 0;

  let columns = resolveColumns(DEFAULT_FIELDS);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const lineNo = i + 1;

    if (line.trim() === "") continue;

    // `#Fields: a<TAB>b<TAB>c` redefines the column layout for what follows.
    if (line.startsWith("#")) {
      const m = /^#\s*fields:?\s*(.*)$/i.exec(line);
      if (m && m[1].trim() !== "") columns = resolveColumns(splitRow(m[1]));
      continue;
    }

    totalLines++;
    const cells = splitRow(line);

    // Locate and validate the timestamp first — it is the one hard requirement.
    const tsIndex = columns.indexOf("ts");
    const ts = parseTimestamp(tsIndex >= 0 ? cleanValue(cells[tsIndex]) : null);
    if (!ts) {
      malformed.push({
        lineNo,
        raw: line,
        reason:
          tsIndex < 0
            ? "no timestamp column in layout"
            : `unparseable timestamp: ${JSON.stringify(cells[tsIndex] ?? "")}`,
      });
      continue;
    }

    const event = emptyEvent(lineNo, line, ts);
    // Indexed writes need a loose view; every key comes from FIELD_ALIASES so
    // it is always a real LogEvent property.
    const target = event as unknown as Record<string, string | number | null>;

    for (let c = 0; c < columns.length; c++) {
      const key = columns[c];
      if (!key || key === "ts" || key === "lineNo" || key === "raw") continue;

      const value = cleanValue(cells[c]);
      if (value === null) continue;

      target[key] = NUMERIC_FIELDS.has(key) ? toInt(value) : value;
    }

    // A feed may carry `url` without `host`; derive one from the other so
    // host-based aggregation still works.
    if (!event.host && event.url) event.host = hostFromUrl(event.url);

    events.push(event);
  }

  return { events, malformed, totalLines };
}

/** Best-effort hostname extraction that tolerates scheme-less URLs. */
export function hostFromUrl(url: string): string | null {
  try {
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(url)
      ? url
      : `http://${url}`;
    const h = new URL(withScheme).hostname;
    return h === "" ? null : h;
  } catch {
    return null;
  }
}
