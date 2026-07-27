/** A single successfully parsed log line. */
export interface LogEvent {
  lineNo: number;
  ts: Date;
  username: string | null;
  department: string | null;
  location: string | null;
  clientIp: string | null;
  serverIp: string | null;
  host: string | null;
  url: string | null;
  method: string | null;
  statusCode: number | null;
  action: string | null;
  reason: string | null;
  bytesSent: number | null;
  bytesReceived: number | null;
  category: string | null;
  threatName: string | null;
  riskScore: number | null;
  userAgent: string | null;
  referer: string | null;
  appName: string | null;
  raw: string;
}

export interface MalformedLine {
  lineNo: number;
  raw: string;
  reason: string;
}

export interface ParseResult {
  events: LogEvent[];
  malformed: MalformedLine[];
  totalLines: number;
}

export type Severity = "low" | "medium" | "high" | "critical";

/** A finding produced by one of the detectors in `src/lib/detectors`. */
export interface Anomaly {
  detector: string;
  title: string;
  severity: Severity;
  /** 0..1 — how sure the detector is that this is genuinely anomalous. */
  confidence: number;
  /** Plain-English reason shown directly to the analyst. */
  explanation: string;
  entity: string | null;
  entityKind: "client_ip" | "username" | "host" | null;
  firstSeen: Date | null;
  lastSeen: Date | null;
  eventCount: number;
  /** Line numbers this finding is based on, used to highlight rows in the UI. */
  eventLineNos: number[];
  evidence: Record<string, unknown>;
}

/** Aggregate rollups computed once at ingest and stored on the upload row. */
export interface UploadStats {
  totalEvents: number;
  uniqueClientIps: number;
  uniqueUsers: number;
  uniqueHosts: number;
  blockedCount: number;
  allowedCount: number;
  threatCount: number;
  bytesSent: number;
  bytesReceived: number;
  /** Fixed-width buckets across the log's time range, for the timeline chart. */
  timeline: TimelineBucket[];
  topHosts: CountPair[];
  topCategories: CountPair[];
  topClientIps: CountPair[];
  topThreats: CountPair[];
  statusBreakdown: CountPair[];
}

export interface TimelineBucket {
  /** ISO timestamp of the bucket's start. */
  start: string;
  total: number;
  blocked: number;
  threats: number;
  anomalous: number;
}

export interface CountPair {
  key: string;
  count: number;
}
