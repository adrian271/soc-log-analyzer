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

/**
 * The three shapes below are stored as JSON and read back later, so they are
 * defined once as runtime schemas in `./schemas` and their types inferred from
 * there. Declaring them twice — an interface here and a schema there — is
 * exactly how a validator drifts away from the thing it is meant to validate.
 */
export type {
  UploadStats,
  TimelineBucket,
  CountPair,
  Evidence,
} from "./schemas";
