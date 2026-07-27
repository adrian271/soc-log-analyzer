import type { Anomaly, LogEvent, Severity } from "./types";
import {
  clamp01,
  formatBytes,
  formatDuration,
  formatHourRanges,
  formatMultiple,
  groupBy,
  median,
  robustZ,
  shannonEntropy,
} from "./stats";

/**
 * Anomaly detection.
 *
 * All eight detectors below are **deterministic** — statistics and rules, no
 * model inference. That is a deliberate choice for a security tool: a SOC
 * analyst has to be able to ask "why did this fire?" and get an answer in terms
 * of numbers they can re-derive from the log themselves. Every finding
 * therefore carries an `explanation` containing the actual observed values, and
 * an `evidence` object with the raw inputs to the score.
 *
 * The LLM (see src/lib/narrative.ts) runs *after* this stage and never changes
 * a score — it only writes the shift-handover prose on top of these findings.
 *
 * ## How confidence is derived
 * Each detector normalises its evidence onto 0..1 and blends the components
 * with fixed weights documented at the detector. Two recurring ingredients:
 *
 *  - **Robust z-score** (`robustZ`): how far above the population median a
 *    value sits, measured in MADs. z >= 3.5 is the usual "clear outlier" line.
 *  - **Volume factor**: more corroborating events => more confidence, saturating
 *    so that 500 events is not treated as ten times more certain than 50.
 *
 * Detectors that observe *direct evidence* (the proxy itself named a threat)
 * start from a high floor; detectors that infer intent from behaviour alone
 * (off-hours, DGA) are capped lower, because those legitimately have benign
 * explanations.
 */

export interface DetectorConfig {
  /** Sliding window used by the request-rate detector. */
  rateWindowMs: number;
  /** A client must exceed this many requests in one window to be considered. */
  rateMinRequests: number;
  /** Minimum requests to a single host before beaconing is considered. */
  beaconMinEvents: number;
  /** Minimum total upload before exfiltration is considered. */
  exfilMinBytes: number;
  /** Minimum auth failures before a brute-force finding is raised. */
  authMinFailures: number;
}

export const DEFAULT_CONFIG: DetectorConfig = {
  rateWindowMs: 60_000,
  rateMinRequests: 30,
  beaconMinEvents: 8,
  exfilMinBytes: 10 * 1024 * 1024,
  authMinFailures: 15,
};

/** Caps how many line numbers we attach, to keep rows and payloads sane. */
const MAX_LINES_PER_FINDING = 1000;

/** No finding is ever reported as certain. See the clamp in detectAnomalies. */
const MAX_CONFIDENCE = 0.97;

/**
 * Separator for composite group keys. A literal space would break on values
 * that legitimately contain spaces — user-agent strings and block reasons both
 * do — so use a character that cannot appear in a parsed field.
 */
const SEP = "\u0000";

function severityFrom(confidence: number, base: Severity): Severity {
  const order: Severity[] = ["low", "medium", "high", "critical"];
  let idx = order.indexOf(base);
  if (confidence >= 0.85) idx += 1;
  else if (confidence < 0.55) idx -= 1;
  return order[Math.max(0, Math.min(order.length - 1, idx))];
}

function span(events: LogEvent[]): { first: Date; last: Date } {
  let first = events[0].ts;
  let last = events[0].ts;
  for (const e of events) {
    if (e.ts < first) first = e.ts;
    if (e.ts > last) last = e.ts;
  }
  return { first, last };
}

function lineNos(events: LogEvent[]): number[] {
  return events.slice(0, MAX_LINES_PER_FINDING).map((e) => e.lineNo);
}

/** Saturating volume factor: 0 at `min`, ~1 once well past `full`. */
function volumeFactor(n: number, min: number, full: number): number {
  return clamp01((n - min) / Math.max(1, full - min));
}

/** Maps a robust z-score onto 0..1, treating z=3 as weak and z=10 as certain. */
function zFactor(z: number): number {
  return clamp01((z - 3) / 7);
}

// ---------------------------------------------------------------------------
// 1. Threat signatures — the proxy already named a threat or blocked malware.
// ---------------------------------------------------------------------------
function detectThreatSignatures(events: LogEvent[]): Anomaly[] {
  const flagged = events.filter(
    (e) =>
      e.threatName !== null ||
      (e.action?.toLowerCase() === "blocked" &&
        /malware|phish|virus|threat|botnet|spyware/i.test(e.reason ?? "")),
  );

  // Group by (threat, client) so one finding = one machine's encounter with one
  // threat, which is the unit an analyst actually investigates.
  const groups = groupBy(
    flagged,
    (e) => `${e.threatName ?? e.reason ?? "Unnamed threat"}${SEP}${e.clientIp ?? "unknown"}`,
  );

  const out: Anomaly[] = [];
  for (const [key, group] of groups) {
    const [threat, clientIp] = key.split(SEP);
    const { first, last } = span(group);
    const hosts = [...new Set(group.map((e) => e.host).filter(Boolean))];
    const blocked = group.filter((e) => e.action?.toLowerCase() === "blocked").length;
    const user = group.find((e) => e.username)?.username ?? null;

    // Direct evidence from the proxy's own inspection engine, so this starts
    // very high; the only uncertainty is whether it was a true block.
    const confidence = clamp01(0.9 + 0.08 * (blocked / group.length));

    out.push({
      detector: "threat_signature",
      title: `${threat} detected on ${clientIp}`,
      severity: blocked === group.length ? "high" : "critical",
      confidence,
      explanation:
        `The proxy identified "${threat}" on ${group.length} request(s) from ${clientIp}` +
        (user ? ` (user ${user})` : "") +
        `, targeting ${hosts.slice(0, 3).join(", ")}${hosts.length > 3 ? ` and ${hosts.length - 3} more` : ""}. ` +
        (blocked === group.length
          ? "All requests were blocked, so this is likely contained — but the host attempted the connection, which means something on it is trying to reach known-bad infrastructure."
          : `${group.length - blocked} of ${group.length} request(s) were ALLOWED through. Treat this host as potentially compromised and investigate immediately.`),
      entity: clientIp,
      entityKind: "client_ip",
      firstSeen: first,
      lastSeen: last,
      eventCount: group.length,
      eventLineNos: lineNos(group),
      evidence: { threat, hosts, blocked, allowed: group.length - blocked, user },
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// 2. Request-rate spike — "unusual number of requests from a single IP in a
//    short time frame". Peak sliding-window rate compared against peers.
// ---------------------------------------------------------------------------
function detectRateSpikes(events: LogEvent[], cfg: DetectorConfig): Anomaly[] {
  const byClient = groupBy(events, (e) => e.clientIp);

  /** Highest number of requests seen inside any `rateWindowMs` window. */
  function peakWindow(list: LogEvent[]): { peak: number; at: Date; window: LogEvent[] } {
    const sorted = [...list].sort((a, b) => a.ts.getTime() - b.ts.getTime());
    let best = 0;
    let bestStart = 0;
    let start = 0;
    for (let end = 0; end < sorted.length; end++) {
      while (sorted[end].ts.getTime() - sorted[start].ts.getTime() > cfg.rateWindowMs) {
        start++;
      }
      if (end - start + 1 > best) {
        best = end - start + 1;
        bestStart = start;
      }
    }
    return {
      peak: best,
      at: sorted[bestStart]?.ts ?? sorted[0].ts,
      window: sorted.slice(bestStart, bestStart + best),
    };
  }

  const peaks = new Map<string, ReturnType<typeof peakWindow>>();
  for (const [ip, list] of byClient) peaks.set(ip, peakWindow(list));

  const population = [...peaks.values()].map((p) => p.peak);
  const med = median(population);

  const out: Anomaly[] = [];
  for (const [ip, p] of peaks) {
    if (p.peak < cfg.rateMinRequests) continue;
    const z = robustZ(p.peak, population);
    if (z < 3.5) continue;

    const group = p.window;
    const { first, last } = span(group);
    const distinctHosts = new Set(group.map((e) => e.host).filter(Boolean)).size;
    const errorRate =
      group.filter((e) => (e.statusCode ?? 0) >= 400).length / group.length;
    const user = group.find((e) => e.username)?.username ?? null;

    // 60% how extreme the rate is, 25% raw volume, 15% error rate — a burst of
    // 404/403s looks far more like scanning than a burst of successful loads.
    const confidence = clamp01(
      0.35 + 0.35 * zFactor(z) + 0.2 * volumeFactor(p.peak, cfg.rateMinRequests, 200) + 0.1 * errorRate,
    );

    out.push({
      detector: "request_rate_spike",
      title: `Request flood from ${ip} (${p.peak} requests in ${formatDuration(cfg.rateWindowMs)})`,
      severity: severityFrom(confidence, errorRate > 0.5 ? "high" : "medium"),
      confidence,
      explanation:
        `${ip}${user ? ` (${user})` : ""} made ${p.peak} requests within a single ` +
        `${formatDuration(cfg.rateWindowMs)} window starting ${p.at.toISOString().replace("T", " ").slice(0, 19)} UTC. ` +
        `The median peak rate across all ${population.length} client IPs in this log is ${med} requests ` +
        `(robust z-score ${z.toFixed(1)}). ` +
        `The burst touched ${distinctHosts} distinct host(s) and ${(errorRate * 100).toFixed(0)}% of responses were HTTP errors` +
        (errorRate > 0.5
          ? ", a pattern consistent with automated scanning or content discovery rather than human browsing."
          : ", which may be legitimate automation — check whether this host runs a scheduled job."),
      entity: ip,
      entityKind: "client_ip",
      firstSeen: first,
      lastSeen: last,
      eventCount: group.length,
      eventLineNos: lineNos(group),
      evidence: {
        peakRequests: p.peak,
        windowSeconds: cfg.rateWindowMs / 1000,
        populationMedian: med,
        robustZ: Number(z.toFixed(2)),
        distinctHosts,
        errorRate: Number(errorRate.toFixed(3)),
      },
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// 3. C2 beaconing — machine-regular callbacks to one host.
// ---------------------------------------------------------------------------
function detectBeaconing(events: LogEvent[], cfg: DetectorConfig): Anomaly[] {
  const byPair = groupBy(events, (e) =>
    e.clientIp && e.host ? `${e.clientIp}${SEP}${e.host}` : null,
  );

  const out: Anomaly[] = [];
  for (const [key, list] of byPair) {
    if (list.length < cfg.beaconMinEvents) continue;
    const [clientIp, host] = key.split(SEP);

    const times = list.map((e) => e.ts.getTime()).sort((a, b) => a - b);
    const deltas: number[] = [];
    for (let i = 1; i < times.length; i++) deltas.push(times[i] - times[i - 1]);

    const medDelta = median(deltas);
    if (medDelta < 5_000 || medDelta > 6 * 3600_000) continue; // too fast / too sparse

    // Regularity: mean absolute deviation of the intervals as a fraction of the
    // interval itself. Human browsing is bursty (ratio ~0.8+); a scheduled
    // callback sits near 0.
    const meanAbsDev =
      deltas.reduce((acc, d) => acc + Math.abs(d - medDelta), 0) / deltas.length;
    const jitterRatio = meanAbsDev / medDelta;
    if (jitterRatio > 0.25) continue;

    const regularity = clamp01(1 - jitterRatio / 0.25);
    const uniformSize =
      1 -
      clamp01(
        median(list.map((e) => Math.abs((e.bytesSent ?? 0) - median(list.map((x) => x.bytesSent ?? 0))))) /
          Math.max(1, median(list.map((e) => e.bytesSent ?? 0))),
      );

    // 55% interval regularity, 25% how many callbacks, 20% payload uniformity.
    const confidence = clamp01(
      0.55 * regularity + 0.25 * volumeFactor(list.length, cfg.beaconMinEvents, 60) + 0.2 * uniformSize,
    );
    if (confidence < 0.5) continue;

    const { first, last } = span(list);
    const user = list.find((e) => e.username)?.username ?? null;

    out.push({
      detector: "c2_beaconing",
      title: `Possible C2 beaconing: ${clientIp} → ${host} every ${formatDuration(medDelta)}`,
      severity: severityFrom(confidence, "high"),
      confidence,
      explanation:
        `${clientIp}${user ? ` (${user})` : ""} contacted ${host} ${list.length} times at a near-constant ` +
        `interval of ${formatDuration(medDelta)} (timing varies by only ${(jitterRatio * 100).toFixed(1)}% around that period), ` +
        `sustained over ${formatDuration(last.getTime() - first.getTime())}. ` +
        `Human browsing produces irregular, bursty gaps; this level of regularity indicates an automated process. ` +
        `Combined with small, uniformly-sized requests, this is the classic signature of command-and-control beaconing. ` +
        `Legitimate alternatives to rule out first: monitoring agents, software update checks, and RSS/telemetry clients.`,
      entity: clientIp,
      entityKind: "client_ip",
      firstSeen: first,
      lastSeen: last,
      eventCount: list.length,
      eventLineNos: lineNos(list),
      evidence: {
        host,
        callbacks: list.length,
        medianIntervalSeconds: Math.round(medDelta / 1000),
        jitterRatio: Number(jitterRatio.toFixed(4)),
        durationSeconds: Math.round((last.getTime() - first.getTime()) / 1000),
        user,
      },
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// 4. Data exfiltration — outbound volume far above the population norm.
// ---------------------------------------------------------------------------
function detectExfiltration(events: LogEvent[], cfg: DetectorConfig): Anomaly[] {
  const byPair = groupBy(events, (e) =>
    e.clientIp && e.host ? `${e.clientIp}${SEP}${e.host}` : null,
  );

  const totals = new Map<string, number>();
  for (const [key, list] of byPair) {
    totals.set(key, list.reduce((acc, e) => acc + (e.bytesSent ?? 0), 0));
  }
  const population = [...totals.values()];

  const out: Anomaly[] = [];
  for (const [key, total] of totals) {
    if (total < cfg.exfilMinBytes) continue;
    const z = robustZ(total, population);
    if (z < 4) continue;

    const [clientIp, host] = key.split(SEP);
    const list = byPair.get(key)!;
    const { first, last } = span(list);
    const user = list.find((e) => e.username)?.username ?? null;
    const received = list.reduce((acc, e) => acc + (e.bytesReceived ?? 0), 0);
    const ratio = received > 0 ? total / received : Infinity;

    // 45% how extreme vs peers, 30% absolute size, 25% upload/download asymmetry
    // (normal web browsing downloads far more than it uploads).
    const asymmetry = clamp01(Math.log10(Math.max(1, ratio)) / 3);
    const confidence = clamp01(
      0.3 + 0.35 * zFactor(z) + 0.2 * volumeFactor(total, cfg.exfilMinBytes, 500 * 1024 * 1024) + 0.15 * asymmetry,
    );

    out.push({
      detector: "data_exfiltration",
      title: `Large outbound transfer: ${formatBytes(total)} from ${clientIp} → ${host}`,
      severity: severityFrom(confidence, "high"),
      confidence,
      explanation:
        `${clientIp}${user ? ` (${user})` : ""} uploaded ${formatBytes(total)} to ${host} across ` +
        `${list.length} request(s) between ${first.toISOString().slice(11, 19)} and ${last.toISOString().slice(11, 19)} UTC. ` +
        `That is ${formatMultiple(total / Math.max(1, median(population)))} the median client→host upload volume in this log ` +
        `(median ${formatBytes(median(population))}), a clear statistical outlier. ` +
        `The session uploaded ${formatMultiple(ratio)} more than it downloaded, ` +
        `which is the inverse of normal web browsing and is consistent with bulk data being moved off the network.`,
      entity: clientIp,
      entityKind: "client_ip",
      firstSeen: first,
      lastSeen: last,
      eventCount: list.length,
      eventLineNos: lineNos(list),
      evidence: {
        host,
        bytesSent: total,
        bytesReceived: received,
        uploadDownloadRatio: Number.isFinite(ratio) ? Number(ratio.toFixed(2)) : null,
        robustZ: Number(z.toFixed(2)),
        requests: list.length,
        user,
      },
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// 5. Authentication failure burst — credential stuffing / brute force.
// ---------------------------------------------------------------------------
function detectAuthFailures(events: LogEvent[], cfg: DetectorConfig): Anomaly[] {
  const byPair = groupBy(events, (e) =>
    e.clientIp && e.host ? `${e.clientIp}${SEP}${e.host}` : null,
  );

  const out: Anomaly[] = [];
  for (const [key, list] of byPair) {
    const failures = list.filter((e) => e.statusCode === 401 || e.statusCode === 403);
    if (failures.length < cfg.authMinFailures) continue;

    const failureRate = failures.length / list.length;
    if (failureRate < 0.5) continue;

    // Distinguish credential guessing from directory/vulnerability scanning.
    // Brute force hammers ONE endpoint repeatedly; a scanner sprays 401/403s
    // across many different paths. Without this, the scanning host in the
    // sample log raises a second, misleading "brute force" finding.
    const urlCounts = new Map<string, number>();
    for (const f of failures) {
      const u = f.url ?? "";
      urlCounts.set(u, (urlCounts.get(u) ?? 0) + 1);
    }
    const topUrlCount = Math.max(...urlCounts.values());
    const endpointConcentration = topUrlCount / failures.length;
    if (endpointConcentration < 0.5) continue;

    const [clientIp, host] = key.split(SEP);
    const { first, last } = span(failures);
    const durationMs = last.getTime() - first.getTime();
    const succeeded = list.filter(
      (e) => e.statusCode !== null && e.statusCode >= 200 && e.statusCode < 300 && e.ts >= first,
    );
    const attemptsPerMin = durationMs > 0 ? (failures.length / durationMs) * 60_000 : failures.length;

    // 40% volume, 30% failure ratio, 30% attempt speed. A successful login at
    // the end of a failed run is the single most important signal, so it adds a
    // flat, large bump.
    let confidence = clamp01(
      0.25 +
        0.25 * volumeFactor(failures.length, cfg.authMinFailures, 100) +
        0.25 * failureRate +
        0.15 * clamp01(attemptsPerMin / 60),
    );
    if (succeeded.length > 0) confidence = clamp01(confidence + 0.15);

    out.push({
      detector: "auth_failure_burst",
      title:
        `${failures.length} failed authentications from ${clientIp} → ${host}` +
        (succeeded.length > 0 ? " followed by a success" : ""),
      severity: severityFrom(confidence, succeeded.length > 0 ? "critical" : "high"),
      confidence,
      explanation:
        `${clientIp} produced ${failures.length} HTTP 401/403 responses against ${host} over ` +
        `${formatDuration(durationMs)} (${attemptsPerMin.toFixed(0)} attempts/min), representing ` +
        `${(failureRate * 100).toFixed(0)}% of all its traffic to that host. ` +
        (succeeded.length > 0
          ? `Critically, ${succeeded.length} request(s) then returned a 2xx — the credential guessing appears to have SUCCEEDED. ` +
            `Identify the account (${succeeded.find((e) => e.username)?.username ?? "unknown"}), force a reset, and review everything that session did.`
          : `No successful authentication followed, so the attempt appears to have failed — but the source should still be investigated and rate-limited.`),
      entity: clientIp,
      entityKind: "client_ip",
      firstSeen: first,
      lastSeen: last,
      eventCount: list.length,
      eventLineNos: lineNos(list),
      evidence: {
        host,
        failures: failures.length,
        totalRequests: list.length,
        failureRate: Number(failureRate.toFixed(3)),
        attemptsPerMinute: Number(attemptsPerMin.toFixed(1)),
        endpointConcentration: Number(endpointConcentration.toFixed(3)),
        successAfterFailures: succeeded.length,
      },
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// 6. DGA / newly-seen random-looking domains.
// ---------------------------------------------------------------------------
const VOWELS = /[aeiou]/g;

/** Longest run of consecutive consonants — English rarely exceeds 3. */
function longestConsonantRun(label: string): number {
  let best = 0;
  let run = 0;
  for (const ch of label) {
    if (/[a-z]/.test(ch) && !/[aeiou]/.test(ch)) {
      run++;
      if (run > best) best = run;
    } else {
      run = 0;
    }
  }
  return best;
}

/**
 * Heuristic score 0..1 that a hostname label looks machine-generated.
 *
 * Four signals, chosen because each fails differently — a name has to look
 * unnatural in several ways at once to score highly:
 *  - entropy: random strings carry more bits/char than real words
 *  - vowel ratio: English sits near 38%; generated labels drift away
 *  - consonant runs: "qxzvbnm" is impossible in natural language
 *  - length: longer labels give the other three more to work with
 */
export function dgaScore(label: string): number {
  if (label.length < 8) return 0;
  const entropy = shannonEntropy(label);
  const vowelRatio = (label.match(VOWELS) ?? []).length / label.length;
  const maxRun = longestConsonantRun(label);

  const entropyPart = clamp01((entropy - 3.0) / 1.2);
  const vowelPart = clamp01(Math.abs(vowelRatio - 0.38) / 0.28);
  const runPart = clamp01((maxRun - 3) / 4);
  const lengthPart = clamp01((label.length - 8) / 12);

  return clamp01(
    0.35 * entropyPart + 0.25 * vowelPart + 0.25 * runPart + 0.15 * lengthPart,
  );
}

/** Labels at or above this score are treated as generated. */
const DGA_THRESHOLD = 0.55;

function detectDga(events: LogEvent[]): Anomaly[] {
  const byClient = groupBy(events, (e) => e.clientIp);

  const out: Anomaly[] = [];
  for (const [clientIp, list] of byClient) {
    const suspicious = list.filter((e) => {
      if (!e.host) return false;
      const label = e.host.split(".")[0];
      return dgaScore(label) >= DGA_THRESHOLD;
    });
    const distinctHosts = new Set(suspicious.map((e) => e.host!));
    if (distinctHosts.size < 5) continue;

    const scores = [...distinctHosts].map((h) => dgaScore(h.split(".")[0]));
    const avgScore = scores.reduce((a, b) => a + b, 0) / scores.length;
    const failed = suspicious.filter(
      (e) => e.statusCode === 0 || e.statusCode === null || (e.statusCode ?? 0) >= 400,
    ).length;
    const failRate = failed / suspicious.length;

    // 45% how domain-generation-like the names are, 30% how many distinct ones,
    // 25% resolution-failure rate (DGA clients burn through dead domains).
    // Capped at 0.85: unusual-looking domains have benign explanations (CDN
    // shards, tracking hostnames), so this should rarely read as certain.
    const confidence = Math.min(
      0.85,
      clamp01(0.2 + 0.35 * avgScore + 0.25 * volumeFactor(distinctHosts.size, 5, 40) + 0.2 * failRate),
    );

    const { first, last } = span(suspicious);
    const user = suspicious.find((e) => e.username)?.username ?? null;
    const examples = [...distinctHosts].slice(0, 4);
    const entropies = [...distinctHosts].map((h) => shannonEntropy(h.split(".")[0]));
    const meanEntropy = entropies.reduce((a, b) => a + b, 0) / entropies.length;

    out.push({
      detector: "dga_domains",
      title: `${distinctHosts.size} algorithmically-generated domains contacted by ${clientIp}`,
      severity: severityFrom(confidence, "medium"),
      confidence,
      explanation:
        `${clientIp}${user ? ` (${user})` : ""} contacted ${distinctHosts.size} distinct hostnames whose names ` +
        `score as machine-generated (mean Shannon entropy ${meanEntropy.toFixed(2)} bits/char across those names, ` +
        `unnatural vowel distribution) — for example ${examples.join(", ")}. ` +
        `${(failRate * 100).toFixed(0)}% of these requests failed to resolve or returned an error, which is typical of malware ` +
        `cycling through a domain-generation algorithm until it finds the one its operator has registered. ` +
        `Benign explanations to rule out: CDN shard hostnames and ad/telemetry domains can look similar.`,
      entity: clientIp,
      entityKind: "client_ip",
      firstSeen: first,
      lastSeen: last,
      eventCount: suspicious.length,
      eventLineNos: lineNos(suspicious),
      evidence: {
        distinctDomains: distinctHosts.size,
        meanDgaScore: Number(avgScore.toFixed(3)),
        meanEntropyBitsPerChar: Number(meanEntropy.toFixed(2)),
        failureRate: Number(failRate.toFixed(3)),
        examples,
        user,
      },
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// 7. Off-hours activity, relative to this log's own working pattern.
// ---------------------------------------------------------------------------
function detectOffHours(events: LogEvent[]): Anomaly[] {
  if (events.length < 50) return [];

  // Derive "business hours" from the data instead of hard-coding 9-5.
  //
  // An earlier version took the busiest hours until they covered 90% of
  // traffic, but that always carves off the quietest *normal* hour: with ten
  // roughly-equal working hours, the tenth is excluded by construction and
  // every user picks up a spurious finding. Instead, an hour counts as
  // business hours if it carries at least 20% of the busiest hour's traffic —
  // a genuinely quiet 02:00 falls far below that, a normal hour never does.
  const hourCounts = new Array(24).fill(0) as number[];
  for (const e of events) hourCounts[e.ts.getUTCHours()]++;
  const peakHourCount = Math.max(...hourCounts);
  if (peakHourCount === 0) return [];

  const businessHours = new Set<number>();
  for (let h = 0; h < 24; h++) {
    if (hourCounts[h] >= 0.2 * peakHourCount) businessHours.add(h);
  }

  const byUser = groupBy(events, (e) => e.username);
  const out: Anomaly[] = [];

  for (const [user, list] of byUser) {
    const outside = list.filter((e) => !businessHours.has(e.ts.getUTCHours()));
    if (outside.length < 4) continue;
    // Only interesting for users who otherwise keep normal hours.
    const insideRatio = (list.length - outside.length) / list.length;
    if (insideRatio < 0.5) continue;

    const { first, last } = span(outside);
    const uploaded = outside.reduce((acc2, e) => acc2 + (e.bytesSent ?? 0), 0);
    const hosts = [...new Set(outside.map((e) => e.host).filter(Boolean))].slice(0, 4);
    const clientIp = outside.find((e) => e.clientIp)?.clientIp ?? null;

    // 50% how much of the user's activity is out-of-pattern, 30% volume,
    // 20% whether it involved meaningful uploads. Capped at 0.7 — working late
    // is common and this signal is corroborating, not conclusive.
    const confidence = Math.min(
      0.7,
      clamp01(
        0.2 +
          0.3 * clamp01(outside.length / Math.max(8, list.length * 0.5)) +
          0.3 * volumeFactor(outside.length, 4, 30) +
          0.2 * clamp01(uploaded / (50 * 1024 * 1024)),
      ),
    );
    // Off-hours work is genuinely weak evidence, so the bar to report is low:
    // the point is to give the analyst corroborating context next to a stronger
    // finding on the same user. The business-hours definition above is what
    // keeps this quiet on normal traffic, not this threshold.
    if (confidence < 0.3) continue;

    out.push({
      detector: "off_hours_activity",
      title: `Off-hours activity by ${user} (${outside.length} requests)`,
      severity: severityFrom(confidence, "medium"),
      confidence,
      explanation:
        `${user} generated ${outside.length} request(s) between ${first.toISOString().slice(11, 16)} and ` +
        `${last.toISOString().slice(11, 16)} UTC, outside the ${formatHourRanges([...businessHours])} ` +
        `window that carries the bulk of this organisation's traffic. ` +
        `${(insideRatio * 100).toFixed(0)}% of this user's other activity falls inside normal hours, so this is a departure from their own baseline. ` +
        (uploaded > 1024 * 1024
          ? `The session uploaded ${formatBytes(uploaded)} to ${hosts.join(", ")} — review what data was accessed.`
          : `Hosts touched: ${hosts.join(", ")}.`) +
        ` Note this is a weak signal on its own; treat it as corroborating context for other findings on the same user or host.`,
      entity: user,
      entityKind: "username",
      firstSeen: first,
      lastSeen: last,
      eventCount: outside.length,
      eventLineNos: lineNos(outside),
      evidence: {
        offHoursRequests: outside.length,
        totalRequests: list.length,
        businessHoursUtc: [...businessHours].sort((a, b) => a - b),
        bytesUploaded: uploaded,
        hosts,
        clientIp,
      },
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// 8. Non-browser / attack-tool user agents.
// ---------------------------------------------------------------------------
const TOOL_UA = [
  { re: /sqlmap/i, name: "sqlmap (SQL injection tool)", weight: 1.0 },
  { re: /nikto/i, name: "Nikto (web vulnerability scanner)", weight: 1.0 },
  { re: /nmap/i, name: "Nmap (network/port scanner)", weight: 1.0 },
  { re: /masscan|zgrab/i, name: "mass scanner", weight: 1.0 },
  { re: /metasploit|meterpreter/i, name: "Metasploit", weight: 1.0 },
  { re: /python-requests|urllib|aiohttp/i, name: "Python HTTP client", weight: 0.6 },
  { re: /curl\//i, name: "curl", weight: 0.5 },
  { re: /wget/i, name: "Wget", weight: 0.5 },
  { re: /powershell|WindowsPowerShell/i, name: "PowerShell", weight: 0.8 },
  { re: /Go-http-client/i, name: "Go HTTP client", weight: 0.5 },
  { re: /libwww-perl/i, name: "libwww-perl", weight: 0.7 },
];

function detectSuspiciousUserAgents(events: LogEvent[]): Anomaly[] {
  const byPair = groupBy(events, (e) =>
    e.clientIp && e.userAgent ? `${e.clientIp}${SEP}${e.userAgent}` : null,
  );

  const out: Anomaly[] = [];
  for (const [key, list] of byPair) {
    const [clientIp, ua] = key.split(SEP);
    const match = TOOL_UA.find((t) => t.re.test(ua));
    if (!match) continue;

    const { first, last } = span(list);
    const user = list.find((e) => e.username)?.username ?? null;
    const hosts = [...new Set(list.map((e) => e.host).filter(Boolean))];

    // Driven mostly by which tool it is: an Nmap UA is unambiguous, whereas
    // curl is used constantly by legitimate scripts and CI.
    const confidence = clamp01(0.35 + 0.45 * match.weight + 0.2 * volumeFactor(list.length, 1, 50));

    out.push({
      detector: "suspicious_user_agent",
      title: `${match.name} user-agent from ${clientIp}`,
      severity: severityFrom(confidence, match.weight >= 0.8 ? "high" : "low"),
      confidence,
      explanation:
        `${list.length} request(s) from ${clientIp}${user ? ` (${user})` : ""} carried the user-agent "${ua.slice(0, 120)}", ` +
        `identifying the client as ${match.name} rather than a web browser. ` +
        `Targets: ${hosts.slice(0, 4).join(", ")}${hosts.length > 4 ? ` and ${hosts.length - 4} more` : ""}. ` +
        (match.weight >= 0.8
          ? `This tool has no legitimate business use from a user endpoint — treat as hostile activity unless it maps to an authorised security test.`
          : `Scripted HTTP clients are common in legitimate automation, so confirm whether this endpoint is expected to run scripts before escalating.`),
      entity: clientIp,
      entityKind: "client_ip",
      firstSeen: first,
      lastSeen: last,
      eventCount: list.length,
      eventLineNos: lineNos(list),
      evidence: { userAgent: ua, tool: match.name, requests: list.length, hosts: hosts.slice(0, 10), user },
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
export const DETECTOR_NAMES = [
  "threat_signature",
  "request_rate_spike",
  "c2_beaconing",
  "data_exfiltration",
  "auth_failure_burst",
  "dga_domains",
  "off_hours_activity",
  "suspicious_user_agent",
] as const;

export function detectAnomalies(
  events: LogEvent[],
  cfg: DetectorConfig = DEFAULT_CONFIG,
): Anomaly[] {
  if (events.length === 0) return [];

  const findings = [
    ...detectThreatSignatures(events),
    ...detectRateSpikes(events, cfg),
    ...detectBeaconing(events, cfg),
    ...detectExfiltration(events, cfg),
    ...detectAuthFailures(events, cfg),
    ...detectDga(events),
    ...detectOffHours(events),
    ...detectSuspiciousUserAgents(events),
  ];

  // Nothing here is ever certain — these are heuristics over a single log file
  // with no endpoint, identity, or threat-intel context to corroborate them.
  // Capping below 1.0 keeps the UI honest: a 0.97 still reads as "act on this",
  // but the tool never tells an analyst a verdict is beyond question.
  for (const f of findings) f.confidence = Math.min(MAX_CONFIDENCE, f.confidence);

  // Highest-confidence first, so the UI's default order is triage order.
  return findings.sort((a, b) => b.confidence - a.confidence);
}
