/**
 * Generates the example ZScaler-style logs in examples/.
 *
 * Run with: npm run gen:logs
 *
 * Output is deterministic (fixed seed + fixed base date) so the committed
 * example files are stable and the README can describe exactly what is in them.
 *
 * Two files are produced:
 *   examples/zscaler-sample.log  - benign traffic + 7 seeded attack scenarios
 *   examples/zscaler-benign.log  - benign traffic only (detector false-positive
 *                                  check: this one should come back near-clean)
 */
import { mkdir, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// ---------------------------------------------------------------------------
// Deterministic PRNG (mulberry32) so regenerating never churns the examples.
// ---------------------------------------------------------------------------
function rng(seed) {
  let a = seed >>> 0;
  return function next() {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const rand = rng(20240514);
const pick = (arr) => arr[Math.floor(rand() * arr.length)];
const between = (lo, hi) => lo + Math.floor(rand() * (hi - lo + 1));

// ---------------------------------------------------------------------------
// Environment: a small corporate network.
// ---------------------------------------------------------------------------
const DEPARTMENTS = ["Engineering", "Finance", "Sales", "HR", "IT", "Legal"];
const LOCATIONS = ["HQ-Austin", "HQ-Austin", "HQ-Austin", "Remote-VPN", "EU-Dublin"];

const USERS = [];
const FIRST = ["alice", "bob", "carol", "dan", "erin", "frank", "grace", "heidi",
  "ivan", "judy", "ken", "lena", "mallory", "niaj", "olivia", "peggy", "quinn",
  "rupert", "sybil", "trent", "uma", "victor", "wendy", "xavier"];
const BROWSER_UAS = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
];

for (let i = 0; i < FIRST.length; i++) {
  USERS.push({
    name: `${FIRST[i]}@tenex.local`,
    dept: DEPARTMENTS[i % DEPARTMENTS.length],
    loc: LOCATIONS[i % LOCATIONS.length],
    ip: `10.10.${1 + (i % 4)}.${20 + i}`,
    // A person has one laptop. An earlier version picked a user-agent at
    // random per request, which made every user appear to switch between
    // Windows Chrome and macOS Safari between page loads — a genuine
    // indicator in real traffic, and pure noise here. The model-detection
    // eval caught it, which is exactly what that eval is for.
    ua: BROWSER_UAS[i % BROWSER_UAS.length],
  });
}

/**
 * host -> [category, server ip prefix, acceptsPost]
 *
 * `acceptsPost` marks sites where a POST is normal — webmail, chat, source
 * control, SaaS apps. A read-only news site or a static CDN receiving
 * multi-kilobyte POSTs is itself an anomaly, so generating them at random
 * planted a signal in traffic that is supposed to be unremarkable.
 */
const BENIGN_SITES = [
  ["www.google.com", "Search Engines", "142.250.72", false],
  ["mail.google.com", "Webmail", "142.250.72", true],
  ["github.com", "Professional Services", "140.82.113", true],
  ["api.github.com", "Professional Services", "140.82.114", true],
  ["outlook.office365.com", "Webmail", "52.96.40", true],
  ["teams.microsoft.com", "Instant Messaging", "52.113.194", true],
  ["slack.com", "Instant Messaging", "3.89.11", true],
  ["www.atlassian.net", "Professional Services", "104.192.142", true],
  ["registry.npmjs.org", "Software Downloads", "104.16.24", false],
  ["s3.us-east-1.amazonaws.com", "Web Hosting", "52.216.35", false],
  ["console.aws.amazon.com", "Professional Services", "99.84.108", true],
  ["www.linkedin.com", "Social Networking", "13.107.42", true],
  ["www.nytimes.com", "News and Media", "151.101.65", false],
  ["cdn.jsdelivr.net", "Content Servers", "104.16.85", false],
  ["www.salesforce.com", "Professional Services", "104.109.10", true],
  ["zoom.us", "Streaming Media", "170.114.52", false],
  ["stackoverflow.com", "Professional Services", "104.18.32", true],
  ["docs.google.com", "Professional Services", "142.250.80", true],
];

const BENIGN_PATHS = ["/", "/index.html", "/api/v1/status", "/assets/app.js",
  "/static/main.css", "/search?q=deployment", "/docs/getting-started",
  "/user/profile", "/api/v2/messages", "/favicon.ico"];

const BASE = Date.UTC(2024, 4, 14, 6, 0, 0); // 2024-05-14T06:00:00Z
const HOUR = 3600_000;

const FIELDS = ["datetime", "user", "department", "location", "clientip",
  "serverip", "method", "host", "url", "action", "reason", "statuscode",
  "requestsize", "responsesize", "urlcategory", "threatname", "riskscore",
  "useragent", "referer", "appname"];

function fmtTime(ms) {
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d+Z$/, "");
}

/** Builds one tab-separated record. `o.ms` is the event time. */
function row(o) {
  const v = [
    fmtTime(o.ms),
    o.user ?? "-",
    o.dept ?? "-",
    o.loc ?? "-",
    o.clientIp ?? "-",
    o.serverIp ?? "-",
    o.method ?? "GET",
    o.host ?? "-",
    o.url ?? "-",
    o.action ?? "Allowed",
    o.reason ?? "-",
    String(o.status ?? 200),
    String(o.reqSize ?? between(200, 1400)),
    String(o.respSize ?? between(500, 60000)),
    o.category ?? "Miscellaneous",
    o.threat ?? "-",
    String(o.risk ?? 0),
    o.ua ?? BROWSER_UAS[0],
    o.referer ?? "-",
    o.app ?? "-",
  ];
  return v.join("\t");
}

/** Ordinary user browsing spread across the working day. */
function benignTraffic(count) {
  const out = [];
  for (let i = 0; i < count; i++) {
    const u = pick(USERS);
    const [host, category, ipPrefix, acceptsPost] = pick(BENIGN_SITES);
    // Working hours 08:00-18:00 UTC, weighted toward mid-morning.
    const hourOffset = 2 + rand() * 10;
    const ms = BASE + hourOffset * HOUR + between(0, 3599) * 1000;
    const path = pick(BENIGN_PATHS);
    const isPost = acceptsPost && rand() < 0.18;
    out.push({
      ms,
      line: row({
        ms,
        user: u.name,
        dept: u.dept,
        loc: u.loc,
        clientIp: u.ip,
        serverIp: `${ipPrefix}.${between(1, 254)}`,
        method: isPost ? "POST" : "GET",
        host,
        url: `https://${host}${path}`,
        action: "Allowed",
        status: rand() < 0.04 ? pick([301, 304, 404]) : 200,
        reqSize: isPost ? between(800, 9000) : between(200, 1400),
        respSize: between(500, 90000),
        category,
        ua: u.ua,
        app: host.includes("office365") || host.includes("microsoft")
          ? "Microsoft 365" : "-",
      }),
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Seeded attack scenarios. Each returns rows AND is described in the README.
// ---------------------------------------------------------------------------

/** 1. C2 beaconing: near-perfect 60s interval to a low-reputation domain. */
function scenarioBeaconing() {
  const out = [];
  const u = USERS[7]; // heidi@tenex.local
  const host = "cdn-analytics-sync.top";
  let ms = BASE + 3 * HOUR;
  for (let i = 0; i < 90; i++) {
    // Jitter of +/- 1.5s around a 60s period — the hallmark of a beacon.
    const t = ms + (rand() * 3000 - 1500);
    out.push({
      ms: t,
      line: row({
        ms: t,
        user: u.name,
        dept: u.dept,
        loc: u.loc,
        clientIp: u.ip,
        serverIp: `185.220.101.${between(1, 60)}`,
        method: "POST",
        host,
        url: `https://${host}/api/ping`,
        action: "Allowed",
        status: 200,
        reqSize: between(280, 340),
        respSize: between(90, 140),
        category: "Miscellaneous",
        risk: 55,
        ua: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
      }),
    });
    ms += 60_000;
  }
  return out;
}

/** 2. Data exfiltration: very large uploads to a file-sharing host, off hours. */
function scenarioExfiltration() {
  const out = [];
  const u = USERS[3]; // dan@tenex.local, Finance
  const host = "upload.anonfiles-cdn.ru";
  let ms = BASE + 16.5 * HOUR; // 22:30 UTC — outside working hours
  for (let i = 0; i < 14; i++) {
    out.push({
      ms,
      line: row({
        ms,
        user: u.name,
        dept: u.dept,
        loc: u.loc,
        clientIp: u.ip,
        serverIp: `91.219.236.${between(1, 200)}`,
        method: "POST",
        host,
        url: `https://${host}/upload/chunk-${i + 1}`,
        action: "Allowed",
        status: 200,
        reqSize: between(48_000_000, 96_000_000),
        respSize: between(200, 900),
        category: "File Host",
        risk: 70,
        ua: "python-requests/2.31.0",
      }),
    });
    ms += between(45, 120) * 1000;
  }
  return out;
}

/** 3. Web/port scanning burst: hundreds of requests in ~2 minutes. */
function scenarioScanBurst() {
  const out = [];
  const clientIp = "10.10.4.99"; // unattributed host
  let ms = BASE + 7 * HOUR;
  const paths = ["/admin", "/wp-login.php", "/.env", "/phpmyadmin", "/config.json",
    "/.git/config", "/backup.zip", "/api/v1/users", "/server-status", "/actuator/health",
    "/cgi-bin/test.cgi", "/vendor/phpunit", "/.aws/credentials", "/debug/pprof"];
  for (let i = 0; i < 260; i++) {
    // Pick the path at random rather than cycling: `paths[i % 14]` alongside a
    // `i % 7` host rotation correlates the two, so each host only ever sees two
    // distinct paths — which reads as credential stuffing rather than scanning.
    const p = pick(paths);
    const host = `intranet-${(i % 7) + 1}.tenex.local`;
    out.push({
      ms,
      line: row({
        ms,
        user: "-",
        dept: "-",
        loc: "HQ-Austin",
        clientIp,
        serverIp: `10.20.5.${(i % 7) + 10}`,
        method: "GET",
        host,
        url: `http://${host}${p}`,
        action: rand() < 0.7 ? "Blocked" : "Allowed",
        reason: "Suspicious activity",
        status: pick([404, 403, 404, 401, 404]),
        reqSize: between(120, 300),
        respSize: between(0, 800),
        category: "Miscellaneous",
        risk: 40,
        ua: "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)",
      }),
    });
    ms += between(200, 700); // sub-second gaps
  }
  return out;
}

/** 4. Blocked malware downloads with named threats. */
function scenarioMalware() {
  const out = [];
  const targets = [
    [USERS[10], "free-invoice-templates.biz", "/download/invoice_may.doc.exe", "Win32.Trojan.Emotet"],
    [USERS[10], "free-invoice-templates.biz", "/download/setup_v2.exe", "Win32.Trojan.Emotet"],
    [USERS[14], "cdn.softwarecracks-hub.net", "/get/adobe_crack.zip", "Win32.Adware.InstallCore"],
    [USERS[2], "secure-docs-login.click", "/verify/office365", "Phish.Office365.Credential"],
    [USERS[2], "secure-docs-login.click", "/verify/submit", "Phish.Office365.Credential"],
  ];
  let ms = BASE + 5 * HOUR;
  for (const [u, host, p, threat] of targets) {
    out.push({
      ms,
      line: row({
        ms,
        user: u.name,
        dept: u.dept,
        loc: u.loc,
        clientIp: u.ip,
        serverIp: `194.5.249.${between(1, 200)}`,
        method: "GET",
        host,
        url: `http://${host}${p}`,
        action: "Blocked",
        reason: "Malware detected",
        status: 403,
        reqSize: between(200, 600),
        respSize: 0,
        category: threat.startsWith("Phish") ? "Phishing" : "Malicious Sites",
        threat,
        risk: 95,
        // A real user clicking a bad link uses their own browser.
        ua: u.ua,
      }),
    });
    ms += between(30, 400) * 1000;
  }
  return out;
}

/** 5. Credential brute force: repeated 401s against a single login endpoint. */
function scenarioBruteForce() {
  const out = [];
  const clientIp = "10.10.2.31";
  const host = "vpn.tenex.local";
  let ms = BASE + 9 * HOUR;
  for (let i = 0; i < 70; i++) {
    const success = i === 69; // finally gets in
    out.push({
      ms,
      line: row({
        ms,
        user: success ? "svc_backup@tenex.local" : "-",
        dept: "IT",
        loc: "Remote-VPN",
        clientIp,
        serverIp: "10.20.1.5",
        method: "POST",
        host,
        url: `https://${host}/auth/login`,
        action: "Allowed",
        status: success ? 200 : 401,
        reqSize: between(400, 700),
        respSize: between(120, 400),
        category: "Professional Services",
        risk: 30,
        ua: "curl/8.4.0",
      }),
    });
    ms += between(1200, 4000);
  }
  return out;
}

/** 6. DGA-style domains: many one-off algorithmically generated hostnames. */
function scenarioDga() {
  const out = [];
  const u = USERS[18]; // sybil
  let ms = BASE + 11 * HOUR;
  const letters = "abcdefghijklmnopqrstuvwxyz";
  for (let i = 0; i < 45; i++) {
    let label = "";
    for (let c = 0; c < between(12, 18); c++) label += letters[between(0, 25)];
    const host = `${label}.${pick(["xyz", "top", "info", "cc"])}`;
    out.push({
      ms,
      line: row({
        ms,
        user: u.name,
        dept: u.dept,
        loc: u.loc,
        clientIp: u.ip,
        serverIp: `45.61.${between(1, 254)}.${between(1, 254)}`,
        method: "GET",
        host,
        url: `http://${host}/`,
        action: rand() < 0.5 ? "Blocked" : "Allowed",
        reason: rand() < 0.5 ? "DNS resolution failed" : "-",
        status: pick([0, 404, 502, 200]),
        reqSize: between(100, 300),
        respSize: between(0, 500),
        category: "Newly Registered Domains",
        risk: 65,
        ua: u.ua,
      }),
    });
    ms += between(2, 25) * 1000;
  }
  return out;
}

/** 7. Off-hours admin activity from a normally 9-5 finance user. */
function scenarioOffHours() {
  const out = [];
  const u = USERS[4]; // erin, Finance
  let ms = BASE + 20.2 * HOUR; // ~02:10 UTC next day
  const hosts = [
    ["payroll.tenex.local", "/admin/export?all=true", "Professional Services"],
    ["payroll.tenex.local", "/admin/employees.csv", "Professional Services"],
    ["drive.google.com", "/upload", "File Host"],
  ];
  for (let i = 0; i < 9; i++) {
    const [host, p, cat] = hosts[i % hosts.length];
    out.push({
      ms,
      line: row({
        ms,
        user: u.name,
        dept: u.dept,
        loc: "Remote-VPN",
        clientIp: u.ip,
        serverIp: `10.20.3.${between(10, 40)}`,
        method: i % 3 === 2 ? "POST" : "GET",
        host,
        url: `https://${host}${p}`,
        action: "Allowed",
        status: 200,
        reqSize: i % 3 === 2 ? between(2_000_000, 5_000_000) : between(300, 900),
        respSize: i % 3 === 2 ? between(300, 900) : between(400_000, 3_000_000),
        category: cat,
        risk: 20,
        ua: u.ua,
      }),
    });
    ms += between(60, 300) * 1000;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Assemble
// ---------------------------------------------------------------------------
function build(rows) {
  rows.sort((a, b) => a.ms - b.ms);
  return [
    "#Version: 1.0",
    "#Software: ZScaler NSS Web Log (synthetic sample for SOC Log Analyzer)",
    `#Fields: ${FIELDS.join("\t")}`,
    ...rows.map((r) => r.line),
    "",
  ].join("\n");
}

const benign = benignTraffic(1800);

const withAttacks = build([
  ...benign,
  ...scenarioBeaconing(),
  ...scenarioExfiltration(),
  ...scenarioScanBurst(),
  ...scenarioMalware(),
  ...scenarioBruteForce(),
  ...scenarioDga(),
  ...scenarioOffHours(),
]);

// A second, independent draw of benign-only traffic for false-positive checks.
const benignOnly = build(benignTraffic(900));

await mkdir(path.join(root, "examples"), { recursive: true });
await writeFile(path.join(root, "examples", "zscaler-sample.log"), withAttacks);
await writeFile(path.join(root, "examples", "zscaler-benign.log"), benignOnly);

console.log(
  `wrote examples/zscaler-sample.log (${withAttacks.split("\n").length - 1} lines)`,
);
console.log(
  `wrote examples/zscaler-benign.log (${benignOnly.split("\n").length - 1} lines)`,
);
