# SOC Log Analyzer

Upload a web proxy log, get back a triaged incident report: a timeline of what
happened, a ranked list of findings, and — for each finding — a plain-English
explanation of *why* it was flagged plus a confidence score.

Built for the Tenex full-stack cybersecurity take-home.

---

## Quick start

Requires **Node 20+** and **Docker**.

```bash
git clone <this-repo> && cd soc-log-analyzer
npm install

cp .env.example .env       # defaults work as-is for local development
npm run db:up              # Postgres 16 via Docker Compose (host port 5433)
npm run db:migrate         # applies db/schema.sql, seeds the demo user
npm run dev                # http://localhost:3000
```

Sign in with:

| Email | Password |
|---|---|
| `analyst@tenex.local` | `SocAnalyst!2024` |

Then upload **`examples/zscaler-sample.log`** from this repository. It contains
~2,300 events of ordinary corporate browsing with seven attack scenarios seeded
into it, and should produce 13 findings.

Also try **`examples/zscaler-benign.log`** — an independent draw of purely normal
traffic. It should come back completely clean. That file exists specifically so
the false-positive rate is demonstrable rather than asserted.

<details>
<summary>Other commands</summary>

```bash
npm test           # parser + detector unit tests (Vitest)
npm run typecheck  # tsc --noEmit
npm run build      # production build
npm run gen:logs   # regenerate the example logs (deterministic)
npm run db:reset   # wipe and recreate the database
npm run db:down    # stop Postgres
```
</details>

> **Port note:** Postgres is published on **5433**, not 5432, so it won't collide
> with an existing local Postgres.

---

## Stack

| Layer | Choice | Why |
|---|---|---|
| Frontend | Next.js 16 (App Router), React 19, TypeScript, Tailwind v4 | Required TS + modern framework |
| Backend | Next.js Route Handlers | A REST API in the same TS project — no separate service to run |
| Database | PostgreSQL 16 (Docker) | Required "modern database"; `JSONB` + array columns fit this data well |
| DB access | `pg` with hand-written SQL | No ORM: every query is visible and explainable |
| Auth | JWT in an httpOnly cookie (`jose`) + scrypt password hashing | Basic auth, no third-party dependency |
| AI | Claude (`@anthropic-ai/sdk`), optional | See [How AI is used](#how-ai-is-used) |
| Tests | Vitest | Parser and detector correctness |

Deliberately **no ORM and no charting library.** Both would have been faster to
write, but the exercise says to only submit code I can thoroughly explain, and
the parts most worth explaining here are the SQL and the chart geometry.

---

## Log format

The parser targets **ZScaler NSS web proxy logs** in tab-separated feed format.

```
#Fields: datetime	user	department	location	clientip	serverip	method	host	url	action	reason	statuscode	requestsize	responsesize	urlcategory	threatname	riskscore	useragent	referer	appname
2024-05-14 08:08:39	frank@tenex.local	Legal	HQ-Austin	10.10.2.25	104.16.24.172	GET	registry.npmjs.org	https://…	Allowed	-	200	861	43719	Software Downloads	-	0	Mozilla/5.0…	-	-
```

Two properties make it tolerant of real files (`src/lib/parser.ts`):

1. **Header-driven.** A `#Fields:` line defines the column order, so a feed
   configured with a different field set still parses. Field names are
   normalised and aliased (`cip`, `clientip`, `Client IP` → the same column), and
   the parser falls back to a documented default order when there is no header.
2. **Line-level fault tolerance.** A short row, an over-long row, or junk in a
   numeric column still yields an event. Only an unparseable **timestamp**
   rejects a line — without one the row is useless for timeline and rate
   analysis. Rejected lines are counted and surfaced in the UI rather than
   silently dropped.

Timestamps without a zone marker are pinned to **UTC** (which is what NSS emits)
rather than drifting with the server's local timezone.

---

## Anomaly detection

**All detection is deterministic** — statistics and rules, no model inference.
Eight detectors run over the parsed events in `src/lib/detectors.ts`.

That is a deliberate choice for a security tool. An analyst has to be able to
ask *"why did this fire?"* and get an answer they can re-derive from the log
themselves. So every finding carries the observed numbers in its explanation
text and an `evidence` object with the raw inputs to its score. It also makes
the whole engine testable, which is what `tests/detectors.test.ts` does.

### The detectors

| Detector | Fires on | Core signal |
|---|---|---|
| `threat_signature` | Proxy named a threat, or blocked with a malware/phishing reason | Direct evidence — highest confidence floor |
| `request_rate_spike` | *"Unusual number of requests from a single IP in a short time frame"* | Peak count in a sliding 60s window vs. the robust z-score across all client IPs |
| `c2_beaconing` | Machine-regular callbacks to one host | Mean absolute deviation of inter-arrival gaps as a fraction of the median gap |
| `data_exfiltration` | Bulk upload to one destination | Total bytes sent per (client, host) vs. population, plus upload/download asymmetry |
| `auth_failure_burst` | Credential stuffing / brute force | 401/403 volume, failure ratio, attempt rate, and endpoint concentration |
| `dga_domains` | Algorithmically generated hostnames | Shannon entropy, vowel ratio, longest consonant run, label length |
| `off_hours_activity` | A user working outside the org's own pattern | Business hours derived from the log's own hourly histogram |
| `suspicious_user_agent` | Attack tooling / scripted clients | Weighted match list (Nmap ≫ curl) |

### Why robust statistics

Everything comparative uses **median and MAD** (median absolute deviation),
never mean and standard deviation:

```
robust z = (x − median) / (1.4826 × MAD)
```

Log data is heavy-tailed, and the outliers are exactly what we are hunting. A
mean-based z-score gets dragged toward the attacker's own traffic and hides the
thing it is supposed to surface. When MAD is zero — common when most clients
make the same small number of requests — the score falls back to a scale derived
from the median so it stays finite instead of returning infinity for every
outlier.

### How confidence is computed

Each detector normalises its evidence onto 0–1 and blends the components with
fixed, documented weights. Two recurring ingredients:

- **z-factor** — how extreme the value is vs. peers, mapped so z=3 is weak and
  z=10 is certain.
- **volume factor** — more corroborating events means more confidence, saturating
  so 500 events isn't treated as ten times more certain than 50.

Worked example — beaconing:

```
confidence = 0.55 × interval regularity
           + 0.25 × callback volume
           + 0.20 × payload-size uniformity
```

The weights encode a judgement: *regularity* is what actually distinguishes a
beacon from human browsing, so it dominates; the other two corroborate.

Two rules keep the scores honest:

- **Detectors that observe direct evidence start high; detectors that infer
  intent are capped.** `threat_signature` starts at 0.90 because the proxy's own
  inspection engine named the threat. `dga_domains` is capped at 0.85 and
  `off_hours_activity` at 0.70, because both have genuinely benign explanations
  (CDN shard hostnames; someone working late).
- **Nothing is ever reported at 1.00.** All confidences are clamped to ≤ 0.97.
  These are heuristics over a single log file with no endpoint, identity, or
  threat-intel context to corroborate them. A 0.97 still reads as "act on this",
  but the tool never tells an analyst a verdict is beyond question.

### Tuning that came out of testing

Two false-positive classes showed up when the detectors were first run against
the benign sample, and both fixes are in the code with comments explaining them:

- **Off-hours fired on everybody.** The first version defined business hours as
  "the busiest hours covering 90% of traffic", which *always* carves off the
  quietest normal hour — so every user picked up a spurious finding. It now
  counts an hour as business hours if it carries ≥20% of the peak hour's traffic.
  Benign traffic went from 10 findings to 0.
- **The port scanner was reported as a brute-force attack.** Its 401/403s tripped
  `auth_failure_burst`. Real credential stuffing hammers *one* endpoint; a
  scanner sprays many. Requiring the failures to concentrate on a single URL
  (≥50%) separates them cleanly — brute force scores 1.0 concentration, the
  scanner ~0.07.

---

## How AI is used

**The LLM writes prose. It does not detect anything and it cannot change a
score.** It is used in exactly one place: `src/lib/narrative.ts`.

| | |
|---|---|
| **Model** | `claude-opus-5` via `@anthropic-ai/sdk`, at `effort: "low"` |
| **Task** | Write the *shift handover brief* — the paragraph at the top of the report that says what happened and what to look at first |
| **Input** | Only the aggregate statistics and the finished findings. **Never raw log lines.** |
| **Runs** | Once per upload, after detection and persistence have completed |
| **Required?** | No. With no `ANTHROPIC_API_KEY` the app falls back to a rule-generated brief and everything else works identically |

The prompt (in `narrative.ts`) instructs the model to correlate findings that
share an IP or user — which is the genuinely useful thing it adds over the
deterministic summary — and forbids it from inventing hosts, IPs, users, or
numbers not present in the input.

**Why this split.** An LLM that hallucinates prose is a cosmetic problem. An LLM
that hallucinates a severity score is a security problem — it produces findings
nobody can reproduce or defend, and it makes the detection layer untestable.
Keeping scoring deterministic means the findings are byte-identical across runs
and covered by unit tests; the model only writes the narration on top.

Sending only aggregates also keeps the prompt small and bounded regardless of
file size, and avoids shipping the full contents of a customer's proxy log to a
third party.

The UI labels which path produced the brief, so it is never ambiguous whether a
human is reading model output or rule output.

To enable it, add to `.env`:

```
ANTHROPIC_API_KEY=sk-ant-...
```

Because log analysis is security-adjacent, the code also handles the model
declining the request (`stop_reason: "refusal"`) — that falls back to the
deterministic brief rather than failing the upload, as do network errors and
rate limits.

---

## REST API

All endpoints require the session cookie and return JSON. Every query is scoped
by `user_id` as well as resource id, so a valid session cannot read another
user's data by guessing a UUID.

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/auth/login` | `{email, password}` → sets httpOnly session cookie |
| `POST` | `/api/auth/logout` | Clears the cookie |
| `GET` | `/api/auth/me` | Current user, or 401 |
| `POST` | `/api/uploads` | `multipart/form-data` with `file` → parses, detects, persists |
| `GET` | `/api/uploads` | The user's uploads, newest first |
| `GET` | `/api/uploads/:id` | Full report: stats, timeline, findings, brief |
| `DELETE` | `/api/uploads/:id` | Deletes upload (cascades to events and findings) |
| `GET` | `/api/uploads/:id/events` | Paginated events. Query: `limit`, `offset`, `q`, `action`, `anomalousOnly` |

```bash
# Example
curl -c jar -X POST localhost:3000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"analyst@tenex.local","password":"SocAnalyst!2024"}'

curl -b jar -X POST localhost:3000/api/uploads \
  -F "file=@examples/zscaler-sample.log"
```

---

## Architecture

```
Upload  →  parse  →  detect  →  aggregate  →  persist  →  (optional) LLM brief
           │         │          │             │
           │         │          │             └─ one transaction: uploads,
           │         │          │                log_events, anomalies
           │         │          └─ timeline buckets + top-N rollups, stored as
           │         │             JSONB so opening a report is one indexed read
           │         └─ 8 deterministic detectors → findings with line numbers
           └─ header-driven, fault-tolerant
```

```
src/
  lib/
    parser.ts      ZScaler log → typed events
    detectors.ts   the eight detectors + confidence model
    stats.ts       median, MAD, robust z, Shannon entropy
    analysis.ts    timeline bucketing + top-N rollups
    ingest.ts      the pipeline above, in one transaction
    narrative.ts   the only LLM call (optional)
    auth.ts        JWT sessions; password.mjs holds scrypt hashing
    db.ts          pooled pg client
  app/
    api/           REST route handlers
    page.tsx       dashboard: upload + previous analyses
    uploads/[id]/  the report
  components/      TimelineChart, AnomalyCard, EventTable, UploadPanel
  proxy.ts         Next 16 middleware — optimistic redirect only
db/schema.sql      applied idempotently by npm run db:migrate
```

**Findings link back to raw lines.** Each finding stores the `event_line_nos`
that triggered it, which is what lets the report highlight the specific rows in
the event table and tag them with the detector responsible. Going from "there is
a beacon" to "these are the actual requests" is one click.

### Security notes

- Passwords hashed with **scrypt** (`node:crypto`), salt stored with the hash,
  verified in constant time.
- Session JWT in an **httpOnly, SameSite=Lax** cookie — not readable from JS, so
  XSS can't steal it; `Secure` in production.
- `src/proxy.ts` (Next 16's renamed middleware) only does an **optimistic**
  redirect so browsers don't flash an empty dashboard. It is *not* the
  authorisation boundary — every route handler and page independently calls
  `currentUser()` and scopes its queries. The proxy never touches the database
  and can't tell whether a user still exists.
- All SQL is parameterised.
- Login returns an identical response for unknown user and wrong password, so it
  can't be used to enumerate accounts.
- The brief is rendered through a small closed set of elements, never as raw
  HTML, so nothing in model output can inject markup.
- Upload limits: 32 MB, extension allow-list.

### Accessibility and visual design

The two chart colours were validated against colourblind-separation, lightness,
chroma and contrast checks for both light and dark surfaces (they pass all five
in both modes). Severity is never carried by colour alone — every badge has a
glyph and the word. Dark mode is a separately chosen set of steps, not an
automatic inversion. The chart is hand-written SVG with a legend, a hover
readout, and an `aria-label` describing it.

---

## Tests

```bash
npm test
```

22 tests over the parser and detectors. The ones that matter most:

- The full 2,296-line sample parses with **zero** malformed lines.
- Every one of the eight detectors fires on the sample.
- Each seeded scenario is matched specifically — the beacon is found at exactly
  60s intervals over 90 callbacks; the brute force reports 69 failures *and* the
  successful login that followed.
- The scanner is **not** reported as credential stuffing.
- No finding ever reports confidence above 0.97.
- **`zscaler-benign.log` produces zero findings** — the strongest guard against
  the detectors being noise.

---

## Example logs

Generated by `scripts/generate-sample-logs.mjs` with a seeded PRNG and a fixed
base date, so they're reproducible and the file contents are stable.

`examples/zscaler-sample.log` — ~1,800 benign events plus seven scenarios:

| # | Scenario | What it looks like |
|---|---|---|
| 1 | C2 beaconing | 90 callbacks to `cdn-analytics-sync.top` at 60s ±1.5s |
| 2 | Data exfiltration | 887 MB uploaded to `upload.anonfiles-cdn.ru` at 22:30 |
| 3 | Scanning burst | 260 requests in ~2 min across admin/`.env`/`.git` paths |
| 4 | Malware & phishing | Blocked Emotet, InstallCore, and an O365 credential phish |
| 5 | Brute force | 70 failed VPN logins, then one success |
| 6 | DGA domains | 45 requests to random-looking `.xyz`/`.top` hostnames |
| 7 | Off-hours access | A finance user pulling payroll exports at 02:10 |

`examples/zscaler-benign.log` — ~900 events, normal traffic only.

---

## Trade-offs and what I'd do next

Built as a functional prototype in the suggested time budget. Things I chose not
to do, and would do next:

- **Ingest is synchronous.** Fine for the 32 MB limit; a real deployment needs a
  job queue with the upload returning immediately and the UI polling status. The
  `uploads.status` column already exists for this.
- **Detector thresholds are constants.** They're centralised in `DEFAULT_CONFIG`
  and each is justified in a comment, but a real product would learn a baseline
  per organisation instead — the current design compares each entity against the
  *rest of the same file*, which is a reasonable proxy but breaks down on a file
  containing only one host.
- **Single-tenant auth.** One user table, no roles, no password reset, no rate
  limiting on login. Session lifetime is a fixed 8 hours ("one shift").
- **No enrichment.** Findings would be far stronger joined against threat intel,
  asset inventory, and identity data. The `evidence` JSON on each finding is
  shaped to make that additive.
- **Detectors are independent.** They don't yet correlate — the brief does that
  narratively, but `10.10.4.99` triggering both a rate spike and an Nmap
  user-agent should really collapse into one higher-confidence incident.
