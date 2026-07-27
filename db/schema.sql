-- SOC Log Analyzer schema.
-- Applied idempotently by `npm run db:migrate` (scripts/migrate.mjs).

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  id            SERIAL PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One row per uploaded log file.
CREATE TABLE IF NOT EXISTS uploads (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  filename        TEXT NOT NULL,
  size_bytes      INTEGER NOT NULL,
  status          TEXT NOT NULL DEFAULT 'processing',  -- processing | ready | failed
  error           TEXT,
  total_lines     INTEGER NOT NULL DEFAULT 0,
  parsed_lines    INTEGER NOT NULL DEFAULT 0,
  malformed_lines INTEGER NOT NULL DEFAULT 0,
  range_start     TIMESTAMPTZ,
  range_end       TIMESTAMPTZ,
  stats           JSONB,        -- aggregate rollups computed at ingest time
  narrative       TEXT,         -- LLM-written SOC summary (nullable: LLM is optional)
  narrative_model TEXT,         -- which model produced `narrative`, or NULL
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS uploads_user_idx ON uploads (user_id, created_at DESC);

-- One row per successfully parsed log line.
CREATE TABLE IF NOT EXISTS log_events (
  id             BIGSERIAL PRIMARY KEY,
  upload_id      UUID NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
  line_no        INTEGER NOT NULL,
  ts             TIMESTAMPTZ NOT NULL,
  username       TEXT,
  department     TEXT,
  location       TEXT,
  client_ip      TEXT,
  server_ip      TEXT,
  host           TEXT,
  url            TEXT,
  method         TEXT,
  status_code    INTEGER,
  action         TEXT,           -- Allowed | Blocked
  reason         TEXT,
  bytes_sent     BIGINT,
  bytes_received BIGINT,
  category       TEXT,
  threat_name    TEXT,
  risk_score     INTEGER,
  user_agent     TEXT,
  referer        TEXT,
  app_name       TEXT,
  raw            TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS log_events_upload_ts_idx  ON log_events (upload_id, ts);
CREATE INDEX IF NOT EXISTS log_events_upload_line_idx ON log_events (upload_id, line_no);
CREATE INDEX IF NOT EXISTS log_events_client_ip_idx  ON log_events (upload_id, client_ip);

-- One row per anomaly finding. `event_line_nos` links a finding back to the
-- specific lines that triggered it so the UI can highlight them.
CREATE TABLE IF NOT EXISTS anomalies (
  id             SERIAL PRIMARY KEY,
  upload_id      UUID NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
  detector       TEXT NOT NULL,     -- stable id of the rule that fired
  title          TEXT NOT NULL,
  severity       TEXT NOT NULL,     -- low | medium | high | critical
  confidence     REAL NOT NULL,     -- 0.0 - 1.0
  explanation    TEXT NOT NULL,     -- plain-English "why this was flagged"
  entity         TEXT,              -- the IP / user / host the finding is about
  entity_kind    TEXT,              -- client_ip | username | host
  first_seen     TIMESTAMPTZ,
  last_seen      TIMESTAMPTZ,
  event_count    INTEGER NOT NULL DEFAULT 0,
  event_line_nos INTEGER[] NOT NULL DEFAULT '{}',
  evidence       JSONB              -- detector-specific supporting numbers
);

CREATE INDEX IF NOT EXISTS anomalies_upload_idx ON anomalies (upload_id, confidence DESC);
