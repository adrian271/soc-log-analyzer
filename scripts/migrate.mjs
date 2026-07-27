/**
 * Applies db/schema.sql and seeds the demo user.
 *
 * Run with: npm run db:migrate
 * (package.json passes --env-file=.env so DATABASE_URL is picked up.)
 */
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import pg from "pg";
import { hashPassword } from "../src/lib/password.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const connectionString =
  process.env.DATABASE_URL ??
  "postgresql://soc:soc_dev_password@localhost:5433/soc_logs";

const DEMO_EMAIL = process.env.DEMO_USER_EMAIL ?? "analyst@tenex.local";
const DEMO_PASSWORD = process.env.DEMO_USER_PASSWORD ?? "SocAnalyst!2024";

/**
 * Same rule as src/lib/db.ts: the Docker Postgres speaks plaintext, every
 * managed provider requires TLS.
 *
 * `pg` will pick up `sslmode=require` from the connection string on its own,
 * but a string pasted without that parameter silently gets no TLS and the
 * provider closes the connection — a confusing failure for a one-off command.
 * Deciding it from the host removes that footgun.
 */
const isLocal = /@(localhost|127\.0\.0\.1|host\.docker\.internal)[:/]/.test(
  connectionString,
);
// When the URL carries `sslmode`, pg builds its own ssl config from it and
// discards ours — so only supply one when the URL is silent. See src/lib/db.ts.
const urlDeclaresSsl = /[?&]sslmode=/.test(connectionString);
const ssl = isLocal || urlDeclaresSsl
  ? undefined
  : { rejectUnauthorized: process.env.PGSSL_NO_VERIFY !== "true" };

const client = new pg.Client({ connectionString, ssl });

try {
  await client.connect();
} catch (err) {
  // Redact the password before printing — this command is usually run with a
  // production connection string pasted into a shared terminal.
  const safe = connectionString.replace(/:\/\/([^:]+):[^@]*@/, "://$1:****@");
  console.error(`\nCould not connect to Postgres at ${safe}`);
  console.error(
    isLocal
      ? "Is the database running?  ->  docker compose up -d\n"
      : "Check the connection string, and that it is the POOLED endpoint\n" +
          "(the host should contain '-pooler').\n",
  );
  console.error(err.message);
  process.exit(1);
}

const schema = await readFile(path.join(root, "db", "schema.sql"), "utf8");
await client.query(schema);
console.log("schema applied");

// Idempotent seed: only insert the demo user if the email is not taken.
const existing = await client.query("SELECT id FROM users WHERE email = $1", [
  DEMO_EMAIL,
]);
if (existing.rowCount === 0) {
  await client.query(
    "INSERT INTO users (email, password_hash) VALUES ($1, $2)",
    [DEMO_EMAIL, await hashPassword(DEMO_PASSWORD)],
  );
  console.log(`seeded demo user: ${DEMO_EMAIL} / ${DEMO_PASSWORD}`);
} else {
  console.log(`demo user already present: ${DEMO_EMAIL}`);
}

await client.end();
console.log("done");
