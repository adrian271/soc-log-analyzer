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

const client = new pg.Client({ connectionString });

try {
  await client.connect();
} catch (err) {
  console.error(`\nCould not connect to Postgres at ${connectionString}`);
  console.error("Is the database running?  ->  docker compose up -d\n");
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
