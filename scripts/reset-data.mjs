/**
 * Clears every upload and its analysis from a database, leaving user accounts
 * intact — the remote equivalent of wanting an empty dashboard.
 *
 *   DATABASE_URL='postgresql://…-pooler.…neon.tech/neondb?sslmode=verify-full' \
 *     npm run db:reset:remote
 *
 * `db:reset` destroys the Docker volume, which has no counterpart on a managed
 * provider. This does the thing you actually want before a demo: wipe the data,
 * keep the login.
 *
 * It is destructive and usually pointed at production, so it prints what it is
 * about to delete and waits for confirmation. Set CONFIRM=yes to skip the
 * prompt when scripting.
 */
import { createInterface } from "node:readline";
import pg from "pg";

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  console.error(
    "\nDATABASE_URL is not set.\n\n" +
      "  DATABASE_URL='<connection string>' npm run db:reset:remote\n",
  );
  process.exit(1);
}

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
  const safe = connectionString.replace(/:\/\/([^:]+):[^@]*@/, "://$1:****@");
  console.error(`\nCould not connect to Postgres at ${safe}`);
  console.error(err.message);
  process.exit(1);
}

// Show the damage before doing it. Deleting the wrong database is a bad
// afternoon, and the connection string is easy to paste incorrectly.
const { rows } = await client.query(`
  SELECT
    current_database()                        AS db,
    (SELECT count(*) FROM uploads)::int       AS uploads,
    (SELECT count(*) FROM log_events)::int    AS events,
    (SELECT count(*) FROM anomalies)::int     AS anomalies,
    (SELECT count(*) FROM users)::int         AS users
`);
const s = rows[0];

// Host, not the full string — no password on screen.
const host = /@([^/?]+)/.exec(connectionString)?.[1] ?? "unknown host";

console.log(`\n  database : ${s.db} @ ${host}`);
console.log(`  will delete:  ${s.uploads} upload(s), ${s.events} event(s), ${s.anomalies} finding(s)`);
console.log(`  will keep  :  ${s.users} user account(s)\n`);

if (s.uploads === 0 && s.events === 0) {
  console.log("Already empty. Nothing to do.");
  await client.end();
  process.exit(0);
}

if (process.env.CONFIRM !== "yes") {
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  const answer = await new Promise((resolve) =>
    rl.question("Type 'delete' to continue: ", (a) => {
      rl.close();
      resolve(a.trim());
    }),
  );
  if (answer !== "delete") {
    console.log("Cancelled. Nothing changed.");
    await client.end();
    process.exit(0);
  }
}

// log_events and anomalies both reference uploads ON DELETE CASCADE, so
// truncating the parent clears all three. RESTART IDENTITY resets the serial
// counters so a fresh demo starts from clean ids.
await client.query("TRUNCATE uploads RESTART IDENTITY CASCADE");

await client.end();
console.log("\nDone. Uploads, events and findings cleared; accounts untouched.");
