/**
 * Changes an existing user's password.
 *
 * `migrate.mjs` only seeds the demo account when the email is absent, so
 * re-running it can't rotate a password that's already been published. This
 * can, and it's the tool for the case where a deployment's credentials have
 * leaked (or were in a public README from the start).
 *
 *   DATABASE_URL='postgresql://…-pooler.…neon.tech/neondb?sslmode=require' \
 *     npm run db:set-password
 *
 * The password is read from stdin with echo disabled rather than taken from an
 * argument or an env var, so it never reaches your shell history or the process
 * list. To script it, pipe instead:  echo 'newpass' | npm run db:set-password
 */
import { createInterface } from "node:readline";
import pg from "pg";
import { hashPassword } from "../src/lib/password.mjs";

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  console.error(
    "\nDATABASE_URL is not set.\n\n" +
      "  DATABASE_URL='<connection string>' npm run db:set-password\n",
  );
  process.exit(1);
}

const email = process.env.DEMO_USER_EMAIL ?? "analyst@tenex.local";

/** Reads one line, hiding it when we're attached to a terminal. */
function readSecret(prompt) {
  return new Promise((resolve) => {
    const isTty = process.stdin.isTTY;
    if (isTty) process.stdout.write(prompt);

    const rl = createInterface({ input: process.stdin, terminal: isTty });

    // With `terminal: true` readline echoes as you type; suppress it so the
    // password never appears on screen or in a screen recording.
    if (isTty) {
      const out = rl.output;
      rl.output = { write: () => {} , ...out };
      rl._writeToOutput = () => {};
    }

    rl.question("", (answer) => {
      rl.close();
      if (isTty) process.stdout.write("\n");
      resolve(answer.trim());
    });
  });
}

const password = await readSecret(`New password for ${email}: `);

if (password.length < 8) {
  console.error("Password must be at least 8 characters. Nothing changed.");
  process.exit(1);
}

const isLocal = /@(localhost|127\.0\.0\.1|host\.docker\.internal)[:/]/.test(
  connectionString,
);
const ssl = isLocal
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

const result = await client.query(
  "UPDATE users SET password_hash = $1 WHERE email = $2 RETURNING id",
  [await hashPassword(password), email],
);

if (result.rowCount === 0) {
  console.error(`\nNo user with email ${email}. Nothing changed.`);
  console.error("Set DEMO_USER_EMAIL if the account uses a different address.");
  await client.end();
  process.exit(1);
}

await client.end();
console.log(`\nPassword updated for ${email}. Existing sessions stay valid `);
console.log("until they expire (8h) — they are signed by AUTH_SECRET, not the");
console.log("password. Rotate AUTH_SECRET too if you need to revoke them now.");
