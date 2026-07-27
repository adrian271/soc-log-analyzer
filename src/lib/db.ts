import { Pool } from "pg";

/**
 * A single shared connection pool.
 *
 * Next dev mode hot-reloads modules, which would otherwise leak a new pool on
 * every edit, so the pool is stashed on globalThis.
 */
const globalForDb = globalThis as unknown as { __socPool?: Pool };

const LOCAL_DEFAULT = "postgresql://soc:soc_dev_password@localhost:5433/soc_logs";
const connectionString = process.env.DATABASE_URL ?? LOCAL_DEFAULT;

const isLocal = /@(localhost|127\.0\.0\.1|host\.docker\.internal)[:/]/.test(
  connectionString,
);

/**
 * The Docker Postgres in docker-compose.yml speaks plaintext; every managed
 * provider (Neon, Supabase, RDS) requires TLS and will refuse the connection
 * without it. Certificates are verified by default — set PGSSL_NO_VERIFY=true
 * only if your provider serves a chain Node can't verify.
 */
const ssl = isLocal
  ? undefined
  : { rejectUnauthorized: process.env.PGSSL_NO_VERIFY !== "true" };

/**
 * Serverless changes what a "pool" means. Locally one long-lived process owns
 * the pool, so a larger one is free. On Vercel every warm function instance
 * holds its own, so `max` is multiplied by the number of live instances and a
 * generous value exhausts the provider's connection limit under light load.
 * Keep it small and let a pooled connection string (Neon's `-pooler` endpoint)
 * do the real multiplexing.
 */
const max = isLocal ? 10 : 3;

export const pool: Pool =
  globalForDb.__socPool ?? new Pool({ connectionString, ssl, max });

if (process.env.NODE_ENV !== "production") globalForDb.__socPool = pool;

export async function query<T extends Record<string, unknown>>(
  text: string,
  params?: unknown[],
): Promise<T[]> {
  const result = await pool.query(text, params as never[]);
  return result.rows as T[];
}

/** Runs `fn` inside a transaction, rolling back on any throw. */
export async function transaction<T>(
  fn: (client: import("pg").PoolClient) => Promise<T>,
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const out = await fn(client);
    await client.query("COMMIT");
    return out;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}
