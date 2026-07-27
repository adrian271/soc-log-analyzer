import { Pool } from "pg";

/**
 * A single shared connection pool.
 *
 * Next dev mode hot-reloads modules, which would otherwise leak a new pool on
 * every edit, so the pool is stashed on globalThis.
 */
const globalForDb = globalThis as unknown as { __socPool?: Pool };

export const pool: Pool =
  globalForDb.__socPool ??
  new Pool({
    connectionString:
      process.env.DATABASE_URL ??
      "postgresql://soc:soc_dev_password@localhost:5433/soc_logs",
    max: 10,
  });

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
