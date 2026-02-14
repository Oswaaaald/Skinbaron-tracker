import pg from 'pg';
import { drizzle, NodePgDatabase } from 'drizzle-orm/node-postgres';
import * as schema from './schema.js';
import { appConfig } from '../lib/config.js';

const pool = new pg.Pool({
  connectionString: appConfig.DATABASE_URL,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
});

export const db = drizzle(pool, { schema });

export type AppDatabase = NodePgDatabase<typeof schema>;

export async function closeDatabase(): Promise<void> {
  await pool.end();
}

/**
 * Check database connectivity (used by health checks)
 */
export async function checkDatabaseHealth(): Promise<boolean> {
  try {
    const client = await pool.connect();
    try {
      const result = await client.query('SELECT 1 as test');
      return result.rows[0]?.test === 1;
    } finally {
      client.release();
    }
  } catch {
    return false;
  }
}
