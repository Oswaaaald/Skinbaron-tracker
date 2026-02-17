import { eq, lt } from 'drizzle-orm';
import { pendingChallenges } from '../schema.js';
import type { AppDatabase } from '../connection.js';

export class ChallengesRepository {
  constructor(private db: AppDatabase) {}

  /**
   * Store a pending challenge with TTL.
   * Upserts: if the key already exists, it is replaced.
   */
  async store(key: string, type: string, value: string, ttlMs: number): Promise<void> {
    const expiresAt = new Date(Date.now() + ttlMs);
    await this.db.insert(pendingChallenges)
      .values({ key, type, value, expires_at: expiresAt })
      .onConflictDoUpdate({
        target: pendingChallenges.key,
        set: { type, value, expires_at: expiresAt },
      });
  }

  /**
   * Get a pending challenge without consuming it.
   * Returns null if not found or expired.
   */
  async get(key: string): Promise<string | null> {
    const [row] = await this.db.select({ value: pendingChallenges.value, expires_at: pendingChallenges.expires_at })
      .from(pendingChallenges)
      .where(eq(pendingChallenges.key, key))
      .limit(1);
    if (!row || row.expires_at < new Date()) {
      if (row) await this.delete(key);
      return null;
    }
    return row.value;
  }

  /**
   * Consume a pending challenge (get + delete atomically).
   * Returns null if not found or expired.
   */
  async consume(key: string): Promise<string | null> {
    const [row] = await this.db.delete(pendingChallenges)
      .where(eq(pendingChallenges.key, key))
      .returning({ value: pendingChallenges.value, expires_at: pendingChallenges.expires_at });
    if (!row || row.expires_at < new Date()) return null;
    return row.value;
  }

  /**
   * Delete a specific challenge.
   */
  async delete(key: string): Promise<void> {
    await this.db.delete(pendingChallenges)
      .where(eq(pendingChallenges.key, key));
  }

  /**
   * Cleanup all expired challenges. Called periodically.
   */
  async cleanup(): Promise<number> {
    const result = await this.db.delete(pendingChallenges)
      .where(lt(pendingChallenges.expires_at, new Date()))
      .returning({ key: pendingChallenges.key });
    return result.length;
  }
}
