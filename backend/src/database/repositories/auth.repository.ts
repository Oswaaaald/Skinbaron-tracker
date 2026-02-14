import { eq, and, or, lt, sql, isNotNull } from 'drizzle-orm';
import { refreshTokens, accessTokenBlacklist } from '../schema.js';
import type { AppDatabase } from '../connection.js';
import type { RefreshTokenRecord } from '../schema.js';
import { hashToken } from '../utils/encryption.js';

export class AuthRepository {
  constructor(private db: AppDatabase) {}

  async addRefreshToken(userId: number, rawToken: string, jti: string, expiresAt: number): Promise<void> {
    const tokenHash = hashToken(rawToken);
    await this.db.insert(refreshTokens).values({
      user_id: userId,
      token_hash: tokenHash,
      token_jti: jti,
      expires_at: new Date(expiresAt),
    });
  }

  async getRefreshToken(rawToken: string): Promise<RefreshTokenRecord | null> {
    const tokenHash = hashToken(rawToken);
    const [token] = await this.db.select()
      .from(refreshTokens)
      .where(eq(refreshTokens.token_hash, tokenHash))
      .limit(1);
    return token ?? null;
  }

  async revokeRefreshToken(rawToken: string, replacedByJti: string): Promise<void> {
    const tokenHash = hashToken(rawToken);
    await this.db.update(refreshTokens)
      .set({ revoked_at: new Date(), replaced_by_jti: replacedByJti })
      .where(eq(refreshTokens.token_hash, tokenHash));
  }

  async revokeAllForUser(userId: number): Promise<void> {
    await this.db.update(refreshTokens)
      .set({ revoked_at: new Date() })
      .where(and(
        eq(refreshTokens.user_id, userId),
        sql`${refreshTokens.revoked_at} IS NULL`
      ));
  }

  async cleanupRefreshTokens(): Promise<void> {
    await this.db.delete(refreshTokens).where(
      or(
        isNotNull(refreshTokens.revoked_at),
        lt(refreshTokens.expires_at, sql`NOW()`)
      )
    );
  }

  async blacklistAccessToken(jti: string, userId: number, expiresAt: number, reason: string): Promise<void> {
    await this.db.insert(accessTokenBlacklist)
      .values({
        jti,
        user_id: userId,
        expires_at: new Date(expiresAt),
        reason,
      })
      .onConflictDoUpdate({
        target: accessTokenBlacklist.jti,
        set: {
          user_id: userId,
          expires_at: new Date(expiresAt),
          reason,
          created_at: new Date(),
        },
      });
  }

  async isBlacklisted(jti: string): Promise<boolean> {
    const [token] = await this.db.select({ jti: accessTokenBlacklist.jti })
      .from(accessTokenBlacklist)
      .where(eq(accessTokenBlacklist.jti, jti))
      .limit(1);
    return !!token;
  }

  async cleanupExpiredBlacklistTokens(): Promise<void> {
    await this.db.delete(accessTokenBlacklist).where(
      lt(accessTokenBlacklist.expires_at, sql`NOW()`)
    );
  }
}
