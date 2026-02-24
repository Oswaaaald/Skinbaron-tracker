import { eq, and, lt, sql } from 'drizzle-orm';
import { refreshTokens, accessTokenBlacklist } from '../schema.js';
import type { AppDatabase } from '../connection.js';
import type { RefreshTokenRecord } from '../schema.js';
import { hashToken } from '../utils/encryption.js';

export class AuthRepository {
  constructor(private db: AppDatabase) {}

  async addRefreshToken(userId: number, rawToken: string, jti: string, expiresAt: number, ipAddress?: string, userAgent?: string, accessTokenJti?: string): Promise<void> {
    const tokenHash = hashToken(rawToken);
    await this.db.insert(refreshTokens).values({
      user_id: userId,
      token_hash: tokenHash,
      token_jti: jti,
      access_token_jti: accessTokenJti ?? null,
      expires_at: new Date(expiresAt),
      ip_address: ipAddress ?? null,
      user_agent: userAgent ?? null,
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

  async revokeAllForUser(userId: number): Promise<string[]> {
    const result = await this.db.update(refreshTokens)
      .set({ revoked_at: new Date() })
      .where(and(
        eq(refreshTokens.user_id, userId),
        sql`${refreshTokens.revoked_at} IS NULL`
      ))
      .returning({ access_token_jti: refreshTokens.access_token_jti });
    return result.map(r => r.access_token_jti).filter((jti): jti is string => jti !== null);
  }

  async getActiveSessionsForUser(userId: number): Promise<Pick<RefreshTokenRecord, 'id' | 'token_jti' | 'ip_address' | 'user_agent' | 'created_at' | 'expires_at'>[]> {
    return this.db.select({
      id: refreshTokens.id,
      token_jti: refreshTokens.token_jti,
      ip_address: refreshTokens.ip_address,
      user_agent: refreshTokens.user_agent,
      created_at: refreshTokens.created_at,
      expires_at: refreshTokens.expires_at,
    })
      .from(refreshTokens)
      .where(and(
        eq(refreshTokens.user_id, userId),
        sql`${refreshTokens.revoked_at} IS NULL`,
        sql`${refreshTokens.expires_at} > NOW()`
      ))
      .orderBy(sql`${refreshTokens.created_at} DESC`);
  }

  async revokeSessionById(sessionId: number, userId: number): Promise<{ revoked: boolean; accessTokenJti: string | null }> {
    const result = await this.db.update(refreshTokens)
      .set({ revoked_at: new Date() })
      .where(and(
        eq(refreshTokens.id, sessionId),
        eq(refreshTokens.user_id, userId),
        sql`${refreshTokens.revoked_at} IS NULL`
      ))
      .returning({ id: refreshTokens.id, access_token_jti: refreshTokens.access_token_jti });
    if (result.length === 0) return { revoked: false, accessTokenJti: null };
    return { revoked: true, accessTokenJti: result[0]?.access_token_jti ?? null };
  }

  async revokeAllOtherSessions(userId: number, currentJti: string): Promise<string[]> {
    const result = await this.db.update(refreshTokens)
      .set({ revoked_at: new Date() })
      .where(and(
        eq(refreshTokens.user_id, userId),
        sql`${refreshTokens.revoked_at} IS NULL`,
        sql`${refreshTokens.token_jti} != ${currentJti}`
      ))
      .returning({ access_token_jti: refreshTokens.access_token_jti });
    return result.map(r => r.access_token_jti).filter((jti): jti is string => jti !== null);
  }

  async cleanupRefreshTokens(): Promise<void> {
    // Only delete expired tokens. Revoked-but-not-expired tokens are kept
    // so that the replaced_by_jti chain remains intact for token reuse detection.
    await this.db.delete(refreshTokens).where(
      lt(refreshTokens.expires_at, sql`NOW()`)
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
