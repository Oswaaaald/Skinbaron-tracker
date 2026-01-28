import type Database from 'better-sqlite3';
import { hashToken } from '../utils/encryption.js';

export interface RefreshTokenRecord {
  id: number;
  user_id: number;
  token_hash: string;
  token_jti: string;
  expires_at: string;
  revoked_at: string | null;
  replaced_by_jti: string | null;
  created_at: string;
}

export class AuthRepository {
  constructor(private db: Database.Database) {}

  // Refresh tokens
  saveRefreshToken(userId: number, token: string, jti: string, expiresAt: number): void {
    const tokenHash = hashToken(token);
    const stmt = this.db.prepare(`
      INSERT INTO refresh_tokens (user_id, token_hash, token_jti, expires_at)
      VALUES (?, ?, ?, ?)
    `);
    stmt.run(userId, tokenHash, jti, new Date(expiresAt).toISOString());
  }

  getRefreshTokenByHash(tokenHash: string): RefreshTokenRecord | null {
    const stmt = this.db.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?');
    const row = stmt.get(tokenHash) as RefreshTokenRecord | undefined;
    return row ?? null;
  }

  getRefreshToken(token: string): RefreshTokenRecord | null {
    const tokenHash = hashToken(token);
    return this.getRefreshTokenByHash(tokenHash);
  }

  revokeRefreshToken(token: string, replacedByJti?: string): void {
    const tokenHash = hashToken(token);
    const stmt = this.db.prepare(`
      UPDATE refresh_tokens
      SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP), 
          replaced_by_jti = COALESCE(?, replaced_by_jti)
      WHERE token_hash = ?
    `);
    stmt.run(replacedByJti ?? null, tokenHash);
  }

  revokeAllRefreshTokensForUser(userId: number): void {
    const stmt = this.db.prepare(`
      UPDATE refresh_tokens
      SET revoked_at = CURRENT_TIMESTAMP, 
          replaced_by_jti = COALESCE(replaced_by_jti, 'logout_all')
      WHERE user_id = ? AND revoked_at IS NULL
    `);
    stmt.run(userId);
  }

  cleanupRefreshTokens(): void {
    const stmt = this.db.prepare(`
      DELETE FROM refresh_tokens
      WHERE (revoked_at IS NOT NULL) OR (expires_at < CURRENT_TIMESTAMP)
    `);
    stmt.run();
  }

  // Access token blacklist
  blacklistAccessToken(jti: string, userId: number, expiresAt: number, reason?: string): void {
    const stmt = this.db.prepare(`
      INSERT INTO access_token_blacklist (jti, user_id, expires_at, reason)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(jti) DO UPDATE SET 
        expires_at = excluded.expires_at, 
        reason = COALESCE(excluded.reason, access_token_blacklist.reason)
    `);
    stmt.run(jti, userId, new Date(expiresAt).toISOString(), reason ?? null);
  }

  isAccessTokenBlacklisted(jti: string): boolean {
    // Cleanup expired tokens first
    const cleanupStmt = this.db.prepare(`
      DELETE FROM access_token_blacklist WHERE expires_at < CURRENT_TIMESTAMP
    `);
    cleanupStmt.run();

    const stmt = this.db.prepare('SELECT 1 FROM access_token_blacklist WHERE jti = ?');
    const row = stmt.get(jti) as { 1: number } | undefined;
    return Boolean(row);
  }
}
