import type Database from 'better-sqlite3';
import type { User, CreateUser, UserRow } from '../schemas.js';
import { CreateUserSchema } from '../schemas.js';
import { rowToUser } from '../utils/converters.js';
import { encryptData, decryptData } from '../utils/encryption.js';

export class UsersRepository {
  constructor(private db: Database.Database) {}

  create(user: CreateUser): User {
    const validated = CreateUserSchema.parse(user);
    
    const stmt = this.db.prepare(`
      INSERT INTO users (username, email, password_hash, is_approved)
      VALUES (?, ?, ?, 0)
    `);

    try {
      const result = stmt.run(validated.username, validated.email, validated.password_hash);
      return this.findById(result.lastInsertRowid as number)!;
    } catch (error) {
      if (error && typeof error === 'object' && 'code' in error && error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
        const errorMessage = error && typeof error === 'object' && 'message' in error ? String(error.message) : '';
        if (errorMessage.includes('users.email')) {
          throw new Error('Email already exists');
        }
        if (errorMessage.includes('users.username')) {
          throw new Error('Username already taken');
        }
      }
      throw error;
    }
  }

  private decrypt2FASecrets(user: User): User {
    if (user.totp_secret_encrypted) {
      try {
        user.totp_secret = decryptData(user.totp_secret_encrypted);
      } catch (error) {
        // If decryption fails (wrong key or corrupted data), leave encrypted
        console.warn(`Failed to decrypt 2FA secret for user ${user.id}:`, error instanceof Error ? error.message : 'Unknown error');
      }
    }
    if (user.recovery_codes_encrypted) {
      try {
        user.recovery_codes = decryptData(user.recovery_codes_encrypted);
      } catch (error) {
        // If decryption fails (wrong key or corrupted data), leave encrypted
        console.warn(`Failed to decrypt recovery codes for user ${user.id}:`, error instanceof Error ? error.message : 'Unknown error');
      }
    }
    return user;
  }

  findById(id: number): User | null {
    const stmt = this.db.prepare('SELECT * FROM users WHERE id = ?');
    const row = stmt.get(id) as UserRow | undefined;
    if (!row) return null;
    const user = rowToUser(row);
    return this.decrypt2FASecrets(user);
  }

  findByEmail(email: string): User | null {
    const stmt = this.db.prepare('SELECT * FROM users WHERE email = ?');
    const row = stmt.get(email) as UserRow | undefined;
    if (!row) return null;
    const user = rowToUser(row);
    return this.decrypt2FASecrets(user);
  }

  findByUsername(username: string): User | null {
    const stmt = this.db.prepare('SELECT * FROM users WHERE username = ?');
    const row = stmt.get(username) as UserRow | undefined;
    if (!row) return null;
    const user = rowToUser(row);
    return this.decrypt2FASecrets(user);
  }

  update(id: number, updates: Partial<CreateUser> & { totp_secret?: string | null; recovery_codes?: string | null }): User {
    const currentUser = this.findById(id);
    if (!currentUser) {
      throw new Error('User not found');
    }

    const processedUpdates: Record<string, string | number | null> = { ...updates } as Record<string, string | number | null>;
    
    if ('totp_secret' in updates) {
      if (updates.totp_secret) {
        processedUpdates['totp_secret_encrypted'] = encryptData(updates.totp_secret);
      } else {
        processedUpdates['totp_secret_encrypted'] = null;
      }
      delete processedUpdates['totp_secret'];
    }
    
    if ('recovery_codes' in updates) {
      if (updates.recovery_codes) {
        processedUpdates['recovery_codes_encrypted'] = encryptData(updates.recovery_codes);
      } else {
        processedUpdates['recovery_codes_encrypted'] = null;
      }
      delete processedUpdates['recovery_codes'];
    }

    const validatedUpdates = CreateUserSchema.partial().parse(processedUpdates);
    
    const fields = Object.keys(validatedUpdates).filter(key => key !== 'updated_at');
    if (fields.length === 0) {
      return currentUser;
    }

    const setClause = fields.map(field => `${field} = ?`).join(', ');
    const values = fields.map(field => (validatedUpdates as Record<string, unknown>)[field]);
    
    const stmt = this.db.prepare(`
      UPDATE users 
      SET ${setClause}, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `);

    stmt.run(...values, id);
    
    // Invalidate cache
    import('../../lib/middleware.js')
      .then(({ invalidateUserCache }) => invalidateUserCache(id))
      .catch(() => {});
    
    return this.findById(id)!;
  }

  delete(id: number): boolean {
    const user = this.findById(id);
    if (user?.is_super_admin) {
      throw new Error('Cannot delete super admin');
    }
    
    const stmt = this.db.prepare('DELETE FROM users WHERE id = ?');
    const result = stmt.run(id);
    
    if (result.changes > 0) {
      import('../../lib/middleware.js')
        .then(({ invalidateUserCache }) => invalidateUserCache(id))
        .catch(() => {});
    }
    
    return result.changes > 0;
  }

  findAll(): User[] {
    const stmt = this.db.prepare('SELECT * FROM users WHERE is_approved = 1 ORDER BY created_at DESC');
    const rows = stmt.all() as UserRow[];
    return rows.map(row => this.decrypt2FASecrets(rowToUser(row)));
  }

  countAll(): number {
    const stmt = this.db.prepare('SELECT COUNT(*) as count FROM users');
    const result = stmt.get() as { count: number };
    return result.count;
  }

  findPendingApproval(limit: number = 50, offset: number = 0): User[] {
    const stmt = this.db.prepare(`
      SELECT * FROM users 
      WHERE is_approved = 0 
      ORDER BY created_at ASC 
      LIMIT ? OFFSET ?
    `);
    const rows = stmt.all(limit, offset) as UserRow[];
    return rows.map(row => this.decrypt2FASecrets(rowToUser(row)));
  }

  approve(id: number): boolean {
    const stmt = this.db.prepare('UPDATE users SET is_approved = 1 WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }

  setAdmin(id: number, isAdmin: boolean): boolean {
    const stmt = this.db.prepare('UPDATE users SET is_admin = ? WHERE id = ?');
    const result = stmt.run(isAdmin ? 1 : 0, id);
    
    if (result.changes > 0) {
      import('../../lib/middleware.js')
        .then(({ invalidateUserCache }) => invalidateUserCache(id))
        .catch(() => {});
    }
    
    return result.changes > 0;
  }

  searchUsers(searchTerm: string, limit: number = 20): User[] {
    const stmt = this.db.prepare(`
      SELECT * FROM users 
      WHERE is_approved = 1 AND (username LIKE ? OR email LIKE ?) 
      ORDER BY username ASC 
      LIMIT ?
    `);
    const term = `%${searchTerm}%`;
    const rows = stmt.all(term, term, limit) as UserRow[];
    return rows.map(row => this.decrypt2FASecrets(rowToUser(row)));
  }
}
