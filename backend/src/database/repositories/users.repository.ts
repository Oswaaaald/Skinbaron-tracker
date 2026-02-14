import { eq, and, or, ilike, desc, count, sql, getTableColumns } from 'drizzle-orm';
import { users } from '../schema.js';
import type { AppDatabase } from '../connection.js';
import type { User } from '../schema.js';
import { encryptData, decryptData } from '../utils/encryption.js';

interface UserUpdate {
  username?: string;
  email?: string;
  password_hash?: string;
  is_admin?: boolean;
  is_super_admin?: boolean;
  is_approved?: boolean;
  totp_enabled?: boolean;
  totp_secret_encrypted?: string | null;
  recovery_codes_encrypted?: string | null;
  tos_accepted_at?: Date | null;
  // Virtual fields (encrypted before storage):
  recovery_codes?: string | null;
  totp_secret?: string | null;
}

export class UsersRepository {
  constructor(private db: AppDatabase) {}

  private withDecryptedFields(user: typeof users.$inferSelect): User {
    return {
      ...user,
      totp_secret: user.totp_secret_encrypted ? decryptData(user.totp_secret_encrypted) : null,
      recovery_codes: user.recovery_codes_encrypted ? decryptData(user.recovery_codes_encrypted) : null,
    };
  }

  async findById(id: number, decrypt2FA = false): Promise<User | null> {
    const [user] = await this.db.select().from(users).where(eq(users.id, id)).limit(1);
    if (!user) return null;
    return decrypt2FA ? this.withDecryptedFields(user) : user;
  }

  async findByEmail(email: string, decrypt2FA = false): Promise<User | null> {
    const [user] = await this.db.select().from(users).where(eq(users.email, email)).limit(1);
    if (!user) return null;
    return decrypt2FA ? this.withDecryptedFields(user) : user;
  }

  async findByUsername(username: string): Promise<User | null> {
    const [user] = await this.db.select().from(users).where(eq(users.username, username)).limit(1);
    return user ?? null;
  }

  async findAllWithStats(): Promise<Array<typeof users.$inferSelect & { stats: { rules_count: number; alerts_count: number; webhooks_count: number } }>> {
    const result = await this.db.select({
      ...getTableColumns(users),
      rules_count: sql<number>`(SELECT COUNT(*)::int FROM rules WHERE rules.user_id = "users"."id")`,
      alerts_count: sql<number>`(SELECT COUNT(*)::int FROM alerts a JOIN rules r ON a.rule_id = r.id WHERE r.user_id = "users"."id")`,
      webhooks_count: sql<number>`(SELECT COUNT(*)::int FROM user_webhooks WHERE user_webhooks.user_id = "users"."id")`,
    }).from(users)
      .where(eq(users.is_approved, true))
      .orderBy(desc(users.created_at));

    return result.map(row => ({
      id: row.id,
      username: row.username,
      email: row.email,
      password_hash: row.password_hash,
      is_admin: row.is_admin,
      is_super_admin: row.is_super_admin,
      is_approved: row.is_approved,
      totp_enabled: row.totp_enabled,
      totp_secret_encrypted: row.totp_secret_encrypted,
      recovery_codes_encrypted: row.recovery_codes_encrypted,
      tos_accepted_at: row.tos_accepted_at,
      created_at: row.created_at,
      updated_at: row.updated_at,
      stats: {
        rules_count: row.rules_count,
        alerts_count: row.alerts_count,
        webhooks_count: row.webhooks_count,
      },
    }));
  }

  async findPendingUsers(): Promise<Array<typeof users.$inferSelect>> {
    return this.db.select().from(users)
      .where(eq(users.is_approved, false))
      .orderBy(desc(users.created_at));
  }

  async searchUsers(query: string): Promise<Array<{ id: number; username: string; email: string }>> {
    const escaped = query.replace(/[%_\\]/g, '\\$&');
    const pattern = `%${escaped}%`;
    return this.db.select({
      id: users.id,
      username: users.username,
      email: users.email,
    }).from(users)
      .where(or(ilike(users.username, pattern), ilike(users.email, pattern)))
      .limit(20);
  }

  async create(userData: { username: string; email: string; password_hash: string }): Promise<typeof users.$inferSelect> {
    const [user] = await this.db.insert(users).values({
      username: userData.username,
      email: userData.email,
      password_hash: userData.password_hash,
    }).returning();
    return user as typeof users.$inferSelect;
  }

  async update(id: number, input: UserUpdate): Promise<typeof users.$inferSelect | null> {
    const { totp_secret, recovery_codes, ...rest } = input;

    const setValues: Record<string, unknown> = {
      ...rest,
      updated_at: new Date(),
    };

    if (totp_secret !== undefined) {
      setValues['totp_secret_encrypted'] = totp_secret ? encryptData(totp_secret) : null;
    }
    if (recovery_codes !== undefined) {
      setValues['recovery_codes_encrypted'] = recovery_codes ? encryptData(recovery_codes) : null;
    }

    const [user] = await this.db.update(users)
      .set(setValues)
      .where(eq(users.id, id))
      .returning();

    return user ?? null;
  }

  async delete(id: number): Promise<boolean> {
    const result = await this.db.delete(users).where(eq(users.id, id)).returning({ id: users.id });
    return result.length > 0;
  }

  async approveUser(id: number): Promise<boolean> {
    const result = await this.db.update(users)
      .set({ is_approved: true, updated_at: new Date() })
      .where(and(eq(users.id, id), eq(users.is_approved, false)))
      .returning({ id: users.id });
    return result.length > 0;
  }

  async rejectUser(id: number): Promise<boolean> {
    const result = await this.db.delete(users)
      .where(and(eq(users.id, id), eq(users.is_approved, false)))
      .returning({ id: users.id });
    return result.length > 0;
  }

  async toggleAdmin(id: number, isAdmin: boolean): Promise<boolean> {
    const result = await this.db.update(users)
      .set({ is_admin: isAdmin, updated_at: new Date() })
      .where(eq(users.id, id))
      .returning({ id: users.id });
    return result.length > 0;
  }

  async countAdmins(): Promise<number> {
    const [result] = await this.db.select({ value: count() })
      .from(users)
      .where(and(eq(users.is_admin, true), eq(users.is_approved, true)));
    return result?.value ?? 0;
  }

  async acceptTos(userId: number): Promise<void> {
    await this.db.update(users)
      .set({ tos_accepted_at: new Date(), updated_at: new Date() })
      .where(eq(users.id, userId));
  }
}
