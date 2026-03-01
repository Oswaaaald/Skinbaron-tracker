import { eq, and, or, ilike, desc, asc, count, sql, getTableColumns } from 'drizzle-orm';
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
  is_restricted?: boolean;
  restriction_type?: string | null;
  restriction_reason?: string | null;
  restriction_expires_at?: Date | null;
  restricted_at?: Date | null;
  restricted_by_admin_id?: number | null;
  totp_enabled?: boolean;
  totp_secret_encrypted?: string | null;
  recovery_codes_encrypted?: string | null;
  avatar_filename?: string | null;
  use_gravatar?: boolean;
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
    const normalizedEmail = email.toLowerCase().trim();
    const [user] = await this.db.select().from(users).where(sql`lower(${users.email}) = ${normalizedEmail}`).limit(1);
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
      is_restricted: row.is_restricted,
      restriction_type: row.restriction_type,
      restriction_reason: row.restriction_reason,
      restriction_expires_at: row.restriction_expires_at,
      restricted_at: row.restricted_at,
      restricted_by_admin_id: row.restricted_by_admin_id,
      totp_enabled: row.totp_enabled,
      totp_secret_encrypted: row.totp_secret_encrypted,
      recovery_codes_encrypted: row.recovery_codes_encrypted,
      tos_accepted_at: row.tos_accepted_at,
      avatar_filename: row.avatar_filename,
      use_gravatar: row.use_gravatar,
      created_at: row.created_at,
      updated_at: row.updated_at,
      stats: {
        rules_count: row.rules_count,
        alerts_count: row.alerts_count,
        webhooks_count: row.webhooks_count,
      },
    }));
  }

  async findAllWithStatsPaginated(options: {
    limit: number;
    offset: number;
    sortBy?: 'username' | 'email' | 'role' | 'created_at' | 'rules' | 'alerts' | 'webhooks';
    sortDir?: 'asc' | 'desc';
    search?: string;
    role?: 'admin' | 'user' | 'all';
    status?: 'all' | 'sanctioned' | 'active';
  }): Promise<{ data: Array<typeof users.$inferSelect & { stats: { rules_count: number; alerts_count: number; webhooks_count: number } }>; total: number }> {
    const { limit, offset, sortBy = 'created_at', sortDir = 'desc', search, role = 'all', status = 'all' } = options;

    // Build conditions
    const conditions = [eq(users.is_approved, true)];
    if (role === 'admin') conditions.push(eq(users.is_admin, true));
    else if (role === 'user') conditions.push(eq(users.is_admin, false));

    if (status === 'sanctioned') conditions.push(eq(users.is_restricted, true));
    else if (status === 'active') conditions.push(eq(users.is_restricted, false));

    if (search) {
      const escaped = search.replace(/[%_\\]/g, '\\$&');
      const pattern = `%${escaped}%`;
      const orCondition = or(ilike(users.username, pattern), ilike(users.email, pattern));
      if (orCondition) conditions.push(orCondition);
    }

    const whereClause = conditions.length === 1 ? conditions[0] : and(...conditions);

    // Count total
    const [countResult] = await this.db.select({ value: count() })
      .from(users)
      .where(whereClause);
    const total = countResult?.value ?? 0;

    // Build sort
    const rulesCountSql = sql<number>`(SELECT COUNT(*)::int FROM rules WHERE rules.user_id = "users"."id")`;
    const alertsCountSql = sql<number>`(SELECT COUNT(*)::int FROM alerts a JOIN rules r ON a.rule_id = r.id WHERE r.user_id = "users"."id")`;
    const webhooksCountSql = sql<number>`(SELECT COUNT(*)::int FROM user_webhooks WHERE user_webhooks.user_id = "users"."id")`;

    const orderFn = sortDir === 'asc' ? asc : desc;
    let orderBy;
    switch (sortBy) {
      case 'username': orderBy = orderFn(users.username); break;
      case 'email': orderBy = orderFn(users.email); break;
      case 'role': orderBy = orderFn(users.is_admin); break;
      case 'rules': orderBy = orderFn(rulesCountSql); break;
      case 'alerts': orderBy = orderFn(alertsCountSql); break;
      case 'webhooks': orderBy = orderFn(webhooksCountSql); break;
      default: orderBy = orderFn(users.created_at); break;
    }

    const result = await this.db.select({
      ...getTableColumns(users),
      rules_count: rulesCountSql,
      alerts_count: alertsCountSql,
      webhooks_count: webhooksCountSql,
    }).from(users)
      .where(whereClause)
      .orderBy(orderBy)
      .limit(limit)
      .offset(offset);

    return {
      data: result.map(row => ({
        id: row.id,
        username: row.username,
        email: row.email,
        password_hash: row.password_hash,
        is_admin: row.is_admin,
        is_super_admin: row.is_super_admin,
        is_approved: row.is_approved,
        is_restricted: row.is_restricted,
        restriction_type: row.restriction_type,
        restriction_reason: row.restriction_reason,
        restriction_expires_at: row.restriction_expires_at,
        restricted_at: row.restricted_at,
        restricted_by_admin_id: row.restricted_by_admin_id,
        totp_enabled: row.totp_enabled,
        totp_secret_encrypted: row.totp_secret_encrypted,
        recovery_codes_encrypted: row.recovery_codes_encrypted,
        tos_accepted_at: row.tos_accepted_at,
        avatar_filename: row.avatar_filename,
        use_gravatar: row.use_gravatar,
        created_at: row.created_at,
        updated_at: row.updated_at,
        stats: {
          rules_count: row.rules_count,
          alerts_count: row.alerts_count,
          webhooks_count: row.webhooks_count,
        },
      })),
      total,
    };
  }

  async findPendingUsers(): Promise<Array<typeof users.$inferSelect>> {
    return this.db.select().from(users)
      .where(eq(users.is_approved, false))
      .orderBy(desc(users.created_at));
  }

  async searchUsers(query: string, adminsOnly: boolean = false): Promise<Array<{ id: number; username: string; email: string }>> {
    const escaped = query.replace(/[%_\\]/g, '\\$&');
    const pattern = `%${escaped}%`;
    const conditions = [or(ilike(users.username, pattern), ilike(users.email, pattern))];
    if (adminsOnly) conditions.push(eq(users.is_admin, true));
    return this.db.select({
      id: users.id,
      username: users.username,
      email: users.email,
    }).from(users)
      .where(and(...conditions))
      .limit(20);
  }

  async create(userData: { username: string; email: string; password_hash?: string }): Promise<typeof users.$inferSelect> {
    const [user] = await this.db.insert(users).values({
      username: userData.username,
      email: userData.email.toLowerCase().trim(),
      password_hash: userData.password_hash ?? null,
    }).returning();
    return user as typeof users.$inferSelect;
  }

  async update(id: number, input: UserUpdate): Promise<typeof users.$inferSelect | null> {
    const { totp_secret, recovery_codes, ...rest } = input;

    // Normalize email to lowercase
    if (rest.email) rest.email = rest.email.toLowerCase().trim();

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
