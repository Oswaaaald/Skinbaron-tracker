import { db } from './connection.js';
import type { AppDatabase } from './connection.js';
import { UsersRepository } from './repositories/users.repository.js';
import { RulesRepository } from './repositories/rules.repository.js';
import { AlertsRepository } from './repositories/alerts.repository.js';
import { WebhooksRepository } from './repositories/webhooks.repository.js';
import { AuthRepository } from './repositories/auth.repository.js';
import { AuditRepository } from './repositories/audit.repository.js';
import { OAuthRepository } from './repositories/oauth.repository.js';
import { PasskeysRepository } from './repositories/passkeys.repository.js';
import { ChallengesRepository } from './repositories/challenges.repository.js';
import { bannedEmails, sanctions } from './schema.js';
import { eq, desc } from 'drizzle-orm';

class Store {
  public users: UsersRepository;
  public rules: RulesRepository;
  public alerts: AlertsRepository;
  public webhooks: WebhooksRepository;
  public auth: AuthRepository;
  public audit: AuditRepository;
  public oauth: OAuthRepository;
  public passkeys: PasskeysRepository;
  public challenges: ChallengesRepository;

  constructor(database: AppDatabase) {
    this.users = new UsersRepository(database);
    this.rules = new RulesRepository(database);
    this.alerts = new AlertsRepository(database);
    this.webhooks = new WebhooksRepository(database);
    this.auth = new AuthRepository(database);
    this.audit = new AuditRepository(database);
    this.oauth = new OAuthRepository(database);
    this.passkeys = new PasskeysRepository(database);
    this.challenges = new ChallengesRepository(database);
  }

  // ==================== Banned emails ====================

  async isEmailBanned(email: string): Promise<boolean> {
    const [result] = await db.select({ id: bannedEmails.id })
      .from(bannedEmails)
      .where(eq(bannedEmails.email, email.toLowerCase().trim()))
      .limit(1);
    return !!result;
  }

  async banEmail(email: string, reason: string | null, adminId: number): Promise<void> {
    await db.insert(bannedEmails).values({
      email: email.toLowerCase().trim(),
      reason,
      banned_by_admin_id: adminId,
    }).onConflictDoNothing();
  }

  async unbanEmail(email: string): Promise<boolean> {
    const result = await db.delete(bannedEmails)
      .where(eq(bannedEmails.email, email.toLowerCase().trim()))
      .returning({ id: bannedEmails.id });
    return result.length > 0;
  }

  // ==================== Sanctions (casier) ====================

  async createSanction(data: {
    user_id: number;
    admin_id: number;
    admin_username: string;
    action: string;
    restriction_type?: string | null;
    reason?: string | null;
    duration_hours?: number | null;
    expires_at?: Date | null;
  }): Promise<void> {
    await db.insert(sanctions).values({
      user_id: data.user_id,
      admin_id: data.admin_id,
      admin_username: data.admin_username,
      action: data.action,
      restriction_type: data.restriction_type || null,
      reason: data.reason || null,
      duration_hours: data.duration_hours || null,
      expires_at: data.expires_at || null,
    });
  }

  async getSanctionsByUserId(userId: number, limit = 50): Promise<Array<typeof sanctions.$inferSelect>> {
    return db.select().from(sanctions)
      .where(eq(sanctions.user_id, userId))
      .orderBy(desc(sanctions.created_at))
      .limit(limit > 0 ? limit : 10000);
  }

  async getSanctionById(sanctionId: number): Promise<typeof sanctions.$inferSelect | null> {
    const rows = await db.select().from(sanctions).where(eq(sanctions.id, sanctionId)).limit(1);
    return rows[0] ?? null;
  }

  async deleteSanction(sanctionId: number): Promise<void> {
    await db.delete(sanctions).where(eq(sanctions.id, sanctionId));
  }
}

export const store = new Store(db);
