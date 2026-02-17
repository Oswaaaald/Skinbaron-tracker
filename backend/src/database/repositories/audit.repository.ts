import { eq, and, desc, lt, count, sql, inArray, getTableColumns } from 'drizzle-orm';
import { alias } from 'drizzle-orm/pg-core';
import { auditLog, adminActions, users, rules, alerts, userWebhooks } from '../schema.js';
import type { AppDatabase } from '../connection.js';
import type { AuditLog, AdminAction } from '../schema.js';

export class AuditRepository {
  constructor(private db: AppDatabase) {}

  async createLog(
    userId: number,
    eventType: string,
    eventData?: string,
    ipAddress?: string,
    userAgent?: string,
  ): Promise<void> {
    await this.db.insert(auditLog).values({
      user_id: userId,
      event_type: eventType,
      event_data: eventData ?? null,
      ip_address: ipAddress ?? null,
      user_agent: userAgent ?? null,
    });
  }

  async getLogsByUserId(userId: number, limit: number = 100): Promise<AuditLog[]> {
    const logs = await this.db.select()
      .from(auditLog)
      .where(eq(auditLog.user_id, userId))
      .orderBy(desc(auditLog.created_at))
      .limit(limit > 0 ? limit : 10000);

    return this.enrichLogsWithAdminUsernames(logs);
  }

  async getAllLogs(limit: number = 100, eventType?: string, userId?: number): Promise<AuditLog[]> {
    const conditions = [];
    if (eventType) conditions.push(eq(auditLog.event_type, eventType));
    if (userId) conditions.push(eq(auditLog.user_id, userId));

    const result = await this.db.select({
      ...getTableColumns(auditLog),
      username: users.username,
      email: users.email,
    }).from(auditLog)
      .leftJoin(users, eq(auditLog.user_id, users.id))
      .where(conditions.length > 0 ? and(...conditions) : undefined)
      .orderBy(desc(auditLog.created_at))
      .limit(limit);

    return this.enrichLogsWithAdminUsernames(result);
  }

  async logAdminAction(
    adminUserId: number,
    action: string,
    targetUserId: number | null,
    details?: string,
  ): Promise<void> {
    await this.db.insert(adminActions).values({
      admin_user_id: adminUserId,
      action,
      target_user_id: targetUserId,
      details: details ?? null,
    });
  }

  async getAdminLogs(limit: number = 100, action?: string, adminId?: number): Promise<AdminAction[]> {
    const adminUser = alias(users, 'admin_user');
    const targetUser = alias(users, 'target_user');

    const conditions = [];
    if (action) conditions.push(eq(adminActions.action, action));
    if (adminId) conditions.push(eq(adminActions.admin_user_id, adminId));

    return this.db.select({
      ...getTableColumns(adminActions),
      admin_username: adminUser.username,
      target_username: targetUser.username,
    }).from(adminActions)
      .leftJoin(adminUser, eq(adminActions.admin_user_id, adminUser.id))
      .leftJoin(targetUser, eq(adminActions.target_user_id, targetUser.id))
      .where(conditions.length > 0 ? and(...conditions) : undefined)
      .orderBy(desc(adminActions.created_at))
      .limit(limit);
  }

  async cleanupOldLogs(daysToKeep: number = 90): Promise<number> {
    const result = await this.db.delete(auditLog)
      .where(lt(auditLog.created_at, sql`NOW() - ${daysToKeep} * INTERVAL '1 day'`))
      .returning({ id: auditLog.id });
    return result.length;
  }

  async cleanupOldAdminActions(daysToKeep: number = 365): Promise<number> {
    const result = await this.db.delete(adminActions)
      .where(lt(adminActions.created_at, sql`NOW() - ${daysToKeep} * INTERVAL '1 day'`))
      .returning({ id: adminActions.id });
    return result.length;
  }

  async getGlobalStats(): Promise<{
    total_users: number;
    total_admins: number;
    total_rules: number;
    enabled_rules: number;
    total_alerts: number;
    total_webhooks: number;
  }> {
    const [[usersCount], [adminsCount], [rulesCount], [enabledRulesCount], [alertsCount], [webhooksCount]] = await Promise.all([
      this.db.select({ value: count() }).from(users).where(eq(users.is_approved, true)),
      this.db.select({ value: count() }).from(users).where(and(eq(users.is_admin, true), eq(users.is_approved, true))),
      this.db.select({ value: count() }).from(rules),
      this.db.select({ value: count() }).from(rules).where(eq(rules.enabled, true)),
      this.db.select({ value: count() }).from(alerts),
      this.db.select({ value: count() }).from(userWebhooks),
    ]);

    return {
      total_users: usersCount?.value ?? 0,
      total_admins: adminsCount?.value ?? 0,
      total_rules: rulesCount?.value ?? 0,
      enabled_rules: enabledRulesCount?.value ?? 0,
      total_alerts: alertsCount?.value ?? 0,
      total_webhooks: webhooksCount?.value ?? 0,
    };
  }

  async getUserStats(userId: number): Promise<{
    totalRules: number;
    enabledRules: number;
    totalAlerts: number;
    todayAlerts: number;
  }> {
    const [[totalRules], [enabledRules], [totalAlerts], [todayAlerts]] = await Promise.all([
      this.db.select({ value: count() }).from(rules).where(eq(rules.user_id, userId)),
      this.db.select({ value: count() }).from(rules).where(and(eq(rules.user_id, userId), eq(rules.enabled, true))),
      this.db.select({ value: count() })
        .from(alerts)
        .innerJoin(rules, eq(alerts.rule_id, rules.id))
        .where(eq(rules.user_id, userId)),
      this.db.select({ value: count() })
        .from(alerts)
        .innerJoin(rules, eq(alerts.rule_id, rules.id))
        .where(and(
          eq(rules.user_id, userId),
          sql`${alerts.sent_at} >= NOW() - INTERVAL '24 hours'`
        )),
    ]);

    return {
      totalRules: totalRules?.value ?? 0,
      enabledRules: enabledRules?.value ?? 0,
      totalAlerts: totalAlerts?.value ?? 0,
      todayAlerts: todayAlerts?.value ?? 0,
    };
  }

  private async enrichLogsWithAdminUsernames<T extends { event_data: string | null }>(logs: T[]): Promise<T[]> {
    const adminIds = new Set<number>();
    for (const log of logs) {
      if (log.event_data) {
        try {
          const data = JSON.parse(log.event_data) as Record<string, unknown>;
          if (typeof data['admin_id'] === 'number') adminIds.add(data['admin_id']);
          if (typeof data['approved_by_admin_id'] === 'number') adminIds.add(data['approved_by_admin_id']);
          if (typeof data['deleted_by_admin_id'] === 'number') adminIds.add(data['deleted_by_admin_id']);
        } catch { /* ignore parse errors */ }
      }
    }

    if (adminIds.size === 0) return logs;

    const admins = await this.db.select({ id: users.id, username: users.username })
      .from(users)
      .where(inArray(users.id, Array.from(adminIds)));

    const adminMap = new Map(admins.map(a => [a.id, a.username]));

    const usernameKeyMap: Record<string, string> = {
      admin_id: 'admin_username',
      approved_by_admin_id: 'approved_by_admin_username',
      deleted_by_admin_id: 'deleted_by_admin_username',
    };

    return logs.map(log => {
      if (!log.event_data) return log;
      try {
        const data = JSON.parse(log.event_data) as Record<string, unknown>;
        let modified = false;
        for (const [idKey, usernameKey] of Object.entries(usernameKeyMap)) {
          const id = data[idKey];
          if (typeof id === 'number' && adminMap.has(id)) {
            data[usernameKey] = adminMap.get(id);
            modified = true;
          }
        }
        if (modified) return { ...log, event_data: JSON.stringify(data) };
      } catch { /* ignore parse errors */ }
      return log;
    });
  }
}
