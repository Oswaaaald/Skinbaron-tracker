import { getDatabase } from './connection.js';
import { RulesRepository } from './repositories/rules.repository.js';
import { AlertsRepository } from './repositories/alerts.repository.js';
import { UsersRepository } from './repositories/users.repository.js';
import { WebhooksRepository } from './repositories/webhooks.repository.js';
import { AuthRepository } from './repositories/auth.repository.js';
import { AuditRepository } from './repositories/audit.repository.js';

export class Store {
  private db = getDatabase();

  // Repositories
  public rules = new RulesRepository(this.db);
  public alerts = new AlertsRepository(this.db);
  public users = new UsersRepository(this.db);
  public webhooks = new WebhooksRepository(this.db);
  public auth = new AuthRepository(this.db);
  public audit = new AuditRepository(this.db);

  // Rules
  createRule = this.rules.create.bind(this.rules);
  getRuleById = this.rules.findById.bind(this.rules);
  getRulesByUserId = this.rules.findByUserId.bind(this.rules);
  getEnabledRules = this.rules.findEnabled.bind(this.rules);
  updateRule = this.rules.update.bind(this.rules);
  deleteRule = this.rules.delete.bind(this.rules);
  enableRulesBatch = this.rules.enableBatch.bind(this.rules);
  disableRulesBatch = this.rules.disableBatch.bind(this.rules);
  deleteRulesBatch = this.rules.deleteBatch.bind(this.rules);

  // Alerts
  createAlertsBatch = this.alerts.createBatch.bind(this.alerts);
  getAlertsByUserId = this.alerts.findByUserId.bind(this.alerts);
  deleteAllUserAlerts = this.alerts.deleteByUserId.bind(this.alerts);
  findAlertsByRuleId = this.alerts.findByRuleId.bind(this.alerts);
  deleteBySaleIds = this.alerts.deleteBySaleIds.bind(this.alerts);
  deleteBySaleIdAndRuleId = this.alerts.deleteBySaleIdAndRuleId.bind(this.alerts);
  getUniqueAlertItemNames = this.alerts.getUniqueItemNames.bind(this.alerts);

  // Users
  createUser = this.users.create.bind(this.users);
  getUserById = this.users.findById.bind(this.users);
  getUserByEmail = this.users.findByEmail.bind(this.users);
  getUserByUsername = this.users.findByUsername.bind(this.users);
  updateUser = this.users.update.bind(this.users);
  deleteUser = this.users.delete.bind(this.users);
  getAllUsers = this.users.findAll.bind(this.users);
  getAllUsersWithStats = this.users.findAllWithStats.bind(this.users);
  searchUsers = this.users.searchUsers.bind(this.users);
  getPendingUsers = this.users.findPendingApproval.bind(this.users);
  approveUser = this.users.approve.bind(this.users);
  
  rejectUser(userId: number): boolean {
    return this.users.delete(userId);
  }

  // Webhooks
  createUserWebhook = this.webhooks.create.bind(this.webhooks);
  getUserWebhookById = this.webhooks.findById.bind(this.webhooks);
  getUserWebhooksByUserId = this.webhooks.findByUserId.bind(this.webhooks);
  updateUserWebhook = this.webhooks.update.bind(this.webhooks);
  deleteUserWebhook(id: number, userId: number): boolean {
    const result = this.webhooks.delete(id, userId);
    
    if (result) {
      this.cleanupRulesAfterWebhookDeletion(id, userId);
    }
    
    return result;
  }
  
  private cleanupRulesAfterWebhookDeletion(webhookId: number, userId: number): void {
    const rules = this.rules.findByUserId(userId);

    for (const rule of rules) {
      if (!rule.webhook_ids || rule.webhook_ids.length === 0) continue;
      
      const updatedWebhookIds = rule.webhook_ids.filter(id => id !== webhookId);
      
      if (updatedWebhookIds.length !== rule.webhook_ids.length) {
        if (updatedWebhookIds.length === 0) {
          if (rule.id !== undefined) {
            this.rules.update(rule.id, { ...rule, enabled: false, webhook_ids: [] });
          }
        } else {
          if (rule.id !== undefined) {
            this.rules.update(rule.id, { ...rule, webhook_ids: updatedWebhookIds });
          }
        }
      }
    }
  }

  enableWebhooksBatch = this.webhooks.enableBatch.bind(this.webhooks);
  disableWebhooksBatch = this.webhooks.disableBatch.bind(this.webhooks);
  deleteWebhooksBatch = this.webhooks.deleteBatch.bind(this.webhooks);

  getRuleWebhooksForNotification(ruleId: number) {
    const rule = this.rules.findById(ruleId);
    if (!rule || !rule.webhook_ids?.length) return [];
    
    return this.webhooks.findByIds(rule.webhook_ids, true).filter(w => w.is_active && w.webhook_url);
  }

  getUserWebhooks = this.webhooks.findByUserId.bind(this.webhooks);

  getUserStats(userId: number) {
    const stats = this.db.prepare(`
      SELECT 
        (SELECT COUNT(*) FROM rules WHERE user_id = ?) as totalRules,
        (SELECT COUNT(*) FROM rules WHERE user_id = ? AND enabled = 1) as enabledRules,
        (SELECT COUNT(*) FROM alerts a JOIN rules r ON a.rule_id = r.id WHERE r.user_id = ?) as totalAlerts,
        (SELECT COUNT(*) FROM alerts a JOIN rules r ON a.rule_id = r.id WHERE r.user_id = ? AND a.sent_at >= datetime('now', '-24 hours')) as todayAlerts
    `).get(userId, userId, userId, userId) as { totalRules: number; enabledRules: number; totalAlerts: number; todayAlerts: number };

    return stats;
  }

  toggleUserAdmin(userId: number, isAdmin: boolean): boolean {
    return this.users.setAdmin(userId, isAdmin);
  }
  
  getStats() {
    const stats = this.db.prepare(`
      SELECT 
        (SELECT COUNT(*) FROM rules) as totalRules,
        (SELECT COUNT(*) FROM rules WHERE enabled = 1) as enabledRules,
        (SELECT COUNT(*) FROM alerts) as totalAlerts,
        (SELECT COUNT(*) FROM alerts WHERE sent_at >= datetime('now', '-24 hours')) as todayAlerts
    `).get() as { totalRules: number; enabledRules: number; totalAlerts: number; todayAlerts: number };

    return stats;
  }
  
  getGlobalStats() {
    return this.audit.getSystemStats();
  }

  getAllAuditLogs(limit: number = 100, eventType?: string, userId?: number) {
    return this.audit.getAllAuditLogs(limit, eventType, userId);
  }

  addRefreshToken = this.auth.saveRefreshToken.bind(this.auth);

  // Auth
  getRefreshToken = this.auth.getRefreshToken.bind(this.auth);
  revokeRefreshToken = this.auth.revokeRefreshToken.bind(this.auth);
  revokeAllRefreshTokensForUser = this.auth.revokeAllRefreshTokensForUser.bind(this.auth);
  cleanupRefreshTokens = this.auth.cleanupRefreshTokens.bind(this.auth);
  blacklistAccessToken = this.auth.blacklistAccessToken.bind(this.auth);
  isAccessTokenBlacklisted = this.auth.isAccessTokenBlacklisted.bind(this.auth);
  cleanupExpiredBlacklistTokens = this.auth.cleanupExpiredBlacklistTokens.bind(this.auth);

  // Audit
  createAuditLog = this.audit.createAuditLog.bind(this.audit);
  getAuditLogsByUserId = this.audit.getAuditLogsByUserId.bind(this.audit);
  cleanOldAuditLogs(daysToKeep: number = 90): number {
    return this.audit.cleanupOldAuditLogs(daysToKeep);
  }
  logAdminAction = this.audit.logAdminAction.bind(this.audit);

  close() {
    this.db.close();
  }
}

// Singleton instance
export const store = new Store();
