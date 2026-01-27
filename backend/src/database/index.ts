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

  // Legacy compatibility methods - delegate to repositories

  // Rules
  createRule = this.rules.create.bind(this.rules);
  getRuleById = this.rules.findById.bind(this.rules);
  getAllRules = this.rules.findAll.bind(this.rules);
  getRulesByUserId = this.rules.findByUserId.bind(this.rules);
  getEnabledRules = this.rules.findEnabled.bind(this.rules);
  updateRule = this.rules.update.bind(this.rules);
  deleteRule = this.rules.delete.bind(this.rules);
  enableRulesBatch = this.rules.enableBatch.bind(this.rules);
  disableRulesBatch = this.rules.disableBatch.bind(this.rules);
  deleteRulesBatch = this.rules.deleteBatch.bind(this.rules);

  // Alerts
  createAlert = this.alerts.create.bind(this.alerts);
  createAlertsBatch = this.alerts.createBatch.bind(this.alerts);
  getAlertById = this.alerts.findById.bind(this.alerts);
  getAlerts = this.alerts.findAll.bind(this.alerts);
  getAlertsBySaleId = this.alerts.findBySaleId.bind(this.alerts);
  getAlertsByUserId = this.alerts.findByUserId.bind(this.alerts);
  getAlertByIdForUser = this.alerts.findByIdForUser.bind(this.alerts);
  getAlertsByRuleIdForUser = this.alerts.findByRuleIdForUser.bind(this.alerts);
  deleteAlertsByRuleId = this.alerts.deleteByRuleId.bind(this.alerts);
  
  cleanupUserOldAlerts(userId: number): number {
    const stmt = this.db.prepare(`
      DELETE FROM alerts 
      WHERE sent_at < DATE('now', '-7 days')
        AND rule_id IN (SELECT id FROM rules WHERE user_id = ?)
    `);
    return stmt.run(userId).changes;
  }

  deleteAllUserAlerts = this.alerts.deleteByUserId.bind(this.alerts);
  
  cleanupOldAlerts(): number {
    const stmt = this.db.prepare(`
      DELETE FROM alerts 
      WHERE sent_at < DATE('now', '-30 days')
    `);
    return stmt.run().changes;
  }

  // Users
  createUser = this.users.create.bind(this.users);
  getUserById = this.users.findById.bind(this.users);
  getUserByEmail = this.users.findByEmail.bind(this.users);
  getUserByUsername = this.users.findByUsername.bind(this.users);
  updateUser = this.users.update.bind(this.users);
  deleteUser = this.users.delete.bind(this.users);
  getAllUsers = this.users.findAll.bind(this.users);
  searchUsers = this.users.searchUsers.bind(this.users);
  getPendingUsers = this.users.findPendingApproval.bind(this.users);
  approveUser = this.users.approve.bind(this.users);
  
  rejectUser(userId: number): boolean {
    return this.users.delete(userId);
  }

  setUserAdmin(userId: number, isAdmin: boolean): boolean {
    return this.users.setAdmin(userId, isAdmin);
  }

  // Webhooks
  createUserWebhook = this.webhooks.create.bind(this.webhooks);
  getUserWebhookById = this.webhooks.findById.bind(this.webhooks);
  getUserWebhooksByUserId = this.webhooks.findByUserId.bind(this.webhooks);
  updateUserWebhook = this.webhooks.update.bind(this.webhooks);
  deleteUserWebhook(id: number, userId: number): boolean {
    const result = this.webhooks.delete(id, userId);
    
    if (result) {
      // Clean up rules that reference this webhook
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
          // Disable rule if no webhooks remain
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
  
  getUserActiveWebhooks(userId: number) {
    return this.webhooks.findByUserId(userId, true).filter(w => w.is_active);
  }

  getRuleWebhooksForNotification(ruleId: number) {
    const rule = this.rules.findById(ruleId);
    if (!rule || !rule.webhook_ids?.length) return [];
    
    return this.webhooks.findByIds(rule.webhook_ids, true).filter(w => w.is_active && w.webhook_url);
  }

  // Legacy method aliases
  getUserWebhooks = this.webhooks.findByUserId.bind(this.webhooks);
  getUserRules(userId: number) {
    return this.rules.findByUserId(userId);
  }
  getUserAlerts(userId: number) {
    return this.alerts.findByUserId(userId);
  }
  getUserStats(userId: number) {
    return {
      total_rules: this.rules.countByUserId(userId),
      total_alerts: this.alerts.countByUserId(userId),
      total_webhooks: this.webhooks.countByUserId(userId)
    };
  }
  toggleUserAdmin(userId: number, isAdmin: boolean): boolean {
    return this.users.setAdmin(userId, isAdmin);
  }
  getGlobalStats() {
    return this.audit.getSystemStats();
  }
  getAllAuditLogs(limit: number = 100, _eventType?: string, userId?: number) {
    if (userId) {
      return this.audit.getAuditLogsByUserId(userId, limit);
    }
    return this.audit.getAuditLogsByUserId(0, limit); // Fallback
  }
  isProcessed(saleId: string, ruleId: number): boolean {
    const alert = this.alerts.findBySaleId(saleId);
    return alert !== null && alert.rule_id === ruleId;
  }
  addRefreshToken = this.auth.saveRefreshToken.bind(this.auth);

  // Auth
  saveRefreshToken = this.auth.saveRefreshToken.bind(this.auth);
  getRefreshToken = this.auth.getRefreshToken.bind(this.auth);
  getRefreshTokenByHash = this.auth.getRefreshTokenByHash.bind(this.auth);
  revokeRefreshToken = this.auth.revokeRefreshToken.bind(this.auth);
  revokeAllRefreshTokensForUser = this.auth.revokeAllRefreshTokensForUser.bind(this.auth);
  cleanupRefreshTokens = this.auth.cleanupRefreshTokens.bind(this.auth);
  blacklistAccessToken = this.auth.blacklistAccessToken.bind(this.auth);
  isAccessTokenBlacklisted = this.auth.isAccessTokenBlacklisted.bind(this.auth);

  // Audit
  createAuditLog = this.audit.createAuditLog.bind(this.audit);
  getAuditLogsByUserId = this.audit.getAuditLogsByUserId.bind(this.audit);
  cleanOldAuditLogs(daysToKeep: number = 90): number {
    return this.audit.cleanupOldAuditLogs(daysToKeep);
  }
  logAdminAction = this.audit.logAdminAction.bind(this.audit);
  getAdminLogs = this.audit.getAdminLogs.bind(this.audit);
  getSystemStats = this.audit.getSystemStats.bind(this.audit);
  getStats = this.audit.getSystemStats.bind(this.audit);

  close() {
    this.db.close();
  }
}

// Singleton instance
export const store = new Store();
