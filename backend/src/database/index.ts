import { db } from './connection.js';
import type { AppDatabase } from './connection.js';
import { UsersRepository } from './repositories/users.repository.js';
import { RulesRepository } from './repositories/rules.repository.js';
import { AlertsRepository } from './repositories/alerts.repository.js';
import { WebhooksRepository } from './repositories/webhooks.repository.js';
import { AuthRepository } from './repositories/auth.repository.js';
import { AuditRepository } from './repositories/audit.repository.js';
import { OAuthRepository } from './repositories/oauth.repository.js';
import type { User, Rule, Alert, UserWebhook, CreateAlert, CreateRule, RefreshTokenRecord, AuditLog, OAuthAccount } from './schema.js';

class Store {
  public users: UsersRepository;
  public rules: RulesRepository;
  public alerts: AlertsRepository;
  public webhooks: WebhooksRepository;
  public auth: AuthRepository;
  public audit: AuditRepository;
  public oauth: OAuthRepository;

  constructor(database: AppDatabase) {
    this.users = new UsersRepository(database);
    this.rules = new RulesRepository(database);
    this.alerts = new AlertsRepository(database);
    this.webhooks = new WebhooksRepository(database);
    this.auth = new AuthRepository(database);
    this.audit = new AuditRepository(database);
    this.oauth = new OAuthRepository(database);
  }

  // ==================== User operations ====================

  async getUserById(id: number, decrypt2FA = false): Promise<User | null> {
    return this.users.findById(id, decrypt2FA);
  }

  async getUserByEmail(email: string, decrypt2FA = false): Promise<User | null> {
    return this.users.findByEmail(email, decrypt2FA);
  }

  async getUserByUsername(username: string): Promise<User | null> {
    return this.users.findByUsername(username);
  }

  async createUser(data: { username: string; email: string; password_hash?: string }): Promise<User> {
    return this.users.create(data);
  }

  async updateUser(id: number, updates: Record<string, unknown>): Promise<User | null> {
    return this.users.update(id, updates);
  }

  async deleteUser(id: number): Promise<boolean> {
    return this.users.delete(id);
  }

  async acceptTos(userId: number): Promise<void> {
    return this.users.acceptTos(userId);
  }

  async toggleUserAdmin(id: number, isAdmin: boolean): Promise<boolean> {
    return this.users.toggleAdmin(id, isAdmin);
  }

  async approveUser(id: number): Promise<boolean> {
    return this.users.approveUser(id);
  }

  async rejectUser(id: number): Promise<boolean> {
    return this.users.rejectUser(id);
  }

  async getAllUsersWithStats() {
    return this.users.findAllWithStats();
  }

  async getPendingUsers() {
    return this.users.findPendingUsers();
  }

  async searchUsers(query: string) {
    return this.users.searchUsers(query);
  }

  // ==================== Rule operations ====================

  async getRuleById(id: number): Promise<Rule | null> {
    return this.rules.findById(id);
  }

  async getRulesByUserId(userId: number): Promise<Rule[]> {
    return this.rules.findByUserId(userId);
  }

  async getEnabledRules(): Promise<Rule[]> {
    return this.rules.findAllEnabled();
  }

  async createRule(data: CreateRule): Promise<Rule> {
    return this.rules.create(data);
  }

  async updateRule(id: number, updates: Partial<CreateRule>): Promise<Rule | null> {
    return this.rules.update(id, updates);
  }

  async deleteRule(id: number): Promise<boolean> {
    return this.rules.delete(id);
  }

  async enableRulesBatch(ruleIds: number[], userId: number): Promise<number> {
    return this.rules.enableBatch(ruleIds, userId);
  }

  async disableRulesBatch(ruleIds: number[], userId: number): Promise<number> {
    return this.rules.disableBatch(ruleIds, userId);
  }

  async deleteRulesBatch(ruleIds: number[], userId: number): Promise<number> {
    return this.rules.deleteBatch(ruleIds, userId);
  }

  // ==================== Alert operations ====================

  async getAlertsByUserId(userId: number, limit: number = 0, offset: number = 0, options?: {
    ruleId?: number;
    itemName?: string;
    sortBy?: 'date' | 'price_asc' | 'price_desc' | 'wear_asc' | 'wear_desc';
  }): Promise<Alert[]> {
    return this.alerts.findByUserId(userId, limit, offset, options);
  }

  async createAlertsBatch(alertsData: CreateAlert[]): Promise<number> {
    return this.alerts.createBatch(alertsData);
  }

  async deleteBySaleIdAndRuleId(saleId: string, ruleId: number): Promise<void> {
    return this.alerts.deleteBySaleIdAndRuleId(saleId, ruleId);
  }

  async deleteAllUserAlerts(userId: number): Promise<number> {
    return this.alerts.deleteAllByUserId(userId);
  }

  async getUniqueAlertItemNames(userId: number): Promise<string[]> {
    return this.alerts.getUniqueItemNames(userId);
  }

  async findUnnotifiedAlertsByRuleId(ruleId: number): Promise<Alert[]> {
    return this.alerts.findUnnotifiedByRuleId(ruleId);
  }

  async markAlertsNotified(alertIds: number[]): Promise<void> {
    return this.alerts.markNotified(alertIds);
  }

  async getUserStats(userId: number) {
    return this.audit.getUserStats(userId);
  }

  // ==================== Webhook operations ====================

  async getUserWebhookById(id: number): Promise<UserWebhook | null> {
    return this.webhooks.findById(id);
  }

  async getUserWebhooksByUserId(userId: number, decrypt = false): Promise<UserWebhook[]> {
    return this.webhooks.findByUserId(userId, decrypt);
  }

  async getUserWebhooks(userId: number): Promise<UserWebhook[]> {
    return this.webhooks.findByUserId(userId, false);
  }

  async createUserWebhook(userId: number, data: { name: string; webhook_url: string; webhook_type?: 'discord'; notification_style?: 'compact' | 'detailed'; is_active?: boolean }): Promise<UserWebhook> {
    return this.webhooks.create(userId, data);
  }

  async updateUserWebhook(id: number, userId: number, data: Partial<{ name: string; webhook_url: string; webhook_type: 'discord'; notification_style: 'compact' | 'detailed'; is_active: boolean }>): Promise<UserWebhook | null> {
    return this.webhooks.update(id, userId, data);
  }

  async deleteUserWebhook(id: number, userId: number): Promise<boolean> {
    return this.webhooks.delete(id, userId);
  }

  async enableWebhooksBatch(ids: number[], userId: number): Promise<number> {
    return this.webhooks.enableBatch(ids, userId);
  }

  async disableWebhooksBatch(ids: number[], userId: number): Promise<number> {
    return this.webhooks.disableBatch(ids, userId);
  }

  async deleteWebhooksBatch(ids: number[], userId: number): Promise<number> {
    return this.webhooks.deleteBatch(ids, userId);
  }

  async getRuleWebhooksForNotification(ruleId: number): Promise<UserWebhook[]> {
    return this.webhooks.getRuleWebhooksForNotification(ruleId);
  }

  // ==================== Auth operations ====================

  async addRefreshToken(userId: number, rawToken: string, jti: string, expiresAt: number): Promise<void> {
    return this.auth.addRefreshToken(userId, rawToken, jti, expiresAt);
  }

  async getRefreshToken(rawToken: string): Promise<RefreshTokenRecord | null> {
    return this.auth.getRefreshToken(rawToken);
  }

  async revokeRefreshToken(rawToken: string, replacedByJti: string): Promise<void> {
    return this.auth.revokeRefreshToken(rawToken, replacedByJti);
  }

  async revokeAllRefreshTokensForUser(userId: number): Promise<void> {
    return this.auth.revokeAllForUser(userId);
  }

  async cleanupRefreshTokens(): Promise<void> {
    return this.auth.cleanupRefreshTokens();
  }

  async blacklistAccessToken(jti: string, userId: number, expiresAt: number, reason: string): Promise<void> {
    return this.auth.blacklistAccessToken(jti, userId, expiresAt, reason);
  }

  async isAccessTokenBlacklisted(jti: string): Promise<boolean> {
    return this.auth.isBlacklisted(jti);
  }

  async cleanupExpiredBlacklistTokens(): Promise<void> {
    return this.auth.cleanupExpiredBlacklistTokens();
  }

  // ==================== Audit operations ====================

  async createAuditLog(userId: number, eventType: string, eventData?: string, ipAddress?: string, userAgent?: string): Promise<void> {
    return this.audit.createLog(userId, eventType, eventData, ipAddress, userAgent);
  }

  async getAuditLogsByUserId(userId: number, limit: number = 100): Promise<AuditLog[]> {
    return this.audit.getLogsByUserId(userId, limit);
  }

  async getAllAuditLogs(limit: number = 100, eventType?: string, userId?: number): Promise<AuditLog[]> {
    return this.audit.getAllLogs(limit, eventType, userId);
  }

  async logAdminAction(adminUserId: number, action: string, targetUserId: number | null, details?: string): Promise<void> {
    return this.audit.logAdminAction(adminUserId, action, targetUserId, details);
  }

  async cleanOldAuditLogs(daysToKeep: number): Promise<number> {
    return this.audit.cleanupOldLogs(daysToKeep);
  }

  async getGlobalStats() {
    return this.audit.getGlobalStats();
  }

  /** Lightweight check used by health endpoint */
  async getStats() {
    return this.audit.getGlobalStats();
  }

  // ==================== OAuth operations ====================

  async findOAuthAccount(provider: string, providerAccountId: string): Promise<OAuthAccount | null> {
    return this.oauth.findByProviderAccount(provider as 'google' | 'github' | 'discord', providerAccountId);
  }

  async getOAuthAccountsByUserId(userId: number): Promise<OAuthAccount[]> {
    return this.oauth.findByUserId(userId);
  }

  async findOAuthAccountByEmail(email: string): Promise<OAuthAccount | null> {
    return this.oauth.findByProviderEmail(email);
  }

  async linkOAuthAccount(userId: number, provider: string, providerAccountId: string, providerEmail?: string): Promise<OAuthAccount> {
    return this.oauth.link(userId, provider as 'google' | 'github' | 'discord', providerAccountId, providerEmail);
  }

  async unlinkOAuthAccount(userId: number, provider: string): Promise<boolean> {
    return this.oauth.unlink(userId, provider as 'google' | 'github' | 'discord');
  }
}

export const store = new Store(db);
