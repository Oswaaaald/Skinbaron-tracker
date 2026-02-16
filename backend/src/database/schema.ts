import { pgTable, pgEnum, serial, text, boolean, real, timestamp, integer, unique, index, primaryKey } from 'drizzle-orm/pg-core';

// ==================== ENUMS ====================

export const filterEnum = pgEnum('filter_enum', ['all', 'only', 'exclude']);
export const webhookTypeEnum = pgEnum('webhook_type_enum', ['discord']);
export const notificationStyleEnum = pgEnum('notification_style_enum', ['compact', 'detailed']);
export const oauthProviderEnum = pgEnum('oauth_provider_enum', ['google', 'github', 'discord']);

// ==================== TABLES ====================

export const users = pgTable('users', {
  id: serial('id').primaryKey(),
  username: text('username').notNull().unique(),
  email: text('email').notNull().unique(),
  password_hash: text('password_hash'),
  is_admin: boolean('is_admin').default(false).notNull(),
  is_super_admin: boolean('is_super_admin').default(false).notNull(),
  is_approved: boolean('is_approved').default(false).notNull(),
  totp_enabled: boolean('totp_enabled').default(false).notNull(),
  totp_secret_encrypted: text('totp_secret_encrypted'),
  recovery_codes_encrypted: text('recovery_codes_encrypted'),
  avatar_filename: text('avatar_filename'),
  use_gravatar: boolean('use_gravatar').default(true).notNull(),
  tos_accepted_at: timestamp('tos_accepted_at', { withTimezone: true }),
  created_at: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updated_at: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => [
  index('idx_users_approved').on(table.is_approved),
  index('idx_users_admin_approved').on(table.is_admin, table.is_approved),
]);

export const rules = pgTable('rules', {
  id: serial('id').primaryKey(),
  user_id: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  search_item: text('search_item').notNull(),
  min_price: real('min_price'),
  max_price: real('max_price'),
  min_wear: real('min_wear'),
  max_wear: real('max_wear'),
  stattrak_filter: filterEnum('stattrak_filter').default('all').notNull(),
  souvenir_filter: filterEnum('souvenir_filter').default('all').notNull(),
  sticker_filter: filterEnum('sticker_filter').default('all').notNull(),
  enabled: boolean('enabled').default(true).notNull(),
  created_at: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updated_at: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => [
  index('idx_rules_enabled').on(table.enabled),
  index('idx_rules_user_enabled').on(table.user_id, table.enabled),
]);

export const userWebhooks = pgTable('user_webhooks', {
  id: serial('id').primaryKey(),
  user_id: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  name: text('name').notNull(),
  webhook_url_encrypted: text('webhook_url_encrypted').notNull(),
  webhook_type: webhookTypeEnum('webhook_type').default('discord').notNull(),
  notification_style: notificationStyleEnum('notification_style').default('compact').notNull(),
  is_active: boolean('is_active').default(true).notNull(),
  created_at: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  updated_at: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => [
  unique('webhooks_user_name_unique').on(table.user_id, table.name),
  index('idx_webhooks_user_active').on(table.user_id, table.is_active),
]);

export const alerts = pgTable('alerts', {
  id: serial('id').primaryKey(),
  rule_id: integer('rule_id').notNull().references(() => rules.id, { onDelete: 'cascade' }),
  sale_id: text('sale_id').notNull(),
  item_name: text('item_name').notNull(),
  price: real('price').notNull(),
  wear_value: real('wear_value'),
  stattrak: boolean('stattrak').default(false).notNull(),
  souvenir: boolean('souvenir').default(false).notNull(),
  has_stickers: boolean('has_stickers').default(false).notNull(),
  skin_url: text('skin_url').notNull(),
  notified_at: timestamp('notified_at', { withTimezone: true }),
  sent_at: timestamp('sent_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => [
  unique('alerts_rule_sale_unique').on(table.rule_id, table.sale_id),
  index('idx_alerts_sale_id').on(table.sale_id),
  index('idx_alerts_rule_id').on(table.rule_id),
  index('idx_alerts_sent_at').on(table.sent_at),
  index('idx_alerts_rule_sent').on(table.rule_id, table.sent_at),
  index('idx_alerts_notified').on(table.rule_id, table.notified_at),
]);

export const ruleWebhooks = pgTable('rule_webhooks', {
  rule_id: integer('rule_id').notNull().references(() => rules.id, { onDelete: 'cascade' }),
  webhook_id: integer('webhook_id').notNull().references(() => userWebhooks.id, { onDelete: 'cascade' }),
}, (table) => [
  primaryKey({ columns: [table.rule_id, table.webhook_id] }),
  index('idx_rule_webhooks_webhook').on(table.webhook_id),
]);

export const auditLog = pgTable('audit_log', {
  id: serial('id').primaryKey(),
  user_id: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  event_type: text('event_type').notNull(),
  event_data: text('event_data'),
  ip_address: text('ip_address'),
  user_agent: text('user_agent'),
  created_at: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => [
  index('idx_audit_log_event_type').on(table.event_type),
  index('idx_audit_log_created_at').on(table.created_at),
  index('idx_audit_log_user_created').on(table.user_id, table.created_at),
  index('idx_audit_user_event_date').on(table.user_id, table.event_type, table.created_at),
  index('idx_audit_event_created').on(table.event_type, table.created_at),
]);

export const adminActions = pgTable('admin_actions', {
  id: serial('id').primaryKey(),
  admin_user_id: integer('admin_user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  action: text('action').notNull(),
  target_user_id: integer('target_user_id').references(() => users.id, { onDelete: 'set null' }),
  details: text('details'),
  created_at: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => [
  index('idx_admin_actions_admin').on(table.admin_user_id),
  index('idx_admin_actions_target').on(table.target_user_id),
  index('idx_admin_actions_created').on(table.created_at),
  index('idx_admin_actions_admin_created').on(table.admin_user_id, table.created_at),
]);

export const refreshTokens = pgTable('refresh_tokens', {
  id: serial('id').primaryKey(),
  user_id: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  token_hash: text('token_hash').notNull().unique(),
  token_jti: text('token_jti').notNull().unique(),
  expires_at: timestamp('expires_at', { withTimezone: true }).notNull(),
  revoked_at: timestamp('revoked_at', { withTimezone: true }),
  replaced_by_jti: text('replaced_by_jti'),
  created_at: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => [
  index('idx_refresh_tokens_expiry').on(table.expires_at),
  index('idx_refresh_tokens_revoked').on(table.revoked_at),
  index('idx_refresh_tokens_user_expires').on(table.user_id, table.expires_at),
  index('idx_refresh_tokens_expiry_revoked').on(table.expires_at, table.revoked_at),
]);

export const accessTokenBlacklist = pgTable('access_token_blacklist', {
  jti: text('jti').primaryKey(),
  user_id: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  expires_at: timestamp('expires_at', { withTimezone: true }).notNull(),
  reason: text('reason'),
  created_at: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => [
  index('idx_token_blacklist_expiry').on(table.expires_at),
  index('idx_token_blacklist_user').on(table.user_id),
]);

export const passkeys = pgTable('passkeys', {
  id: serial('id').primaryKey(),
  user_id: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  credential_id: text('credential_id').notNull().unique(),
  public_key: text('public_key').notNull(),
  counter: integer('counter').notNull().default(0),
  device_type: text('device_type').notNull(), // 'singleDevice' | 'multiDevice'
  backed_up: boolean('backed_up').notNull().default(false),
  transports: text('transports'), // JSON array of AuthenticatorTransport
  name: text('name').notNull().default('My Passkey'),
  created_at: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
  last_used_at: timestamp('last_used_at', { withTimezone: true }),
}, (table) => [
  index('idx_passkeys_user_id').on(table.user_id),
  index('idx_passkeys_credential_id').on(table.credential_id),
]);

export const oauthAccounts = pgTable('oauth_accounts', {
  id: serial('id').primaryKey(),
  user_id: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  provider: oauthProviderEnum('provider').notNull(),
  provider_account_id: text('provider_account_id').notNull(),
  provider_email: text('provider_email'),
  created_at: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => [
  unique('oauth_provider_account_unique').on(table.provider, table.provider_account_id),
  unique('oauth_user_provider_unique').on(table.user_id, table.provider),
  index('idx_oauth_user_id').on(table.user_id),
  index('idx_oauth_provider_account').on(table.provider, table.provider_account_id),
  index('idx_oauth_provider_email').on(table.provider_email),
]);

// ==================== INFERRED TYPES ====================

/** User row from database */
type UserSelect = typeof users.$inferSelect;

/** User with optional decrypted 2FA fields (populated by repository) */
export type User = UserSelect & {
  totp_secret?: string | null;
  recovery_codes?: string | null;
};

/** Rule row from database with webhook_ids from junction table */
export type Rule = typeof rules.$inferSelect & {
  webhook_ids: number[];
};

/** Alert row from database */
export type Alert = typeof alerts.$inferSelect;

/** Webhook with optional decrypted URL */
export type UserWebhook = typeof userWebhooks.$inferSelect & {
  webhook_url?: string;
};

/** Refresh token record */
export type RefreshTokenRecord = typeof refreshTokens.$inferSelect;

/** OAuth account linked to a user */
export type OAuthAccount = typeof oauthAccounts.$inferSelect;

/** Passkey/WebAuthn credential */
export type Passkey = typeof passkeys.$inferSelect;

/** Audit log with optional joined user info */
export type AuditLog = typeof auditLog.$inferSelect & {
  username?: string | null;
  email?: string | null;
};

/** Admin action with joined usernames */
export type AdminAction = typeof adminActions.$inferSelect & {
  admin_username: string | null;
  target_username: string | null;
};

// Insert types
export type InsertUser = typeof users.$inferInsert;
export type InsertRule = typeof rules.$inferInsert;
export type InsertAlert = typeof alerts.$inferInsert;
export type InsertWebhook = typeof userWebhooks.$inferInsert;

/** Alert creation type (omits auto-generated fields) */
export type CreateAlert = Omit<typeof alerts.$inferInsert, 'id' | 'sent_at' | 'notified_at'>;

/** Rule creation type with webhook_ids for junction table */
export type CreateRule = Omit<typeof rules.$inferInsert, 'id' | 'created_at' | 'updated_at'> & {
  webhook_ids: number[];
};
