import { z } from 'zod';

/**
 * DELETION POLICY
 * ===============
 * All user deletions are handled by database CASCADE constraints.
 * 
 * Rules:
 * - Personal data (rules, alerts, webhooks, audit logs) → CASCADE (deleted with user)
 * - Admin actions performed by user → CASCADE (deleted with admin)
 * - Admin actions targeting user → CASCADE (deleted with target)
 * 
 * To add a new feature:
 * 1. Add FOREIGN KEY with appropriate ON DELETE action (CASCADE or SET NULL)
 * 2. No code change needed in deleteUser() - it only deletes the user record
 * 3. Test user deletion to verify cascade behavior
 */

// ==================== ZOD SCHEMAS ====================

export const RuleSchema = z.object({
  id: z.number().optional(),
  user_id: z.number().int().positive(),
  search_item: z.string().min(1, 'Search item is required'),
  min_price: z.number().min(0).optional(),
  max_price: z.number().min(0).optional(),
  min_wear: z.number().min(0).max(1).optional(),
  max_wear: z.number().min(0).max(1).optional(),
  stattrak_filter: z.enum(['all', 'only', 'exclude']).default('all'),
  souvenir_filter: z.enum(['all', 'only', 'exclude']).default('all'),
  sticker_filter: z.enum(['all', 'only', 'exclude']).default('all'),
  webhook_ids: z.array(z.number()).min(0).default([]),
  enabled: z.boolean().default(true),
  created_at: z.string().optional(),
  updated_at: z.string().optional(),
});

export const CreateRuleSchema = RuleSchema.omit({ id: true, created_at: true, updated_at: true });

export const AlertSchema = z.object({
  id: z.number().optional(),
  rule_id: z.number(),
  sale_id: z.string().min(1, 'Sale ID is required'),
  item_name: z.string().min(1, 'Item name is required'),
  price: z.number().min(0),
  wear_value: z.number().min(0).max(1).optional(),
  stattrak: z.boolean().default(false),
  souvenir: z.boolean().default(false),
  has_stickers: z.boolean().default(false),
  skin_url: z.string().url('Valid skin URL required'),
  sent_at: z.string().optional(),
});

export const CreateUserSchema = z.object({
  username: z.string().min(3).max(20),
  email: z.string().email(),
  password_hash: z.string(),
  totp_secret_encrypted: z.string().nullable().optional(),
  totp_enabled: z.number().optional(),
  recovery_codes_encrypted: z.string().nullable().optional(),
});

export const UserSchema = z.object({
  id: z.number(),
  username: z.string().min(3).max(20),
  email: z.string().email(),
  password_hash: z.string(),
  is_admin: z.number().default(0),
  is_super_admin: z.number().default(0),
  is_approved: z.number().default(0),
  totp_secret_encrypted: z.string().nullable().optional(),
  totp_enabled: z.number().default(0).optional(),
  recovery_codes_encrypted: z.string().nullable().optional(),
  created_at: z.string(),
  updated_at: z.string(),
});

export const CreateUserWebhookSchema = z.object({
  name: z.string().min(1).max(50),
  webhook_url: z.string().url('Valid webhook URL required'),
  webhook_type: z.enum(['discord']).default('discord'),
  notification_style: z.enum(['compact', 'detailed']).default('compact'),
  is_active: z.boolean().default(true),
});

export const UserWebhookSchema = z.object({
  id: z.number(),
  user_id: z.number(),
  name: z.string().min(1).max(50),
  webhook_url_encrypted: z.string(),
  webhook_type: z.enum(['discord']),
  notification_style: z.enum(['compact', 'detailed']),
  is_active: z.boolean(),
  created_at: z.string(),
  updated_at: z.string(),
});

// ==================== TYPESCRIPT TYPES ====================

export type Rule = z.infer<typeof RuleSchema>;
export type Alert = z.infer<typeof AlertSchema>;
export type User = z.infer<typeof UserSchema> & {
  // Decrypted fields (added by repository)
  totp_secret?: string | null;
  recovery_codes?: string | null;
};
export type CreateUser = z.infer<typeof CreateUserSchema>;
export type CreateRule = Omit<Rule, 'id' | 'created_at' | 'updated_at'>;
export type CreateAlert = Omit<Alert, 'id' | 'sent_at'>;

export type UserWebhook = z.infer<typeof UserWebhookSchema> & {
  webhook_url?: string;
};
export type CreateUserWebhook = z.infer<typeof CreateUserWebhookSchema>;

export type RefreshTokenRecord = {
  id: number;
  user_id: number;
  token_hash: string;
  token_jti: string;
  expires_at: string;
  revoked_at?: string | null;
  replaced_by_jti?: string | null;
  created_at: string;
};

export type AccessTokenBlacklistRecord = {
  jti: string;
  user_id: number;
  expires_at: string;
  reason?: string | null;
  created_at: string;
};

export type AuditLog = {
  id: number;
  user_id: number;
  event_type: string;
  event_data: string | null;
  ip_address: string | null;
  user_agent: string | null;
  created_at: string;
  username?: string;
  email?: string;
};

// ==================== DATABASE ROW TYPES ====================

export interface RuleRow {
  id: number;
  user_id: number;
  search_item: string;
  min_price: number | null;
  max_price: number | null;
  min_wear: number | null;
  max_wear: number | null;
  stattrak_filter: string;
  souvenir_filter: string;
  sticker_filter: string;
  webhook_ids: string | null;
  enabled: number;
  created_at: string;
  updated_at: string;
}

export interface AlertRow {
  id: number;
  rule_id: number;
  sale_id: string;
  item_name: string;
  price: number;
  wear_value: number | null;
  stattrak: number;
  souvenir: number;
  has_stickers: number;
  skin_url: string;
  sent_at: string;
}

export interface UserRow {
  id: number;
  username: string;
  email: string;
  password_hash: string;
  is_admin: number;
  is_super_admin: number;
  is_approved: number;
  totp_secret_encrypted: string | null;
  totp_enabled: number;
  recovery_codes_encrypted: string | null;
  created_at: string;
  updated_at: string;
}

export interface WebhookRow {
  id: number;
  user_id: number;
  name: string;
  webhook_url_encrypted: string;
  webhook_type: string;
  notification_style: string;
  is_active: number;
  created_at: string;
  updated_at: string;
}
