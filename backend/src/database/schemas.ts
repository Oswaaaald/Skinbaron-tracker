import { z } from 'zod';

// ==================== Re-export types from Drizzle schema ====================
export type {
  User,
  Rule,
  Alert,
  UserWebhook,
  RefreshTokenRecord,
  OAuthAccount,
  AuditLog,
  AdminAction,
  CreateAlert,
  CreateRule,
  InsertUser,
  InsertRule,
  InsertAlert,
  InsertWebhook,
} from './schema.js';

// ==================== Zod Validation Schemas (route input validation) ====================

/**
 * Rule validation schema
 */
export const RuleSchema = z.object({
  id: z.number().optional(),
  user_id: z.number(),
  search_item: z.string().min(1).max(200),
  min_price: z.number().min(0).max(1_000_000).nullable().optional(),
  max_price: z.number().min(0).max(1_000_000).nullable().optional(),
  min_wear: z.number().min(0).max(1).nullable().optional(),
  max_wear: z.number().min(0).max(1).nullable().optional(),
  stattrak_filter: z.enum(['all', 'only', 'exclude']).default('all'),
  souvenir_filter: z.enum(['all', 'only', 'exclude']).default('all'),
  sticker_filter: z.enum(['all', 'only', 'exclude']).default('all'),
  webhook_ids: z.array(z.number()).max(10).default([]),
  enabled: z.boolean().default(true),
  created_at: z.date().optional(),
  updated_at: z.date().optional(),
});

/**
 * User creation schema
 */
export const CreateUserSchema = z.object({
  username: z.string().min(3).max(20),
  email: z.string().email(),
  password_hash: z.string(),
  totp_secret_encrypted: z.string().nullable().optional(),
  totp_enabled: z.boolean().optional(),
  recovery_codes_encrypted: z.string().nullable().optional(),
});

export type CreateUser = z.infer<typeof CreateUserSchema>;

/**
 * Webhook creation schema
 */
export const CreateUserWebhookSchema = z.object({
  name: z.string().min(1).max(50),
  webhook_url: z.string().url(),
  webhook_type: z.enum(['discord']).default('discord'),
  notification_style: z.enum(['compact', 'detailed']).default('compact'),
  is_active: z.boolean().default(true),
});

export type CreateUserWebhook = z.infer<typeof CreateUserWebhookSchema>;
// ==================== Admin Route Schemas ====================

/** Shared: params with :id (integer) — used for admin user routes */
export const AdminUserParamsSchema = z.object({
  id: z.coerce.number().int().positive(),
});

/** Shared: params with :sanctionId (integer) */
export const SanctionParamsSchema = z.object({
  sanctionId: z.coerce.number().int().positive(),
});

/** GET /admin/users querystring */
export const AdminUsersQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(100).default(20),
  offset: z.coerce.number().int().min(0).default(0),
  sort_by: z.enum(['username', 'email', 'role', 'created_at', 'rules', 'alerts', 'webhooks']).default('created_at'),
  sort_dir: z.enum(['asc', 'desc']).default('desc'),
  search: z.string().max(200).optional(),
  role: z.enum(['admin', 'user', 'all']).default('all'),
  status: z.enum(['all', 'sanctioned', 'active']).default('all'),
});

/** PATCH /admin/users/:id/admin body */
export const AdminToggleSchema = z.object({
  is_admin: z.boolean(),
});

/** PATCH /admin/users/:id/restrict body */
export const RestrictUserSchema = z.object({
  restriction_type: z.enum(['temporary', 'permanent']),
  reason: z.string().min(1).max(500),
  duration_hours: z.number().int().min(1).max(8760).optional(),
  ban_email: z.boolean().optional(),
}).refine(
  data => data.restriction_type !== 'temporary' || data.duration_hours !== undefined,
  { message: 'duration_hours is required for temporary restrictions', path: ['duration_hours'] },
);

/** PATCH /admin/users/:id/unrestrict body */
export const UnrestrictUserSchema = z.object({
  reason: z.string().min(1).max(500),
});

/** PATCH /admin/users/:id/username body */
export const AdminUsernameSchema = z.object({
  username: z.string()
    .min(3, 'Username must be at least 3 characters')
    .max(32, 'Username must be at most 32 characters')
    .regex(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers and underscores'),
});

/** POST /admin/users/:id/reset body */
export const AdminResetSchema = z.object({
  target: z.enum(['2fa', 'passkeys', 'sessions']),
});

/** GET /admin/audit-logs querystring */
export const AdminAuditQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(1000).default(100),
  event_type: z.string().max(50).optional(),
  user_id: z.coerce.number().int().positive().optional(),
});

/** GET /admin/admin-logs querystring (superadmin only) */
export const AdminLogsQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(1000).default(100),
  action: z.string().max(50).optional(),
  admin_id: z.coerce.number().int().positive().optional(),
});

/** GET /admin/audit-logs/:userId params + querystring */
export const AdminUserAuditParamsSchema = z.object({
  userId: z.coerce.number().int().positive(),
});

export const AdminUserAuditQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(500).default(100),
});

/** GET /admin/users/search querystring */
export const AdminSearchQuerySchema = z.object({
  q: z.string().min(1).max(100),
  admins_only: z.enum(['true', 'false']).optional().transform(v => v === 'true'),
});

// ==================== Auth Route Schemas ====================

/** POST /auth/finalize-oauth-registration body */
export const FinalizeOAuthRegistrationSchema = z.object({
  username: z.string()
    .min(3, 'Username must be at least 3 characters')
    .max(20, 'Username must be at most 20 characters')
    .regex(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers and underscores'),
  tos_accepted: z.literal(true, { error: 'You must accept the Terms of Service' }),
});

/** POST /auth/verify-oauth-2fa body */
export const VerifyOAuth2FASchema = z.object({
  totp_code: z.string().min(6).max(8),
});

/** POST /auth/refresh body (optional refresh token) */
export const RefreshBodySchema = z.object({
  refresh_token: z.string().max(2048).optional(),
});

/** POST /auth/logout body (optional refresh token) */
export const LogoutBodySchema = z.object({
  refresh_token: z.string().max(2048).optional(),
});

/** GET /auth/oauth/:provider params */
export const OAuthProviderParamsSchema = z.object({
  provider: z.string().min(1).max(20),
});

/** GET /auth/oauth/:provider querystring */
export const OAuthProviderQuerySchema = z.object({
  mode: z.enum(['login', 'register']).optional(),
});

/** GET /auth/oauth/:provider/callback querystring */
export const OAuthCallbackQuerySchema = z.object({
  code: z.string().max(4096).optional(),
  state: z.string().max(4096).optional(),
  error: z.string().max(500).optional(),
});

/** POST /auth/passkey/authenticate-verify body */
export const PasskeyAuthVerifySchema = z.object({
  credential: z.record(z.string(), z.unknown()).refine(obj => JSON.stringify(obj).length <= 65536, 'Credential payload too large'),
  challengeKey: z.string().min(1).max(512),
});

// ==================== User Route Schemas ====================

/** POST /user/2fa/enable body */
export const Enable2FASchema = z.object({
  code: z.string().length(6, '2FA code must be exactly 6 digits').regex(/^\d{6}$/, '2FA code must be exactly 6 digits'),
});

/** POST /user/2fa/disable body */
export const Disable2FASchema = z.object({
  password: z.string().max(128).optional(),
  totp_code: z.string().max(8).optional(),
});

/** DELETE /user/account body */
export const DeleteAccountSchema = z.object({
  password: z.string().max(128).optional(),
  totp_code: z.string().max(8).optional(),
});

/** Passkey :id param (PATCH/DELETE /user/passkeys/:id) */
export const PasskeyParamsSchema = z.object({
  id: z.coerce.number().int().positive(),
});

/** PATCH /user/passkeys/:id body */
export const PasskeyRenameSchema = z.object({
  name: z.string().min(1).max(64),
});

/** POST /user/passkeys/register-verify body */
export const PasskeyRegisterVerifySchema = z.object({
  credential: z.record(z.string(), z.unknown()).refine(obj => JSON.stringify(obj).length <= 65536, 'Credential payload too large'),
  name: z.string().max(64).optional(),
});

/** GET /user/audit-logs querystring */
export const UserAuditQuerySchema = z.object({
  limit: z.coerce.number().int().min(1).max(500).default(100),
});

/** DELETE /user/oauth-accounts/:provider params */
export const OAuthUnlinkParamsSchema = z.object({
  provider: z.string().min(1).max(20),
});

// ==================== Items Route Schemas ====================

/** GET /items/search querystring */
export const ItemSearchQuerySchema = z.object({
  q: z.string().max(200).optional(),
  limit: z.string().optional().transform(val => {
    if (!val) return 20;
    const n = parseInt(val, 10);
    return isNaN(n) ? 20 : Math.min(n, 50);
  }),
});

// ==================== Batch Operation Schemas ====================

/** POST /rules/batch/enable or /rules/batch/disable body */
export const BatchRuleIdsSchema = z.object({
  rule_ids: z.array(z.number().int().positive()).max(50).optional(),
});

/** POST /rules/batch/delete body */
export const BatchRuleDeleteSchema = z.object({
  rule_ids: z.array(z.number().int().positive()).max(50).optional(),
  confirm_all: z.boolean().optional(),
});

/** POST /webhooks/batch/enable or /webhooks/batch/disable body */
export const BatchWebhookIdsSchema = z.object({
  webhook_ids: z.array(z.number().int().positive()).max(20).optional(),
});

/** POST /webhooks/batch/delete body */
export const BatchWebhookDeleteSchema = z.object({
  webhook_ids: z.array(z.number().int().positive()).max(20).optional(),
  confirm_all: z.boolean().optional(),
});