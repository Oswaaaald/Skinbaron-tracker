import { z } from 'zod';

// ==================== Re-export types from Drizzle schema ====================
export type {
  User,
  Rule,
  Alert,
  UserWebhook,
  RefreshTokenRecord,
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
  min_price: z.number().min(0).nullable().optional(),
  max_price: z.number().min(0).nullable().optional(),
  min_wear: z.number().min(0).max(1).nullable().optional(),
  max_wear: z.number().min(0).max(1).nullable().optional(),
  stattrak_filter: z.enum(['all', 'only', 'exclude']).default('all'),
  souvenir_filter: z.enum(['all', 'only', 'exclude']).default('all'),
  sticker_filter: z.enum(['all', 'only', 'exclude']).default('all'),
  webhook_ids: z.array(z.number()).default([]),
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
