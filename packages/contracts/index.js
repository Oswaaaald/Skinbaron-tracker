import { z } from 'zod';

export const PASSWORD_RULES = Object.freeze({
  minLength: 8,
  maxLength: 128,
  complexityRegex: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/,
  complexityMessage: 'Password must contain uppercase, lowercase and number',
  weakPasswordMessage: 'Password is too weak. Avoid common words, keyboard patterns, or repeating characters.',
});

export const AuthUserPublicSchema = z.object({
  id: z.number(),
  username: z.string(),
  email: z.string().email(),
  avatar_url: z.string().nullable(),
  use_gravatar: z.boolean(),
  is_admin: z.boolean(),
  is_super_admin: z.boolean(),
  has_password: z.boolean(),
});

export const ProfileResponseSchema = z.object({
  success: z.boolean(),
  data: AuthUserPublicSchema,
});

export const LoginResponseSchema = z.object({
  success: z.boolean(),
  data: AuthUserPublicSchema.partial().extend({
    requires_2fa: z.boolean(),
    token_expires_at: z.number().optional(),
  }),
});

export const RegisterResponseSchema = z.object({
  success: z.boolean(),
  message: z.string().optional(),
  data: z.object({
    pending_approval: z.boolean().optional(),
    token_expires_at: z.number().optional(),
  }).merge(AuthUserPublicSchema.partial()),
});

export const authUserPublicJsonSchema = {
  type: 'object',
  additionalProperties: false,
  required: ['id', 'username', 'email', 'avatar_url', 'use_gravatar', 'is_admin', 'is_super_admin', 'has_password'],
  properties: {
    id: { type: 'number' },
    username: { type: 'string' },
    email: { type: 'string' },
    avatar_url: { type: 'string', nullable: true },
    use_gravatar: { type: 'boolean' },
    is_admin: { type: 'boolean' },
    is_super_admin: { type: 'boolean' },
    has_password: { type: 'boolean' },
  },
};

export const profileResponseJsonSchema = {
  type: 'object',
  additionalProperties: false,
  required: ['success', 'data'],
  properties: {
    success: { type: 'boolean' },
    data: authUserPublicJsonSchema,
  },
};

export const loginResponseJsonSchema = {
  type: 'object',
  additionalProperties: false,
  required: ['success', 'data'],
  properties: {
    success: { type: 'boolean' },
    data: {
      type: 'object',
      additionalProperties: false,
      required: ['requires_2fa'],
      properties: {
        ...authUserPublicJsonSchema.properties,
        requires_2fa: { type: 'boolean' },
        token_expires_at: { type: 'number' },
      },
    },
  },
};

export const registerResponseJsonSchema = {
  type: 'object',
  additionalProperties: false,
  required: ['success', 'data'],
  properties: {
    success: { type: 'boolean' },
    message: { type: 'string' },
    data: {
      type: 'object',
      additionalProperties: false,
      properties: {
        pending_approval: { type: 'boolean' },
        token_expires_at: { type: 'number' },
        ...authUserPublicJsonSchema.properties,
      },
    },
  },
};

export const RATE_LIMIT_PRESETS = Object.freeze({
  AUTH_STRICT: Object.freeze({
    max: 5,
    timeWindow: '1 minute',
    error: 'Too many attempts',
    message: 'Too many authentication attempts. Please try again in 1 minute.',
  }),
  USER_SENSITIVE: Object.freeze({
    max: 5,
    timeWindow: '1 minute',
    error: 'Too many attempts',
    message: 'Too many attempts. Please try again in 1 minute.',
  }),
  USER_AVATAR: Object.freeze({
    max: 3,
    timeWindow: '5 minutes',
    error: 'Too many attempts',
    message: 'Too many avatar changes. Please try again in 5 minutes.',
  }),
  USER_HEAVY: Object.freeze({
    max: 3,
    timeWindow: '5 minutes',
    error: 'Too many attempts',
    message: 'Too many requests. Please try again later.',
  }),
  RULE_WRITE: Object.freeze({
    max: 15,
    timeWindow: '1 minute',
    error: 'Too many attempts',
    message: 'Too many rule changes. Please try again in 1 minute.',
  }),
  BATCH_WRITE: Object.freeze({
    max: 5,
    timeWindow: '1 minute',
    error: 'Too many attempts',
    message: 'Too many batch operations. Please try again in 1 minute.',
  }),
  WEBHOOK_WRITE: Object.freeze({
    max: 10,
    timeWindow: '1 minute',
    error: 'Too many attempts',
    message: 'Too many webhook changes. Please try again in 1 minute.',
  }),
  ADMIN_WRITE: Object.freeze({
    max: 10,
    timeWindow: '1 minute',
    error: 'Too many attempts',
    message: 'Too many admin operations. Please try again in 1 minute.',
  }),
});

export function buildRateLimitConfig(preset) {
  return {
    max: preset.max,
    timeWindow: preset.timeWindow,
    errorResponseBuilder: () => ({
      statusCode: 429,
      success: false,
      error: preset.error,
      message: preset.message,
    }),
  };
}
