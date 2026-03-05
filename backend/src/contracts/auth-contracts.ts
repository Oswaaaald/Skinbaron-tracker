import {
  authUserPublicJsonSchema,
  profileResponseJsonSchema,
  loginResponseJsonSchema,
  registerResponseJsonSchema,
} from '@skinbaron/contracts';

export const authUserPublicResponseSchema = authUserPublicJsonSchema;
export const profileResponseSchema = profileResponseJsonSchema;
export const loginResponseSchema = loginResponseJsonSchema;
export const registerResponseSchema = registerResponseJsonSchema;

const authUserPublicProperties = (authUserPublicJsonSchema as { properties: Record<string, unknown> }).properties;

export const authSessionUserSchema = {
  type: 'object',
  additionalProperties: false,
  required: ['id', 'username', 'email', 'avatar_url', 'use_gravatar', 'is_admin', 'is_super_admin', 'has_password'],
  properties: {
    ...authUserPublicProperties,
    token_expires_at: { type: 'number' },
  },
} as const;

export const authSessionResponseSchema = {
  type: 'object',
  additionalProperties: false,
  required: ['success', 'data'],
  properties: {
    success: { type: 'boolean' },
    data: authSessionUserSchema,
  },
} as const;

export const profileUpdateResponseSchema = {
  type: 'object',
  additionalProperties: false,
  required: ['success', 'message', 'data'],
  properties: {
    success: { type: 'boolean' },
    message: { type: 'string' },
    data: authUserPublicJsonSchema,
  },
} as const;
