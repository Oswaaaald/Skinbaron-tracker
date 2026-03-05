import type { z } from 'zod';

export declare const PASSWORD_RULES: {
  readonly minLength: number;
  readonly maxLength: number;
  readonly complexityRegex: RegExp;
  readonly complexityMessage: string;
  readonly weakPasswordMessage: string;
};

export declare const AuthUserPublicSchema: z.ZodType<{
  id: number;
  username: string;
  email: string;
  avatar_url: string | null;
  use_gravatar: boolean;
  is_admin: boolean;
  is_super_admin: boolean;
  has_password: boolean;
}>;

export declare const ProfileResponseSchema: z.ZodType<{
  success: boolean;
  data: z.infer<typeof AuthUserPublicSchema>;
}>;

export declare const LoginResponseSchema: z.ZodType<{
  success: boolean;
  data: Partial<z.infer<typeof AuthUserPublicSchema>> & {
    requires_2fa: boolean;
    token_expires_at?: number;
  };
}>;

export declare const RegisterResponseSchema: z.ZodType<{
  success: boolean;
  message?: string;
  data: Partial<z.infer<typeof AuthUserPublicSchema>> & {
    pending_approval?: boolean;
    token_expires_at?: number;
  };
}>;

export type JsonSchemaObject = Record<string, unknown>;

export declare const authUserPublicJsonSchema: JsonSchemaObject;
export declare const profileResponseJsonSchema: JsonSchemaObject;
export declare const loginResponseJsonSchema: JsonSchemaObject;
export declare const registerResponseJsonSchema: JsonSchemaObject;

export type RateLimitPreset = {
  readonly max: number;
  readonly timeWindow: string;
  readonly error: string;
  readonly message: string;
};

export declare const RATE_LIMIT_PRESETS: {
  readonly AUTH_STRICT: RateLimitPreset;
  readonly USER_SENSITIVE: RateLimitPreset;
  readonly USER_AVATAR: RateLimitPreset;
  readonly USER_HEAVY: RateLimitPreset;
  readonly RULE_WRITE: RateLimitPreset;
  readonly BATCH_WRITE: RateLimitPreset;
  readonly WEBHOOK_WRITE: RateLimitPreset;
  readonly ADMIN_WRITE: RateLimitPreset;
};

export declare function buildRateLimitConfig(preset: RateLimitPreset): {
  max: number;
  timeWindow: string;
  errorResponseBuilder: () => {
    statusCode: number;
    success: boolean;
    error: string;
    message: string;
  };
};
