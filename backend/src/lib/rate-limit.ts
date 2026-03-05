import { RATE_LIMIT_PRESETS, buildRateLimitConfig } from '@skinbaron/contracts';

export const rateLimitPresets = RATE_LIMIT_PRESETS;

export const authStrictRateLimit = buildRateLimitConfig(RATE_LIMIT_PRESETS.AUTH_STRICT);
export const userSensitiveRateLimit = buildRateLimitConfig(RATE_LIMIT_PRESETS.USER_SENSITIVE);
export const userAvatarRateLimit = buildRateLimitConfig(RATE_LIMIT_PRESETS.USER_AVATAR);
export const userHeavyRateLimit = buildRateLimitConfig(RATE_LIMIT_PRESETS.USER_HEAVY);
export const rulesWriteRateLimit = buildRateLimitConfig(RATE_LIMIT_PRESETS.RULE_WRITE);
export const batchWriteRateLimit = buildRateLimitConfig(RATE_LIMIT_PRESETS.BATCH_WRITE);
export const webhooksWriteRateLimit = buildRateLimitConfig(RATE_LIMIT_PRESETS.WEBHOOK_WRITE);
export const adminWriteRateLimit = buildRateLimitConfig(RATE_LIMIT_PRESETS.ADMIN_WRITE);

export type RateLimitConfig = ReturnType<typeof buildRateLimitConfig>;
