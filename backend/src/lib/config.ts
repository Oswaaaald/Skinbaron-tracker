import { config } from 'dotenv';
import { z } from 'zod';

// Load environment variables
config();

// Configuration schema with validation
const ConfigSchema = z.object({
  // Server
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().default(8080),
  COOKIE_DOMAIN: z.string().optional(),
  
  // SkinBaron API
  SB_API_KEY: z.string().optional(),
  
  // Discord
  DISCORD_WEBHOOK: z.string().url().optional().or(z.literal('')),
  DISCORD_BOT_NAME: z.string().default('🔔 SkinBaron Tracker'),
  DISCORD_BOT_AVATAR: z.string().url().default('https://skinbaron.de/favicon.png'),
  
  // Database
  DATABASE_URL: z.string().url(),
  DATABASE_SSL: z.coerce.boolean().default(false),
  
  // Authentication
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters for security'),
  JWT_ACCESS_SECRET: z.string().min(32).optional().or(z.literal('')),
  JWT_REFRESH_SECRET: z.string().min(32).optional().or(z.literal('')),
  // Note: A strong JWT secret should be randomly generated with high entropy
  // Encryption key for sensitive data (defaults to JWT_SECRET for backward compatibility)
  ENCRYPTION_KEY: z.string().optional(),
  APP_VERSION: z.string().default('dev'),
  
  // Polling
  POLL_CRON: z.string().default('*/5 * * * *'),
  SCHEDULER_ENABLED: z.coerce.boolean().default(true),
  
  // API
  NEXT_PUBLIC_API_URL: z.string().min(1, 'NEXT_PUBLIC_API_URL is required'),
  CORS_ORIGIN: z.string().min(1, 'CORS_ORIGIN is required'),
  RATE_LIMIT_MAX: z.coerce.number().default(1000),
  RATE_LIMIT_WINDOW: z.coerce.number().default(60000),
  
  // Logging
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
  
  // Audit logs retention (GDPR compliance)
  AUDIT_LOG_RETENTION_DAYS: z.coerce.number().default(365),
  ALERT_RETENTION_DAYS: z.coerce.number().default(90),

  // OAuth2 providers (all optional — only enabled if configured)
  GOOGLE_CLIENT_ID: z.string().optional(),
  GOOGLE_CLIENT_SECRET: z.string().optional(),
  GITHUB_CLIENT_ID: z.string().optional(),
  GITHUB_CLIENT_SECRET: z.string().optional(),
  DISCORD_CLIENT_ID: z.string().optional(),
  DISCORD_CLIENT_SECRET: z.string().optional(),

  // WebAuthn / Passkeys (optional — derived from CORS_ORIGIN if not set)
  WEBAUTHN_RP_ID: z.string().optional(),
  WEBAUTHN_RP_NAME: z.string().optional(),
  WEBAUTHN_RP_ORIGIN: z.string().optional(),
});

// Parse and validate configuration
function loadConfig() {
  try {
    const parsed = ConfigSchema.parse(process.env);
    // Enforce encryption hygiene: require a distinct key in production
    if (parsed.NODE_ENV === 'production') {
      if (!parsed.ENCRYPTION_KEY) {
        throw new Error('ENCRYPTION_KEY is required in production and must differ from JWT_SECRET');
      }
      if (parsed.ENCRYPTION_KEY === parsed.JWT_SECRET) {
        throw new Error('ENCRYPTION_KEY must not equal JWT_SECRET in production');
      }
    }

    const config = {
      ...parsed,
      ENCRYPTION_KEY: parsed.ENCRYPTION_KEY || parsed.JWT_SECRET,
      JWT_ACCESS_SECRET: parsed.JWT_ACCESS_SECRET || parsed.JWT_SECRET,
      JWT_REFRESH_SECRET: parsed.JWT_REFRESH_SECRET || parsed.JWT_SECRET,
    };

    // Derive WebAuthn RP values from CORS_ORIGIN if not explicitly set
    const rpOrigin = config.WEBAUTHN_RP_ORIGIN || config.CORS_ORIGIN;
    let rpId = config.WEBAUTHN_RP_ID;
    if (!rpId) {
      try {
        rpId = new URL(rpOrigin).hostname;
      } catch {
        rpId = 'localhost';
      }
    }
    const webauthnConfig = {
      ...config,
      WEBAUTHN_RP_ID: rpId,
      WEBAUTHN_RP_NAME: config.WEBAUTHN_RP_NAME || 'SkinBaron Tracker',
      WEBAUTHN_RP_ORIGIN: rpOrigin,
    };

    return webauthnConfig;
  } catch (error) {
    if (error instanceof z.ZodError) {
      console.error('❌ Configuration validation failed:');
      for (const issue of error.issues) {
        console.error(`  - ${issue.path.join('.')}: ${issue.message}`);
      }
    } else {
      console.error('❌ Configuration error:', error instanceof Error ? error.message : error);
    }
    process.exit(1);
  }
}

export const appConfig = loadConfig();

// SkinBaron API constants
export const SKINBARON_API = {
  BASE_URL: 'https://api.skinbaron.de',
  APP_ID: 730, // CS2/CS:GO Steam App ID
  ENDPOINTS: {
    SEARCH: '/Search',
  },
} as const;

// Discord embed colors
export const DISCORD_COLORS = {
  MATCH: 0x00ff00,      // Green for matches
} as const;

// User limits
export const MAX_RULES_PER_USER = 50;
export const MAX_WEBHOOKS_PER_USER = 20;

// User cache
export const USER_CACHE_MAX = 500;
export const USER_CACHE_TTL_MS = 30_000; // 30 seconds

// Scheduler / Discord rate-limiting
export const DISCORD_DELAY_MS = 2100; // ~28 messages/min with safety margin
export const API_PAGE_SIZE = 250; // SkinBaron max items per page

// 2FA recovery codes
export const RECOVERY_CODE_COUNT = 10;
export const RECOVERY_CODE_BYTES = 4; // produces 8 hex characters

// Upload limits
export const MAX_UPLOAD_SIZE = 5 * 1024 * 1024; // 5 MB