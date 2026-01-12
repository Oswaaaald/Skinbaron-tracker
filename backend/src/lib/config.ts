import { config } from 'dotenv';
import { z } from 'zod';

// Load environment variables
config();

// Configuration schema with validation
const ConfigSchema = z.object({
  // Server
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().default(8080),
  
  // SkinBaron API
  SB_API_KEY: z.string().optional(),
  
  // Discord
  DISCORD_WEBHOOK: z.string().url().optional().or(z.literal('')),
  DISCORD_BOT_NAME: z.string().default('🔔 SkinBaron Tracker'),
  DISCORD_BOT_AVATAR: z.string().url().default('https://skinbaron.de/favicon.png'),
  
  // Database
  SQLITE_PATH: z.string().default('./data/alerts.db'),
  
  // Authentication
  JWT_SECRET: z.string().min(1, 'JWT_SECRET is required'),
  // Encryption key for sensitive data (defaults to JWT_SECRET for backward compatibility)
  ENCRYPTION_KEY: z.string().optional(),
  
  // Polling
  POLL_CRON: z.string().default('*/5 * * * *'),
  
  // API
  CORS_ORIGIN: z.string().default('http://localhost:3000'),
  RATE_LIMIT_MAX: z.coerce.number().default(100),
  RATE_LIMIT_WINDOW: z.coerce.number().default(60000),
  
  // Logging
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
  
  // Audit logs retention (GDPR compliance)
  AUDIT_LOG_RETENTION_DAYS: z.coerce.number().default(365),
});

// Parse and validate configuration
function loadConfig() {
  try {
    const parsed = ConfigSchema.parse(process.env);
    // Ensure ENCRYPTION_KEY is set (fallback to JWT_SECRET if not provided)
    const config = {
      ...parsed,
      ENCRYPTION_KEY: parsed.ENCRYPTION_KEY || parsed.JWT_SECRET,
    };
    return config;
  } catch (error) {
    if (error instanceof z.ZodError) {
      error.issues.forEach((_err) => {
        // Errors already logged by Zod
      });
    }
    process.exit(1);
  }
}

export type Config = z.infer<typeof ConfigSchema>;
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
  BEST_DEAL: 0xff9500,  // Orange for best deals
  NEW_ITEM: 0x0099ff,   // Blue for new items
  ERROR: 0xff0000,      // Red for errors
} as const;

export default appConfig;