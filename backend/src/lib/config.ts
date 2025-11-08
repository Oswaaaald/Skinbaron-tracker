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
  
  // Database
  SQLITE_PATH: z.string().default('./data/alerts.db'),
  
  // Authentication
  JWT_SECRET: z.string().default('change-this-in-production-' + Math.random().toString(36)),
  
  // Polling
  POLL_CRON: z.string().default('*/5 * * * *'),
  
  // API
  CORS_ORIGIN: z.string().default('http://localhost:3000'),
  RATE_LIMIT_MAX: z.coerce.number().default(100),
  RATE_LIMIT_WINDOW: z.coerce.number().default(60000),
  
  // Logging
  LOG_LEVEL: z.enum(['error', 'warn', 'info', 'debug']).default('info'),
});

// Parse and validate configuration
function loadConfig() {
  try {
    return ConfigSchema.parse(process.env);
  } catch (error) {
    console.error('❌ Configuration validation failed:');
    if (error instanceof z.ZodError) {
      error.errors.forEach((err) => {
        console.error(`  - ${err.path.join('.')}: ${err.message}`);
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
    BEST_DEALS: '/BestDeals',
    NEWEST_ITEMS: '/NewestItems',
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