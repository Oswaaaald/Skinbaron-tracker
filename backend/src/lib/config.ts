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
  SB_API_KEY: z.string().min(1, 'SkinBaron API key is required'),
  
  // Discord
  DISCORD_WEBHOOK: z.string().url('Valid Discord webhook URL is required'),
  
  // Database
  SQLITE_PATH: z.string().default('./data/alerts.db'),
  
  // Polling
  POLL_CRON: z.string().default('*/2 * * * *'),
  ENABLE_BEST_DEALS: z.coerce.boolean().default(true),
  ENABLE_NEWEST_ITEMS: z.coerce.boolean().default(true),
  
  // Feed filters
  FEEDS_MAX_PRICE: z.coerce.number().default(200),
  FEEDS_MAX_WEAR: z.coerce.number().min(0).max(1).default(0.20),
  
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