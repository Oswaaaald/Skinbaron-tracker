#!/usr/bin/env node

/**
 * Environment Variable Validation Script
 * Validates required environment variables before application startup
 */

const REQUIRED_VARS = {
  JWT_SECRET: {
    description: 'Secret key for JWT token signing',
    example: 'your-super-secret-jwt-key-min-32-chars',
  },
  NEXT_PUBLIC_API_URL: {
    description: 'Public URL of the API server',
    example: 'https://skinbaron-tracker-api.example.com',
  },
  CORS_ORIGIN: {
    description: 'Allowed CORS origin (frontend URL)',
    example: 'https://skinbaron-tracker.example.com',
  },
};

const PRODUCTION_REQUIRED_VARS = {
  ENCRYPTION_KEY: {
    description: 'Encryption key for sensitive data (must differ from JWT_SECRET)',
    example: 'your-super-secret-encryption-key-min-32-chars',
  },
};

const OPTIONAL_VARS = {
  NODE_ENV: { default: 'development', description: 'Environment mode' },
  PORT: { default: '8080', description: 'Server port' },
  COOKIE_DOMAIN: { default: 'undefined', description: 'Cookie domain for authentication' },
  SB_API_KEY: { default: 'undefined', description: 'SkinBaron API key (required for price tracking)' },
  DATABASE_URL: { default: undefined, description: 'PostgreSQL connection URL' },
  APP_VERSION: { default: 'dev', description: 'Application version' },
  POLL_CRON: { default: '*/5 * * * *', description: 'Cron schedule for polling' },
  RATE_LIMIT_MAX: { default: '1000', description: 'Maximum requests per window' },
  RATE_LIMIT_WINDOW: { default: '60000', description: 'Rate limit window in ms' },
  LOG_LEVEL: { default: 'info', description: 'Logging level (error|warn|info|debug)' },
  AUDIT_LOG_RETENTION_DAYS: { default: '365', description: 'Days to retain audit logs' },
};

const errors = [];
const warnings = [];
const isProduction = process.env.NODE_ENV === 'production';

// Check required variables
for (const [key, config] of Object.entries(REQUIRED_VARS)) {
  if (!process.env[key]) {
    errors.push({
      variable: key,
      description: config.description,
      example: config.example,
    });
  }
}

// Check production-specific variables
if (isProduction) {
  for (const [key, config] of Object.entries(PRODUCTION_REQUIRED_VARS)) {
    if (!process.env[key]) {
      errors.push({
        variable: key,
        description: config.description,
        example: config.example,
      });
    }
  }

  // Validate ENCRYPTION_KEY differs from JWT_SECRET
  if (process.env.ENCRYPTION_KEY && process.env.ENCRYPTION_KEY === process.env.JWT_SECRET) {
    errors.push({
      variable: 'ENCRYPTION_KEY',
      description: 'Must differ from JWT_SECRET in production',
      example: 'Use a different secret key',
    });
  }
}

// Check optional but important variables
if (!process.env.SB_API_KEY) {
  warnings.push({
    variable: 'SB_API_KEY',
    description: 'SkinBaron API key not set - price tracking will not work',
  });
}

// Display results
if (errors.length > 0 || warnings.length > 0) {
  console.error('\n' + '='.repeat(80));
  console.error('  🔧 ENVIRONMENT CONFIGURATION');
  console.error('='.repeat(80) + '\n');

  if (errors.length > 0) {
    console.error('❌ MISSING REQUIRED VARIABLES:\n');
    errors.forEach(({ variable, description, example }) => {
      console.error(`  ${variable}`);
      console.error(`    → ${description}`);
      console.error(`    → Example: ${example}\n`);
    });

    console.error('='.repeat(80));
    console.error('  ⚠️  Please set the required environment variables in:');
    console.error('     - Deployment platform (Coolify, Dokploy, etc.)');
    console.error('     - .env file (for local development)');
    console.error('     - docker-compose.yml environment section');
    console.error('='.repeat(80) + '\n');

    process.exit(1);
  }

  if (warnings.length > 0) {
    console.warn('⚠️  OPTIONAL VARIABLES (with defaults):\n');
    warnings.forEach(({ variable, description }) => {
      console.warn(`  ${variable}`);
      console.warn(`    → ${description}\n`);
    });
    console.warn('='.repeat(80) + '\n');
  }
}

console.log('✅ Environment validation passed');
