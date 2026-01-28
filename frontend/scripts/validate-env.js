#!/usr/bin/env node

/**
 * Environment Variable Validation Script
 * Validates required environment variables before Next.js build
 */

const REQUIRED_VARS = {
  NEXT_PUBLIC_API_URL: {
    description: 'Public URL of the API server',
    example: 'https://skinbaron-tracker-api.example.com',
  },
};

const OPTIONAL_VARS = {
  NODE_ENV: { default: 'production', description: 'Environment mode' },
};

const errors = [];

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

// Display results
if (errors.length > 0) {
  console.error('\n' + '='.repeat(80));
  console.error('  🔧 ENVIRONMENT CONFIGURATION');
  console.error('='.repeat(80) + '\n');

  console.error('❌ MISSING REQUIRED BUILD ARGUMENTS:\n');
  errors.forEach(({ variable, description, example }) => {
    console.error(`  ${variable}`);
    console.error(`    → ${description}`);
    console.error(`    → Example: ${example}\n`);
  });

  console.error('='.repeat(80));
  console.error('  ⚠️  For Docker builds, provide in docker-compose.yml:');
  console.error('     build:');
  console.error('       args:');
  console.error('         NEXT_PUBLIC_API_URL: ${NEXT_PUBLIC_API_URL}');
  console.error('');
  console.error('  ⚠️  For deployment platforms (Coolify, Dokploy, etc.):');
  console.error('     Set as environment variable in platform settings');
  console.error('='.repeat(80) + '\n');

  process.exit(1);
}

console.log('✅ Environment validation passed');
