#!/usr/bin/env node

/**
 * Migration script to apply database schema updates
 * This script applies the multi-user system migrations to the production database
 */

const path = require('path');
const { execSync } = require('child_process');

console.log('🔧 Starting database migration process...');
console.log('📍 Current directory:', process.cwd());

// Change to backend directory
process.chdir('/home/oswaaaald/skinbaron-alerts-sbapi/backend');

console.log('📦 Building TypeScript files...');
try {
  execSync('npx tsc', { stdio: 'inherit' });
  console.log('✅ TypeScript compilation completed');
} catch (error) {
  console.error('❌ TypeScript compilation failed:', error.message);
  process.exit(1);
}

console.log('🚀 Running database migrations...');
try {
  // Import and run migrations
  const { DatabaseMigrations } = require('./dist/lib/migrations.js');
  const { appConfig } = require('./dist/lib/config.js');
  
  const dbPath = appConfig.SQLITE_PATH;
  
  console.log(`📂 Database path: ${dbPath}`);
  
  const migrations = new DatabaseMigrations(dbPath);
  migrations.runMigrations();
  migrations.close();
  
  console.log('🎉 Database migrations completed successfully!');
  
} catch (error) {
  console.error('❌ Migration failed:', error);
  process.exit(1);
}