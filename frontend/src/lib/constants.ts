/**
 * Shared constants for the frontend application
 * Centralizes magic numbers and configuration values
 */

// ==================== QUERY CONFIGURATION ====================

/** Time in ms before cached data is considered stale */
export const QUERY_STALE_TIME = 15_000; // 15 seconds

/** Default polling interval for real-time data */
export const POLL_INTERVAL = 10_000; // 10 seconds

/** Polling interval when page is in background */
export const BACKGROUND_POLL_INTERVAL = 30_000; // 30 seconds

// ==================== PAGINATION ====================

/** Number of alerts per page in the alerts grid */
export const ALERTS_PAGE_SIZE = 12;

/** Number of rules per page in the rules table */
export const RULES_PAGE_SIZE = 10;

/** Number of audit logs per page */
export const AUDIT_LOGS_PAGE_SIZE = 20;

// ==================== UI CONSTANTS ====================

/** Debounce delay for search inputs (ms) */
export const SEARCH_DEBOUNCE_MS = 300;

/** Toast notification duration (ms) */
export const TOAST_DURATION = 5_000;

/** Animation duration for transitions (ms) */
export const ANIMATION_DURATION = 200;

// ==================== LIMITS ====================

/** Maximum number of rules per user */
export const MAX_RULES_PER_USER = 50;

/** Maximum number of webhooks per user */
export const MAX_WEBHOOKS_PER_USER = 10;

/** Maximum length for webhook names */
export const MAX_WEBHOOK_NAME_LENGTH = 50;

/** Maximum length for rule search items */
export const MAX_SEARCH_ITEM_LENGTH = 100;

// ==================== VALIDATION ====================

/** Minimum password length */
export const MIN_PASSWORD_LENGTH = 8;

/** Minimum username length */
export const MIN_USERNAME_LENGTH = 3;

/** Maximum username length */
export const MAX_USERNAME_LENGTH = 20;

// ==================== API ====================

/** Default request timeout (ms) */
export const API_TIMEOUT = 30_000;

/** Number of retries for failed requests */
export const API_RETRY_COUNT = 3;

// ==================== QUERY KEYS ====================

/** 
 * Centralized query keys for React Query cache management 
 * Use these constants to ensure consistent cache invalidation
 */
export const QUERY_KEYS = {
  // Core data
  ALERTS: 'alerts',
  RULES: 'rules',
  WEBHOOKS: 'webhooks',
  
  // User related
  USER: 'user',
  USER_STATS: 'user-stats',
  USER_PROFILE: 'user-profile',
  USER_AUDIT_LOGS: 'user-audit-logs',
  
  // 2FA
  TWO_FA_STATUS: '2fa-status',
  TWO_FA_SETUP: '2fa-setup',
  
  // System
  SYSTEM_STATUS: 'system-status',
  ALERT_STATS: 'alert-stats',
  
  // Admin - use compound keys for sub-resources
  ADMIN: 'admin',
  ADMIN_USERS: 'admin-users',
  ADMIN_PENDING: 'admin-pending',
  ADMIN_STATS: 'admin-stats',
  ADMIN_AUDIT_LOGS: 'admin-audit-logs',
  SEARCH_USERS: 'search-users',
  
  // Legacy (for sync)
  SYNC_STATS: 'sync-stats',
} as const;

/** Type-safe query key builder for compound keys */
export const buildQueryKey = {
  admin: {
    users: () => [QUERY_KEYS.ADMIN_USERS] as const,
    pending: () => [QUERY_KEYS.ADMIN_PENDING] as const,
    stats: () => [QUERY_KEYS.ADMIN_STATS] as const,
  },
  user: {
    stats: () => [QUERY_KEYS.USER_STATS] as const,
    profile: () => [QUERY_KEYS.USER_PROFILE] as const,
  },
} as const;
