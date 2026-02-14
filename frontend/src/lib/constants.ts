/**
 * Shared constants for the frontend application
 * Centralizes magic numbers and configuration values
 */

// ==================== QUERY CONFIGURATION ====================

/** Default polling interval for real-time data (alerts, alert stats) */
export const POLL_INTERVAL = 10_000; // 10 seconds

/** Polling interval for slower-changing data (system status, user stats, admin data, logs) */
export const SLOW_POLL_INTERVAL = 30_000; // 30 seconds

// ==================== PAGINATION ====================

/** Number of alerts per page in the alerts grid */
export const ALERTS_PAGE_SIZE = 12;

// ==================== AUDIT LOG CONFIGURATION ====================

import { 
  Shield, 
  ShieldAlert, 
  LogIn, 
  Key, 
  Mail, 
  User,
  ShieldCheck,
  ShieldOff,
  AlertCircle,
  Download,
  type LucideIcon
} from "lucide-react"

/** Event type configuration for audit logs display */
export const AUDIT_EVENT_CONFIG: Record<string, {
  icon: LucideIcon;
  label: string;
  variant: "default" | "secondary" | "destructive" | "outline";
}> = {
  login_success: { icon: LogIn, label: "Login Success", variant: "default" },
  login_failed: { icon: ShieldAlert, label: "Login Failed", variant: "destructive" },
  logout: { icon: LogIn, label: "Logout", variant: "secondary" },
  "2fa_enabled": { icon: ShieldCheck, label: "2FA Enabled", variant: "default" },
  "2fa_disabled": { icon: ShieldOff, label: "2FA Disabled", variant: "secondary" },
  "2fa_recovery_code_used": { icon: Key, label: "Recovery Code Used", variant: "outline" },
  email_changed: { icon: Mail, label: "Email Changed", variant: "outline" },
  username_changed: { icon: User, label: "Username Changed", variant: "outline" },
  password_changed: { icon: Key, label: "Password Changed", variant: "default" },
  password_change_failed: { icon: AlertCircle, label: "Password Change Failed", variant: "destructive" },
  user_approved: { icon: ShieldCheck, label: "Account Approved", variant: "default" },
  user_promoted: { icon: Shield, label: "Promoted to Admin", variant: "default" },
  user_demoted: { icon: ShieldOff, label: "Admin Privileges Revoked", variant: "secondary" },
  user_deleted: { icon: ShieldAlert, label: "Account Deleted", variant: "destructive" },
  data_export: { icon: Download, label: "Data Export", variant: "outline" },
} as const;

/** Event type options for filter dropdowns */
export const AUDIT_EVENT_TYPES = [
  { value: "all", label: "All Events" },
  { value: "login_success", label: "Login Success" },
  { value: "login_failed", label: "Login Failed" },
  { value: "logout", label: "Logout" },
  { value: "2fa_enabled", label: "2FA Enabled" },
  { value: "2fa_disabled", label: "2FA Disabled" },
  { value: "2fa_recovery_code_used", label: "2FA Recovery Used" },
  { value: "email_changed", label: "Email Changed" },
  { value: "username_changed", label: "Username Changed" },
  { value: "password_changed", label: "Password Changed" },
  { value: "password_change_failed", label: "Password Change Failed" },
  { value: "user_approved", label: "User Approved" },
  { value: "user_promoted", label: "User Promoted" },
  { value: "user_demoted", label: "User Demoted" },
  { value: "user_deleted", label: "User Deleted" },
  { value: "data_export", label: "Data Export" },
] as const;

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
  
} as const;
