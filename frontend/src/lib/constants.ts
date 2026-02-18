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

/** Number of users per page in admin panel */
export const ADMIN_USERS_PAGE_SIZE = 20;

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
  Link2,
  Unlink,
  UserPlus,
  Fingerprint,
  Camera,
  Ban,
  Trash2,
  RotateCcw,
  LogOut,
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
  oauth_register: { icon: UserPlus, label: "OAuth Registration", variant: "default" },
  oauth_linked: { icon: Link2, label: "Account Linked", variant: "default" },
  oauth_unlinked: { icon: Unlink, label: "Account Unlinked", variant: "secondary" },
  passkey_registered: { icon: Fingerprint, label: "Passkey Registered", variant: "default" },
  passkey_deleted: { icon: Fingerprint, label: "Passkey Deleted", variant: "secondary" },
  avatar_uploaded: { icon: Camera, label: "Avatar Uploaded", variant: "default" },
  avatar_removed: { icon: Camera, label: "Avatar Removed", variant: "secondary" },
  gravatar_toggled: { icon: Camera, label: "Gravatar Setting Changed", variant: "outline" },
  account_restricted: { icon: Ban, label: "Account Restricted", variant: "destructive" },
  account_unrestricted: { icon: Ban, label: "Account Unrestricted", variant: "default" },
  sanction_deleted: { icon: Trash2, label: "Sanction Deleted", variant: "secondary" },
  "2fa_reset_by_admin": { icon: RotateCcw, label: "2FA Reset by Admin", variant: "destructive" },
  passkeys_reset_by_admin: { icon: RotateCcw, label: "Passkeys Reset by Admin", variant: "destructive" },
  sessions_reset_by_admin: { icon: LogOut, label: "Sessions Revoked by Admin", variant: "destructive" },
} as const;

// ==================== ADMIN ACTION LOG CONFIGURATION ====================

/** Action type configuration for admin logs display */
export const ADMIN_ACTION_CONFIG: Record<string, {
  icon: LucideIcon;
  label: string;
  variant: "default" | "secondary" | "destructive" | "outline";
}> = {
  approve_user: { icon: ShieldCheck, label: "User Approved", variant: "default" },
  reject_user: { icon: ShieldAlert, label: "User Rejected", variant: "destructive" },
  delete_user: { icon: Trash2, label: "User Deleted", variant: "destructive" },
  grant_admin: { icon: Shield, label: "Admin Granted", variant: "default" },
  revoke_admin: { icon: ShieldOff, label: "Admin Revoked", variant: "secondary" },
  restrict_user: { icon: Ban, label: "User Restricted", variant: "destructive" },
  unrestrict_user: { icon: Ban, label: "User Unrestricted", variant: "default" },
  delete_sanction: { icon: Trash2, label: "Sanction Deleted", variant: "secondary" },
  change_username: { icon: User, label: "Username Changed", variant: "outline" },
  admin_avatar_removed: { icon: Camera, label: "Avatar Removed", variant: "secondary" },
  reset_2fa: { icon: RotateCcw, label: "2FA Reset", variant: "destructive" },
  reset_passkeys: { icon: RotateCcw, label: "Passkeys Reset", variant: "destructive" },
  reset_sessions: { icon: LogOut, label: "Sessions Revoked", variant: "destructive" },
  force_scheduler: { icon: AlertCircle, label: "Scheduler Forced", variant: "outline" },
  test_sentry: { icon: AlertCircle, label: "Sentry Tested", variant: "outline" },
  account_self_deleted: { icon: ShieldAlert, label: "Self-Deleted Account", variant: "destructive" },
} as const;

/** Action type options for admin logs filter dropdown */
export const ADMIN_ACTION_TYPES = [
  { value: "all", label: "All Actions" },
  { value: "approve_user", label: "User Approved" },
  { value: "reject_user", label: "User Rejected" },
  { value: "delete_user", label: "User Deleted" },
  { value: "grant_admin", label: "Admin Granted" },
  { value: "revoke_admin", label: "Admin Revoked" },
  { value: "restrict_user", label: "User Restricted" },
  { value: "unrestrict_user", label: "User Unrestricted" },
  { value: "delete_sanction", label: "Sanction Deleted" },
  { value: "change_username", label: "Username Changed" },
  { value: "admin_avatar_removed", label: "Avatar Removed" },
  { value: "reset_2fa", label: "2FA Reset" },
  { value: "reset_passkeys", label: "Passkeys Reset" },
  { value: "reset_sessions", label: "Sessions Revoked" },
  { value: "force_scheduler", label: "Scheduler Forced" },
  { value: "test_sentry", label: "Sentry Tested" },
  { value: "account_self_deleted", label: "Account Self-Deleted" },
] as const;

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
  { value: "oauth_register", label: "OAuth Registration" },
  { value: "oauth_linked", label: "Account Linked" },
  { value: "oauth_unlinked", label: "Account Unlinked" },
  { value: "passkey_registered", label: "Passkey Registered" },
  { value: "passkey_deleted", label: "Passkey Deleted" },
  { value: "avatar_uploaded", label: "Avatar Uploaded" },
  { value: "avatar_removed", label: "Avatar Removed" },
  { value: "gravatar_toggled", label: "Gravatar Setting Changed" },
  { value: "account_restricted", label: "Account Restricted" },
  { value: "account_unrestricted", label: "Account Unrestricted" },
  { value: "sanction_deleted", label: "Sanction Deleted" },
  { value: "2fa_reset_by_admin", label: "2FA Reset by Admin" },
  { value: "passkeys_reset_by_admin", label: "Passkeys Reset by Admin" },
  { value: "sessions_reset_by_admin", label: "Sessions Revoked by Admin" },
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
  PASSKEYS: 'passkeys',
  
  // System
  SYSTEM_STATUS: 'system-status',
  ALERT_STATS: 'alert-stats',
  
  // Admin - use compound keys for sub-resources
  ADMIN: 'admin',
  ADMIN_USERS: 'admin-users',
  ADMIN_PENDING: 'admin-pending',
  ADMIN_STATS: 'admin-stats',
  ADMIN_AUDIT_LOGS: 'admin-audit-logs',
  ADMIN_LOGS: 'admin-logs',
  SEARCH_USERS: 'search-users',
  
} as const;
