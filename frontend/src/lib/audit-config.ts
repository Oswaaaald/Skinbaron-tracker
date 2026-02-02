/**
 * Audit log display configuration
 * Separated from constants.ts because it contains React components (icons)
 */

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
} as const;

/** Event type options for filter dropdowns (pure data, no components) */
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
] as const;
