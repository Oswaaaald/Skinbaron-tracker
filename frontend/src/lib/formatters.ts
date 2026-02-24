/**
 * Centralized formatting utilities
 * Prevents code duplication across components
 * 
 * Convention:
 *   - Locale:   'en-GB' everywhere (DD/MM/YYYY, 24h)
 *   - Timezone: omitted → browser's local TZ (what the user expects)
 *   - DB stores: Europe/Brussels (UTC+1 / +2 DST), but display
 *                converts to the viewer's clock automatically via Date.
 */

// ─── Shared locale constant ─────────────────────────────────────────────────
const LOCALE = 'en-GB' as const;

/** Capitalize first letter of a string. */
export function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

/** Parse a user-agent string into a human-readable device description (e.g. "Chrome on macOS"). */
function parseSessionDevice(ua: string): string {
  let browser = 'Unknown Browser';
  if (ua.includes('Firefox/')) browser = 'Firefox';
  else if (ua.includes('Edg/')) browser = 'Edge';
  else if (ua.includes('OPR/') || ua.includes('Opera/')) browser = 'Opera';
  else if (ua.includes('Chrome/') && !ua.includes('Edg/')) browser = 'Chrome';
  else if (ua.includes('Safari/') && !ua.includes('Chrome/')) browser = 'Safari';

  let os = '';
  if (ua.includes('Windows')) os = 'Windows';
  else if (ua.includes('Mac OS X')) os = 'macOS';
  else if (ua.includes('Android')) os = 'Android';
  else if (ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS';
  else if (ua.includes('Linux')) os = 'Linux';
  else if (ua.includes('CrOS')) os = 'ChromeOS';

  return os ? `${browser} on ${os}` : browser;
}

/**
 * Format a price in EUR currency
 */
export function formatPrice(price: number): string {
  return new Intl.NumberFormat('de-DE', {
    style: 'currency',
    currency: 'EUR',
    minimumFractionDigits: 2,
  }).format(price);
}

/**
 * Format a date with relative time and full date
 * 
 * @param dateString - ISO date string from API
 * @returns Formatted string like "Just now • 11 Jan 2026, 23:37"
 */
export function formatRelativeDate(dateString: string): string {
  // Ensure the date is treated as UTC if no timezone marker is present
  const utcDate = dateString.includes('Z') || dateString.includes('+') ? dateString : dateString.replace(' ', 'T') + 'Z';
  const date = new Date(utcDate);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();

  // Guard against negative time (clock skew between client and server)
  if (diffMs < 0) {
    const absoluteDate = date.toLocaleDateString(LOCALE, {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    });
    return `Just now • ${absoluteDate}`;
  }

  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  let relative = "";

  if (diffMins < 1) {
    relative = "Just now";
  } else if (diffMins < 60) {
    relative = `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`;
  } else if (diffHours < 24) {
    relative = `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
  } else if (diffDays < 7) {
    relative = `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
  } else {
    relative = date.toLocaleDateString(LOCALE, {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
    });
  }

  const fullDate = date.toLocaleString(LOCALE, {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });

  return `${relative} • ${fullDate}`;
}

/**
 * Format a date with short relative time (for compact displays)
 * 
 * @param dateString - Date string from API
 * @returns Short formatted string like "Just now", "5m ago", "2h ago", "11/01/2026"
 */
export function formatShortDate(dateString?: string | null): string {
  if (!dateString) return 'N/A';
  
  // Ensure the date is treated as UTC if no timezone marker is present
  const utcDate = dateString.includes('Z') || dateString.includes('+') 
    ? dateString 
    : dateString.replace(' ', 'T') + 'Z';
  const date = new Date(utcDate);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`;
  return date.toLocaleDateString(LOCALE, { day: '2-digit', month: '2-digit', year: 'numeric' });
}

/**
 * Format a date/time for system displays (no relative time)
 * 
 * @param dateString - Date string or Date object
 * @returns Formatted string like "11/01/2026, 23:37"
 */
export function formatSystemDate(dateString?: Date | string | null): string {
  if (!dateString) return 'Never';
  
  // Handle Date objects vs strings
  let date: Date;
  if (dateString instanceof Date) {
    date = dateString;
  } else {
    // Ensure the date is treated as UTC if no timezone marker is present
    const utcDate = dateString.includes('Z') || dateString.includes('+') 
      ? dateString 
      : dateString.replace(' ', 'T') + 'Z';
    date = new Date(utcDate);
  }
  
  return date.toLocaleString(LOCALE, {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
}

/**
 * Format a date+time for detail views (e.g. admin user detail, passkeys)
 * 
 * @param dateString - Date string from API
 * @returns Formatted string like "24/02/2026, 14:37" or "—" if null
 */
export function formatDateTime(dateString?: string | null): string {
  if (!dateString) return '—';
  
  const utcDate = dateString.includes('Z') || dateString.includes('+')
    ? dateString
    : dateString.replace(' ', 'T') + 'Z';
  const date = new Date(utcDate);
  
  return date.toLocaleString(LOCALE, {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
}

/**
 * Format a date only (no time) for tables and compact views
 * 
 * @param dateString - Date string from API
 * @returns Formatted string like "24/02/2026" or "—" if null
 */
export function formatDateOnly(dateString?: string | null): string {
  if (!dateString) return '—';
  
  const utcDate = dateString.includes('Z') || dateString.includes('+')
    ? dateString
    : dateString.replace(' ', 'T') + 'Z';
  const date = new Date(utcDate);
  
  return date.toLocaleDateString(LOCALE, {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
  });
}

/**
 * Format uptime duration from seconds
 * 
 * @param uptimeSeconds - Uptime in seconds
 * @returns Formatted string like "12h 34m"
 */
export function formatUptime(uptimeSeconds?: number): string {
  if (!uptimeSeconds) return 'N/A';
  const hours = Math.floor(uptimeSeconds / 3600);
  const minutes = Math.floor((uptimeSeconds % 3600) / 60);
  return `${hours}h ${minutes}m`;
}

/**
 * Format audit log event data into human-readable text
 * 
 * @param eventType - The type of event (login_success, 2fa_enabled, etc.)
 * @param eventDataJson - JSON string of event-specific data
 * @returns Human-readable description of the event
 */
export function formatEventData(eventType: string, eventDataJson: string | null): string {
  // Events with static messages that don't need event_data
  if (eventType === "data_export") return "Personal data exported";

  if (!eventDataJson) return "";

  try {
    const raw = JSON.parse(eventDataJson) as Record<string, unknown>;
    // Helper to safely extract string values from parsed JSON
    const s = (key: string, fallback = ''): string => {
      const v = raw[key];
      return typeof v === 'string' ? v : (typeof v === 'number' ? String(v) : fallback);
    };

    switch (eventType) {
      case "login_success": {
        const method = s('method');
        if (method === '2fa') return 'Login with 2FA';
        if (method === 'passkey') return 'Login with passkey';
        if (method.startsWith('oauth_')) {
          const provider = method.replace('oauth_', '');
          const providerName = capitalize(provider);
          return `Login with ${providerName}`;
        }
        return 'Login with password';
      }
      
      case "login_failed":
        if (raw['reason'] === "unknown_email") return "Failed: unknown email";
        if (raw['reason'] === "invalid_password") return "Failed: invalid password";
        if (raw['reason'] === "invalid_2fa_code") return "Failed: invalid 2FA code";
        if (raw['reason'] === "invalid_2fa_backup_code") return "Failed: invalid 2FA backup code";
        if (raw['reason'] === "account_restricted") return "Failed: account restricted";
        return `Failed: ${s('reason')}`;
      
      case "2fa_enabled":
        return "Two-factor authentication enabled";
      
      case "2fa_disabled":
        return "Two-factor authentication disabled";
      
      case "2fa_recovery_code_used":
        return `Recovery code used (${s('remaining_codes')} remaining)`;
      
      case "email_changed":
        return `New email: ${s('new_email')}`;
      
      case "username_changed":
        return raw['changed_by_admin']
          ? `Username changed by ${s('admin_username', 'admin')}: "${s('old_username')}" → "${s('new_username')}"`
          : `New username: ${s('new_username')}`;
      
      case "password_changed":
        return raw['method'] === 'set_initial_password' ? 'Initial password set' : 'Password successfully changed';
      
      case "password_change_failed":
        if (raw['reason'] === "invalid_current_password") return "Failed: invalid current password";
        if (raw['reason'] === "same_password") return "Failed: same password";
        return `Failed: ${s('reason')}`;
      
      case "oauth_register": {
        const provider = s('provider', 'unknown');
        const providerName = capitalize(provider);
        return `Registered via ${providerName}`;
      }
      
      case "oauth_linked": {
        const provider = s('provider', 'unknown');
        const providerName = capitalize(provider);
        return `${providerName} account linked`;
      }
      
      case "oauth_unlinked": {
        const provider = s('provider', 'unknown');
        const providerName = capitalize(provider);
        return `${providerName} account unlinked`;
      }
      
      case "user_approved":
        return `Approved by ${s('admin_username') || `admin #${s('approved_by_admin_id')}`}`;
      
      case "user_promoted":
        return `Promoted to admin by ${s('admin_username') || `#${s('admin_id')}`}`;
      
      case "user_demoted":
        return `Demoted by ${s('admin_username') || `admin #${s('admin_id')}`}`;
      
      case "passkey_registered": {
        const pkName = s('name', 'Passkey');
        const pkType = raw['device_type'] === 'singleDevice' ? ' (hardware key)' : raw['device_type'] === 'multiDevice' ? ' (synced)' : '';
        return `Passkey "${pkName}" registered${pkType}`;
      }
      
      case "passkey_deleted":
        return `Passkey removed`;

      case "data_export":
        return "Personal data exported (GDPR)";
      
      case "avatar_uploaded":
        return "Custom avatar uploaded";
      
      case "avatar_removed":
        return raw['removed_by_admin']
          ? `Avatar removed by ${s('admin_username', 'admin')}`
          : "Custom avatar removed";
      
      case "gravatar_toggled":
        return raw['use_gravatar'] ? "Gravatar fallback enabled" : "Gravatar fallback disabled";
      
      case "account_restricted": {
        const adminName = raw['admin_username'] ? `by ${s('admin_username')}` : 'by admin';
        const rType = s('restriction_type');
        const reason = raw['reason'] ? `: ${s('reason')}` : '';
        if (rType === 'permanent') {
          return `Account permanently restricted ${adminName}${reason}`;
        }
        const duration = raw['duration_hours'] ? ` for ${s('duration_hours')}h` : '';
        return `Account temporarily restricted${duration} ${adminName}${reason}`;
      }
      
      case "account_unrestricted": {
        const adminName = raw['admin_username'] ? `by ${s('admin_username')}` : 'by admin';
        const reason = raw['reason'] ? `: ${s('reason')}` : '';
        return `Account unrestricted ${adminName}${reason}`;
      }
      
      case "sanction_deleted": {
        const adminName = raw['deleted_by_admin_username'] ? `by ${s('deleted_by_admin_username')}` : 'by admin';
        const reason = raw['reason'] ? `: ${s('reason')}` : '';
        const action = s('action');
        const rType = s('restriction_type');
        if (action === 'restrict') {
          const typeLabel = rType === 'permanent' ? 'Permanent' : 'Temporary';
          return `${typeLabel} restriction removed ${adminName}${reason}`;
        }
        return `Unrestriction removed ${adminName}${reason}`;
      }
      
      case "user_deleted":
        return "";
      
      case "2fa_reset_by_admin": {
        const adminName = raw['admin_username'] ? `by ${s('admin_username')}` : 'by admin';
        return `Two-factor authentication reset ${adminName}`;
      }

      case "passkeys_reset_by_admin": {
        const adminName = raw['admin_username'] ? `by ${s('admin_username')}` : 'by admin';
        return `All passkeys removed ${adminName}`;
      }

      case "sessions_reset_by_admin": {
        const adminName = raw['admin_username'] ? `by ${s('admin_username')}` : 'by admin';
        return `All sessions revoked ${adminName}`;
      }

      case "sessions_revoked":
        return "All sessions revoked by user";

      case "session_revoked": {
        const sessionUa = raw['session_user_agent'] as string | undefined;
        if (sessionUa) {
          const parsed = parseSessionDevice(sessionUa);
          return `Session revoked: ${parsed}`;
        }
        return "Session revoked";
      }

      case "other_sessions_revoked":
        return "All other sessions revoked";

      case "logout":
        return raw['reason'] === "user_logout" ? "User logout" : "Logged out";
      
      default:
        return eventDataJson;
    }
  } catch {
    return eventDataJson;
  }
}
