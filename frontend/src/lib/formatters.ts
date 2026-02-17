/**
 * Centralized formatting utilities
 * Prevents code duplication across components
 */

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
 * @param locale - Locale for formatting ('en' or 'fr'), defaults to 'en'
 * @returns Formatted string like "Just now • 11 Jan 2026, 23:37"
 */
export function formatRelativeDate(dateString: string, locale: 'en' | 'fr' = 'en'): string {
  // Ensure the date is treated as UTC if no timezone marker is present
  const utcDate = dateString.includes('Z') || dateString.includes('+') ? dateString : dateString.replace(' ', 'T') + 'Z';
  const date = new Date(utcDate);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();

  // Guard against negative time (clock skew between client and server)
  if (diffMs < 0) {
    const absoluteDate = date.toLocaleDateString(locale === 'fr' ? 'fr-FR' : 'en-GB', {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
    return `Just now • ${absoluteDate}`;
  }

  const diffMins = Math.floor(diffMs / 60000);
  const diffHours = Math.floor(diffMs / 3600000);
  const diffDays = Math.floor(diffMs / 86400000);

  let relative = "";
  
  if (locale === 'fr') {
    if (diffMins < 1) {
      relative = "À l'instant";
    } else if (diffMins < 60) {
      relative = `Il y a ${diffMins} minute${diffMins > 1 ? 's' : ''}`;
    } else if (diffHours < 24) {
      relative = `Il y a ${diffHours} heure${diffHours > 1 ? 's' : ''}`;
    } else if (diffDays < 7) {
      relative = `Il y a ${diffDays} jour${diffDays > 1 ? 's' : ''}`;
    } else {
      relative = date.toLocaleDateString('fr-FR', {
        day: 'numeric',
        month: 'short',
        year: 'numeric',
      });
    }

    const fullDate = date.toLocaleString('fr-FR', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });

    return `${relative} • ${fullDate}`;
  } else {
    if (diffMins < 1) {
      relative = "Just now";
    } else if (diffMins < 60) {
      relative = `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`;
    } else if (diffHours < 24) {
      relative = `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`;
    } else if (diffDays < 7) {
      relative = `${diffDays} day${diffDays > 1 ? 's' : ''} ago`;
    } else {
      relative = date.toLocaleDateString('en-US', {
        day: 'numeric',
        month: 'short',
        year: 'numeric',
      });
    }

    const fullDate = date.toLocaleString('en-US', {
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });

    return `${relative} • ${fullDate}`;
  }
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
  return date.toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric' });
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
  
  return date.toLocaleString('en-GB', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
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
    const data = JSON.parse(eventDataJson) as Record<string, unknown>;

    switch (eventType) {
      case "login_success": {
        const method = String(data['method'] || '');
        if (method === '2fa') return 'Login with 2FA';
        if (method === 'passkey') return 'Login with passkey';
        if (method.startsWith('oauth_')) {
          const provider = method.replace('oauth_', '');
          const providerName = provider.charAt(0).toUpperCase() + provider.slice(1);
          return `Login with ${providerName}`;
        }
        return 'Login with password';
      }
      
      case "login_failed":
        if (data['reason'] === "unknown_email") return "Failed: unknown email";
        if (data['reason'] === "invalid_password") return "Failed: invalid password";
        if (data['reason'] === "invalid_2fa_code") return "Failed: invalid 2FA code";
        if (data['reason'] === "invalid_2fa_backup_code") return "Failed: invalid 2FA backup code";
        return `Failed: ${String(data['reason'])}`;
      
      case "2fa_enabled":
        return "Two-factor authentication enabled";
      
      case "2fa_disabled":
        return "Two-factor authentication disabled";
      
      case "2fa_recovery_code_used":
        return `Recovery code used (${String(data['remaining_codes'])} remaining)`;
      
      case "email_changed":
        return `New email: ${String(data['new_email'])}`;
      
      case "username_changed":
        return `New username: ${String(data['new_username'])}`;
      
      case "password_changed":
        return data['method'] === 'set_initial_password' ? 'Initial password set' : 'Password successfully changed';
      
      case "password_change_failed":
        if (data['reason'] === "invalid_current_password") return "Failed: invalid current password";
        if (data['reason'] === "same_password") return "Failed: same password";
        return `Failed: ${String(data['reason'])}`;
      
      case "oauth_register": {
        const provider = String(data['provider'] || 'unknown');
        const providerName = provider.charAt(0).toUpperCase() + provider.slice(1);
        return `Registered via ${providerName}`;
      }
      
      case "oauth_linked": {
        const provider = String(data['provider'] || 'unknown');
        const providerName = provider.charAt(0).toUpperCase() + provider.slice(1);
        return `${providerName} account linked`;
      }
      
      case "oauth_unlinked": {
        const provider = String(data['provider'] || 'unknown');
        const providerName = provider.charAt(0).toUpperCase() + provider.slice(1);
        return `${providerName} account unlinked`;
      }
      
      case "user_approved":
        return `Approved by ${String(data['admin_username']) || `admin #${String(data['approved_by_admin_id'])}`}`;
      
      case "user_promoted":
        return `Promoted to admin by ${String(data['admin_username']) || `#${String(data['admin_id'])}`}`;
      
      case "user_demoted":
        return `Demoted by ${String(data['admin_username']) || `admin #${String(data['admin_id'])}`}`;
      
      case "passkey_registered": {
        const pkName = String(data['name'] || 'Passkey');
        const pkType = data['device_type'] === 'singleDevice' ? ' (hardware key)' : data['device_type'] === 'multiDevice' ? ' (synced)' : '';
        return `Passkey "${pkName}" registered${pkType}`;
      }
      
      case "passkey_deleted":
        return `Passkey removed`;
      
      case "avatar_uploaded":
        return "Custom avatar uploaded";
      
      case "avatar_removed":
        return data['removed_by_admin'] ? "Avatar removed by admin" : "Custom avatar removed";
      
      case "gravatar_toggled":
        return data['use_gravatar'] ? "Gravatar fallback enabled" : "Gravatar fallback disabled";
      
      case "account_frozen":
        return data['reason'] ? `Account frozen: ${String(data['reason'])}` : "Account frozen by admin";
      
      case "account_unfrozen":
        return "Account unfrozen by admin";
      
      case "account_banned":
        return data['reason'] 
          ? `Account banned: ${String(data['reason'])}${data['email_banned'] ? ' (email also banned)' : ''}`
          : `Account banned by admin${data['email_banned'] ? ' (email also banned)' : ''}`;
      
      case "account_unbanned":
        return "Account unbanned by admin";
      
      case "username_changed":
        return data['changed_by_admin']
          ? `Username changed by admin: "${String(data['old_username'])}" → "${String(data['new_username'])}"`
          : `New username: ${String(data['new_username'])}`;
      
      case "user_deleted":
        return "";
      
      case "logout":
        return data['reason'] === "user_logout" ? "User logout" : "Logged out";
      
      default:
        return eventDataJson;
    }
  } catch {
    return eventDataJson;
  }
}
