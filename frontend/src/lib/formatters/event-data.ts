import { capitalize, parseSessionDevice } from './common'

export function formatEventData(eventType: string, eventDataJson: string | null): string {
  if (eventType === 'data_export') return 'Personal data exported (GDPR)'
  if (!eventDataJson) return ''

  try {
    const raw = JSON.parse(eventDataJson) as Record<string, unknown>
    const s = (key: string, fallback = ''): string => {
      const v = raw[key]
      return typeof v === 'string' ? v : (typeof v === 'number' ? String(v) : fallback)
    }

    switch (eventType) {
      case 'login_success': {
        const method = s('method')
        if (method === '2fa') return 'Login with 2FA'
        if (method === 'passkey') return 'Login with passkey'
        if (method.startsWith('oauth_')) {
          const provider = method.replace('oauth_', '')
          return `Login with ${capitalize(provider)}`
        }
        return 'Login with password'
      }

      case 'login_failed':
        if (raw['reason'] === 'unknown_email') return 'Failed: unknown email'
        if (raw['reason'] === 'invalid_password') return 'Failed: invalid password'
        if (raw['reason'] === 'invalid_2fa_code') return 'Failed: invalid 2FA code'
        if (raw['reason'] === 'invalid_2fa_backup_code') return 'Failed: invalid 2FA backup code'
        if (raw['reason'] === 'account_restricted') return 'Failed: account restricted'
        return `Failed: ${s('reason')}`

      case '2fa_enabled':
        return 'Two-factor authentication enabled'

      case '2fa_disabled':
        return 'Two-factor authentication disabled'

      case '2fa_recovery_code_used':
        return `Recovery code used (${s('remaining_codes')} remaining)`

      case 'email_changed':
        return `New email: ${s('new_email')}`

      case 'username_changed':
        return raw['changed_by_admin']
          ? `Username changed by ${s('admin_username', 'admin')}: "${s('old_username')}" → "${s('new_username')}"`
          : `New username: ${s('new_username')}`

      case 'password_changed':
        return raw['method'] === 'set_initial_password' ? 'Initial password set' : 'Password successfully changed'

      case 'password_change_failed':
        if (raw['reason'] === 'invalid_current_password') return 'Failed: invalid current password'
        if (raw['reason'] === 'same_password') return 'Failed: same password'
        return `Failed: ${s('reason')}`

      case 'oauth_register':
        return `Registered via ${capitalize(s('provider', 'unknown'))}`

      case 'oauth_linked':
        return `${capitalize(s('provider', 'unknown'))} account linked`

      case 'oauth_unlinked':
        return `${capitalize(s('provider', 'unknown'))} account unlinked`

      case 'user_approved':
        return `Approved by ${s('admin_username') || `admin #${s('approved_by_admin_id')}`}`

      case 'user_promoted':
        return `Promoted to admin by ${s('admin_username') || `#${s('admin_id')}`}`

      case 'user_demoted':
        return `Demoted by ${s('admin_username') || `admin #${s('admin_id')}`}`

      case 'passkey_registered': {
        const pkName = s('name', 'Passkey')
        const pkType = raw['device_type'] === 'singleDevice'
          ? ' (hardware key)'
          : raw['device_type'] === 'multiDevice'
            ? ' (synced)'
            : ''
        return `Passkey "${pkName}" registered${pkType}`
      }

      case 'passkey_deleted':
        return 'Passkey removed'

      case 'avatar_uploaded':
        return 'Custom avatar uploaded'

      case 'avatar_removed':
        return raw['removed_by_admin']
          ? `Avatar removed by ${s('admin_username', 'admin')}`
          : 'Custom avatar removed'

      case 'gravatar_toggled':
        return raw['use_gravatar'] ? 'Gravatar fallback enabled' : 'Gravatar fallback disabled'

      case 'account_restricted': {
        const adminName = raw['admin_username'] ? `by ${s('admin_username')}` : 'by admin'
        const rType = s('restriction_type')
        const reason = raw['reason'] ? `: ${s('reason')}` : ''
        if (rType === 'permanent') return `Account permanently restricted ${adminName}${reason}`
        const duration = raw['duration_hours'] ? ` for ${s('duration_hours')}h` : ''
        return `Account temporarily restricted${duration} ${adminName}${reason}`
      }

      case 'account_unrestricted': {
        const adminName = raw['admin_username'] ? `by ${s('admin_username')}` : 'by admin'
        const reason = raw['reason'] ? `: ${s('reason')}` : ''
        return `Account unrestricted ${adminName}${reason}`
      }

      case 'sanction_deleted': {
        const adminName = raw['deleted_by_admin_username'] ? `by ${s('deleted_by_admin_username')}` : 'by admin'
        const reason = raw['reason'] ? `: ${s('reason')}` : ''
        const action = s('action')
        const rType = s('restriction_type')
        if (action === 'restrict') {
          const typeLabel = rType === 'permanent' ? 'Permanent' : 'Temporary'
          return `${typeLabel} restriction removed ${adminName}${reason}`
        }
        return `Unrestriction removed ${adminName}${reason}`
      }

      case 'user_deleted':
        return ''

      case '2fa_reset_by_admin':
        return `Two-factor authentication reset ${raw['admin_username'] ? `by ${s('admin_username')}` : 'by admin'}`

      case 'passkeys_reset_by_admin':
        return `All passkeys removed ${raw['admin_username'] ? `by ${s('admin_username')}` : 'by admin'}`

      case 'sessions_reset_by_admin':
        return `All sessions revoked ${raw['admin_username'] ? `by ${s('admin_username')}` : 'by admin'}`

      case 'sessions_revoked':
        return 'All sessions revoked by user'

      case 'session_revoked': {
        const sessionUa = raw['session_user_agent'] as string | undefined
        if (sessionUa) {
          return `Session revoked: ${parseSessionDevice(sessionUa)}`
        }
        return 'Session revoked'
      }

      case 'other_sessions_revoked':
        return 'All other sessions revoked'

      case 'logout':
        return raw['reason'] === 'user_logout' ? 'User logout' : 'Logged out'

      default:
        return eventDataJson
    }
  } catch {
    return eventDataJson
  }
}
