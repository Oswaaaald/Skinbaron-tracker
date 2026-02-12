import type { Rule, Alert, User, UserWebhook, RuleRow, AlertRow, UserRow, WebhookRow } from '../schemas.js';
import { decryptData } from './encryption.js';

/**
 * Converts SQLite RuleRow to Rule model
 */
export function rowToRule(row: RuleRow): Rule {
  return {
    id: row.id,
    user_id: row.user_id,
    search_item: row.search_item,
    min_price: row.min_price ?? undefined,
    max_price: row.max_price ?? undefined,
    min_wear: row.min_wear ?? undefined,
    max_wear: row.max_wear ?? undefined,
    stattrak_filter: row.stattrak_filter as 'all' | 'only' | 'exclude',
    souvenir_filter: row.souvenir_filter as 'all' | 'only' | 'exclude',
    sticker_filter: row.sticker_filter as 'all' | 'only' | 'exclude',
    webhook_ids: row.webhook_ids ? (JSON.parse(row.webhook_ids) as number[]) : [],
    enabled: Boolean(row.enabled),
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

/**
 * Converts SQLite AlertRow to Alert model
 */
export function rowToAlert(row: AlertRow): Alert {
  return {
    id: row.id,
    rule_id: row.rule_id,
    sale_id: row.sale_id,
    item_name: row.item_name,
    price: row.price,
    wear_value: row.wear_value ?? undefined,
    stattrak: Boolean(row.stattrak),
    souvenir: Boolean(row.souvenir),
    skin_url: row.skin_url,
    alert_type: row.alert_type as 'match' | 'best_deal' | 'new_item',
    sent_at: row.sent_at,
  };
}

/**
 * Converts SQLite UserRow to User model
 * Optionally decrypts 2FA secrets
 */
export function rowToUser(row: UserRow, decrypt2FA: boolean = false): User {
  const user: User = {
    id: row.id,
    username: row.username,
    email: row.email,
    password_hash: row.password_hash,
    is_admin: row.is_admin,
    is_super_admin: row.is_super_admin,
    is_approved: row.is_approved,
    totp_secret_encrypted: row.totp_secret_encrypted,
    totp_enabled: row.totp_enabled,
    recovery_codes_encrypted: row.recovery_codes_encrypted,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };

  if (decrypt2FA) {
    if (row.totp_secret_encrypted) {
      user.totp_secret = decryptData(row.totp_secret_encrypted);
    }
    if (row.recovery_codes_encrypted) {
      user.recovery_codes = decryptData(row.recovery_codes_encrypted);
    }
  }

  return user;
}

/**
 * Converts SQLite WebhookRow to UserWebhook model
 * Optionally decrypts webhook URL
 */
export function rowToWebhook(row: WebhookRow, decryptUrl: boolean = false): UserWebhook {
  const webhook: UserWebhook = {
    id: row.id,
    user_id: row.user_id,
    name: row.name,
    webhook_url_encrypted: row.webhook_url_encrypted,
    webhook_type: row.webhook_type as 'discord' | 'slack' | 'teams' | 'generic',
    is_active: Boolean(row.is_active),
    created_at: row.created_at,
    updated_at: row.updated_at,
  };

  if (decryptUrl && row.webhook_url_encrypted) {
    try {
      webhook.webhook_url = decryptData(row.webhook_url_encrypted);
    } catch (error) {
      console.warn(`Failed to decrypt webhook URL for webhook ${row.id}:`, error instanceof Error ? error.message : 'Unknown error');
    }
  }

  return webhook;
}
