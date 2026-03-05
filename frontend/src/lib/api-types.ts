// Types matching backend schemas
export interface Rule {
  id?: number;
  user_id?: number;
  search_item: string;
  min_price?: number;
  max_price?: number;
  min_wear?: number;
  max_wear?: number;
  stattrak_filter?: 'all' | 'only' | 'exclude';
  souvenir_filter?: 'all' | 'only' | 'exclude';
  sticker_filter?: 'all' | 'only' | 'exclude';
  webhook_ids: number[]; // Array of webhook IDs (optional)
  enabled?: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface CreateRuleData {
  search_item: string;
  min_price?: number;
  max_price?: number;
  min_wear?: number;
  max_wear?: number;
  stattrak_filter?: 'all' | 'only' | 'exclude';
  souvenir_filter?: 'all' | 'only' | 'exclude';
  sticker_filter?: 'all' | 'only' | 'exclude';
  webhook_ids: number[];
  enabled?: boolean;
}

export interface Alert {
  id?: number;
  rule_id: number;
  sale_id: string;
  item_name: string;
  price: number;
  wear_value?: number;
  stattrak: boolean;
  souvenir: boolean;
  has_stickers: boolean;
  skin_url: string;
  sent_at: string;
}

export interface Webhook {
  id?: number;
  user_id: number;
  name: string;
  webhook_url?: string; // Only present when decrypt=true
  webhook_type: 'discord';
  notification_style: 'compact' | 'detailed';
  is_active: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
  details?: unknown;
  requires2FA?: boolean; // For 2FA login flow
  status?: number;
  count?: number; // For batch operations that return count directly
}

export type UserProfile = {
  id: number;
  username: string;
  email: string;
  avatar_url?: string;
  is_admin?: boolean;
  is_super_admin?: boolean;
  use_gravatar?: boolean;
  has_password?: boolean;
};

export interface PaginatedResponse<T> extends ApiResponse<T[]> {
  pagination?: {
    limit: number;
    offset: number;
    count: number;
    total: number;
  };
}

export interface SystemStats {
  scheduler: {
    isRunning: boolean;
    lastRunTime: Date | null;
    nextRunTime: Date | null;
    totalRuns: number;
    totalAlerts: number;
  };
  health?: {
    status: string;
    timestamp: string;
    services: Record<string, string>;
    stats: {
      uptime: number;
      memory: NodeJS.MemoryUsage;
      version: string;
    };
  };
}

export interface AuditLog {
  id: number;
  user_id: number;
  username?: string; // Enriched by backend JOIN
  email?: string; // Enriched by backend JOIN
  event_type: string;
  event_data: string | null;
  ip_address: string | null;
  user_agent: string | null;
  created_at: string;
}

export interface OAuthAccount {
  id: number;
  provider: string;
  provider_email: string | null;
  created_at: string;
}

export interface PasskeyInfo {
  id: number;
  name: string;
  device_type: string;
  backed_up: boolean;
  transports: string[];
  created_at: string;
  last_used_at: string | null;
}

/** Passkey registration options from backend (WebAuthn PublicKeyCredentialCreationOptionsJSON) */
export interface PasskeyRegisterOptionsResponse {
  rp: { name: string; id?: string };
  user: { id: string; name: string; displayName: string };
  challenge: string;
  pubKeyCredParams: Array<{ type: string; alg: number }>;
  timeout?: number;
  excludeCredentials?: Array<{ id: string; type: string; transports?: string[] }>;
  authenticatorSelection?: Record<string, unknown>;
  attestation?: string;
  extensions?: Record<string, unknown>;
}

/** Passkey auth options from backend (WebAuthn PublicKeyCredentialRequestOptionsJSON + challengeKey) */
export interface PasskeyAuthOptionsResponse {
  challengeKey: string;
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: Array<{ id: string; type: string; transports?: string[] }>;
  userVerification?: string;
  extensions?: Record<string, unknown>;
}

export interface AdminUser {
  id: number;
  username: string;
  email: string;
  avatar_url: string | null;
  is_admin: boolean;
  is_super_admin: boolean;
  is_restricted: boolean;
  restriction_type: string | null;
  restriction_expires_at: string | null;
  created_at: string;
  stats: {
    rules_count: number;
    alerts_count: number;
    webhooks_count: number;
  };
}

export interface Sanction {
  id: number;
  admin_username: string;
  action: 'restrict' | 'unrestrict';
  restriction_type: 'temporary' | 'permanent' | null;
  reason: string | null;
  duration_hours: number | null;
  expires_at: string | null;
  created_at: string;
}

export interface AdminActionLog {
  id: number;
  admin_user_id: number;
  admin_username: string | null;
  action: string;
  target_user_id: number | null;
  target_username: string | null;
  details: string | null;
  created_at: string;
}

export interface AdminUserDetail {
  id: number;
  username: string;
  email: string;
  avatar_url: string | null;
  has_custom_avatar: boolean;
  is_admin: boolean;
  is_super_admin: boolean;
  is_approved: boolean;
  is_restricted: boolean;
  restriction_type: 'temporary' | 'permanent' | null;
  restriction_reason: string | null;
  restriction_expires_at: string | null;
  restricted_at: string | null;
  totp_enabled: boolean;
  tos_accepted_at: string | null;
  created_at: string;
  updated_at: string;
  oauth_accounts: {
    id: number;
    provider: string;
    provider_email: string | null;
    created_at: string;
  }[];
  passkeys: {
    id: number;
    name: string;
    device_type: string;
    backed_up: boolean;
    created_at: string;
    last_used_at: string | null;
  }[];
  stats: {
    rules_count: number;
    active_rules_count: number;
    webhooks_count: number;
    active_webhooks_count: number;
    alerts_count: number;
  };
  sanctions: Sanction[];
}
