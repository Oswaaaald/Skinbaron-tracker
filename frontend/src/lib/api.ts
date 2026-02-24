// API Client for SkinBaron Tracker Backend

import { logger } from './logger';

const API_BASE_URL = process.env['NEXT_PUBLIC_API_URL'] || '';

export class ApiError extends Error {
  status: number;
  body: unknown;
  url: string;
  method: string;

  constructor(message: string, status: number, url: string, method: string, body: unknown) {
    super(message);
    this.status = status;
    this.body = body;
    this.url = url;
    this.method = method;
  }
}

// Types matching backend schemas
export interface Rule {
  id?: number;
  user_id?: string;
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
  sent_at?: string;
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
  requires2FA?: boolean;  // For 2FA login flow
  status?: number;
  count?: number;  // For batch operations that return count directly
}

export type UserProfile = {
  id: number;
  username: string;
  email: string;
  avatar_url?: string;
  is_admin?: boolean;
  is_super_admin?: boolean;
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
  username?: string;  // Enriched by backend JOIN
  email?: string;     // Enriched by backend JOIN
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

class ApiClient {
  private baseURL: string;
  private onLogout: (() => void) | null = null;
  private onRefresh: ((expiresAt: number) => void) | null = null;
  private refreshPromise: Promise<{ success: boolean; expiresAt?: number }> | null = null;
  private hasCalledLogout: boolean = false;
  private csrfToken: string | null = null;

  constructor(baseURL: string = API_BASE_URL) {
    // Allow build-time to proceed without API_URL (SSG pages won't call API during build)
    if (!baseURL && typeof window !== 'undefined') {
      throw new Error('NEXT_PUBLIC_API_URL environment variable is required');
    }
    this.baseURL = baseURL;
    // Only init CSRF token on client-side
    if (typeof window !== 'undefined') {
      void this.initCsrfToken();
    }
  }

  private async initCsrfToken() {
    try {
      const response = await fetch(`${this.baseURL}/api/csrf-token`, {
        credentials: 'include',
      });
      if (response.ok) {
        const data = await response.json() as ApiResponse<{ csrf_token: string }>;
        if (data.success && data.data?.csrf_token) {
          this.csrfToken = data.data.csrf_token;
        }
      }
    } catch (error) {
      logger.warn('Failed to initialize CSRF token:', error);
    }
  }

  ensureSuccess<T>(response: ApiResponse<T>, fallbackMessage?: string): ApiResponse<T> {
    if (!response.success) {
      const message = response.message || response.error || fallbackMessage || 'Request failed';
      throw new Error(message);
    }
    return response;
  }

  // Method to set logout callback
  setLogoutCallback(callback: () => void) {
    this.onLogout = callback;
  }

  // Method to set refresh callback
  setRefreshCallback(callback: (expiresAt: number) => void) {
    this.onRefresh = callback;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {},
    allowRefresh: boolean = true
  ): Promise<ApiResponse<T>> {
    try {
      const url = `${this.baseURL}${endpoint}`;

      // Build headers
      const headers: Record<string, string> = {};
      if (options.body && !(options.body instanceof FormData)) headers['Content-Type'] = 'application/json';
      
      // Add CSRF token for mutating requests — lazy-init if constructor fetch failed
      const isMutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(options.method || 'GET');
      if (isMutating) {
        if (!this.csrfToken) {
          await this.initCsrfToken();
        }
        if (this.csrfToken) {
          headers['x-csrf-token'] = this.csrfToken;
        }
      }

      const response = await fetch(url, {
        ...options,
        headers: {
          ...headers,
          ...options.headers,
        },
        credentials: 'include',
      });

      let data: unknown = null;
      try {
        data = await response.json();
      } catch {
        // Non-JSON response
        const message = `Invalid JSON response (status ${response.status})`;
        throw new ApiError(message, response.status, url, options.method || 'GET', null);
      }

      if (!response.ok) {
        const errorPayload =
          data && typeof data === 'object'
            ? (data as { message?: string; error?: string; code?: string })
            : undefined;
        const message = errorPayload?.message || errorPayload?.error || `HTTP ${response.status}`;

        const isAuthLogin = endpoint.startsWith('/api/auth/login');
        const isAuthRegister = endpoint.startsWith('/api/auth/register');
        const isAuthLogout = endpoint.startsWith('/api/auth/logout');

        // Check for CSRF token errors (403 with CSRF_TOKEN_* code)
        const isCsrfError = response.status === 403 && 
          errorPayload?.code?.startsWith('CSRF_TOKEN_');

        if (isCsrfError && allowRefresh) {
          // CSRF token expired or invalid - regenerate and retry
          await this.initCsrfToken();
          return this.request<T>(endpoint, options, false);
        }

        const shouldAttemptRefresh =
          !isAuthLogin &&
          !isAuthRegister &&
          !isAuthLogout &&
          response.status === 401 &&
          allowRefresh;

        if (shouldAttemptRefresh) {
          const refreshResult = await this.tryRefreshToken();
          if (refreshResult.success) {
            // Notify that token was refreshed
            if (this.onRefresh && refreshResult.expiresAt) {
              this.onRefresh(refreshResult.expiresAt);
            }
            // Reset logout flag since we successfully refreshed
            this.hasCalledLogout = false;
            return this.request<T>(endpoint, options, false);
          }
          // Only trigger logout callback once if refresh failed
          if (this.onLogout && !this.hasCalledLogout) {
            this.hasCalledLogout = true;
            this.onLogout();
          }
        }

        return {
          success: false,
          error: message,
          message,
          details: data,
          status: response.status,
        };
      }

      const parsed = data as ApiResponse<T>;
      return { ...parsed, success: parsed?.success ?? true };
    } catch (error) {
      const message = (error as Error).message || 'Network error';
      if (process.env['NODE_ENV'] === 'development') {
        logger.warn('API request failed:', message);
      }
      return { success: false, error: message, message } as ApiResponse<T>;
    }
  }

  async tryRefreshToken(): Promise<{ success: boolean; expiresAt?: number }> {
    // If a refresh is already in progress, wait for it instead of starting a new one
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    // Start a new refresh and store the promise
    this.refreshPromise = (async () => {
      try {
        const result = await this.refresh();
        return {
          success: Boolean(result?.success),
          expiresAt: result?.data?.token_expires_at,
        };
      } catch (error) {
        if (process.env['NODE_ENV'] === 'development') {
          logger.warn('Token refresh failed:', (error as Error).message);
        }
        return { success: false };
      } finally {
        // Clear the promise after completion (success or failure)
        this.refreshPromise = null;
      }
    })();

    return this.refreshPromise;
  }

  // Auth endpoints
  async login(email: string, password: string, totpCode?: string): Promise<ApiResponse<{ token_expires_at?: number; requires_2fa?: boolean } & UserProfile>> {
    this.hasCalledLogout = false; // Reset logout flag on new login
    return this.request(`/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password, totp_code: totpCode }),
      }, false);
  }

  async verifyOAuth2FA(totpCode: string): Promise<ApiResponse<UserProfile>> {
    this.hasCalledLogout = false;
    return this.request(`/api/auth/verify-oauth-2fa`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ totp_code: totpCode }),
    }, false);
  }

  async register(username: string, email: string, password: string): Promise<ApiResponse<{ token_expires_at?: number; token?: string } & Partial<UserProfile>>> {
    this.hasCalledLogout = false; // Reset logout flag on new register
    return this.request(`/api/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, email, password, tos_accepted: true }),
      }, false);
  }

  async refresh() {
    return this.request<{ token_expires_at?: number }>(`/api/auth/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({}),
    }, false);
  }

  async logout() {
    // Ensure we have a fresh CSRF token before logging out
    if (!this.csrfToken && typeof window !== 'undefined') {
      await this.initCsrfToken();
    }

    return this.request<{ message: string }>(`/api/auth/logout`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({}),
    }, true); // allow CSRF auto-retry; auth refresh is skipped for logout
  }

  // System endpoints
  async getSystemStatus() {
    return this.request<SystemStats>('/api/system/status');
  }



  // Rules endpoints
  async getRules(): Promise<ApiResponse<Rule[]>> {
    return this.request<Rule[]>('/api/rules');
  }

  async createRule(rule: CreateRuleData): Promise<ApiResponse<Rule>> {
    return this.request<Rule>('/api/rules', {
      method: 'POST',
      body: JSON.stringify(rule),
    });
  }

  async updateRule(id: number, data: Partial<CreateRuleData>): Promise<ApiResponse<Rule>> {
    return this.request<Rule>(`/api/rules/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(data),
    });
  }

  async deleteRule(id: number): Promise<ApiResponse<{ message: string }>> {
    return this.request<{ message: string }>(`/api/rules/${id}`, {
      method: 'DELETE',
    });
  }

  async batchEnableRules(ruleIds?: number[]): Promise<ApiResponse<{ message: string; count: number }>> {
    return this.request<{ message: string; count: number }>(`/api/rules/batch/enable`, {
      method: 'POST',
      body: JSON.stringify({ rule_ids: ruleIds || [] }),
    });
  }

  async batchDisableRules(ruleIds?: number[]): Promise<ApiResponse<{ message: string; count: number }>> {
    return this.request<{ message: string; count: number }>(`/api/rules/batch/disable`, {
      method: 'POST',
      body: JSON.stringify({ rule_ids: ruleIds || [] }),
    });
  }

  async batchDeleteRules(ruleIds?: number[], confirmAll: boolean = false): Promise<ApiResponse<{ message: string; count: number }>> {
    return this.request<{ message: string; count: number }>(`/api/rules/batch/delete`, {
      method: 'POST',
      body: JSON.stringify({ rule_ids: ruleIds || [], confirm_all: confirmAll }),
    });
  }

  // Alerts endpoints
  async getAlerts(params: {
    limit?: number;
    offset?: number;
    rule_id?: number;
    item_name?: string;
    sort_by?: 'date' | 'price_asc' | 'price_desc' | 'wear_asc' | 'wear_desc';
  } = {}): Promise<PaginatedResponse<Alert>> {
    const searchParams = new URLSearchParams();
    
    if (params.limit) searchParams.append('limit', params.limit.toString());
    if (params.offset) searchParams.append('offset', params.offset.toString());
    if (params.rule_id) searchParams.append('rule_id', params.rule_id.toString());
    if (params.item_name) searchParams.append('item_name', params.item_name);
    if (params.sort_by) searchParams.append('sort_by', params.sort_by);

    const endpoint = `/api/alerts${searchParams.toString() ? '?' + searchParams.toString() : ''}`;
    return this.request<Alert[]>(endpoint) as Promise<PaginatedResponse<Alert>>;
  }

  async getAlertItemNames(): Promise<ApiResponse<string[]>> {
    return this.request('/api/alerts/items');
  }

  async getAlertStats(): Promise<ApiResponse<{
    totalRules: number;
    enabledRules: number;
    totalAlerts: number;
    todayAlerts: number;
  }>> {
    return this.request('/api/alerts/stats');
  }

  async clearAllAlerts(): Promise<ApiResponse<{
    deletedCount: number;
    message: string;
  }>> {
    return this.request('/api/alerts/clear-all', {
      method: 'POST',
    });
  }

  // Webhook endpoints
  async getWebhooks(decrypt: boolean = false): Promise<ApiResponse<Webhook[]>> {
    const query = decrypt ? '?decrypt=true' : '';
    return this.request<Webhook[]>(`/api/webhooks${query}`);
  }

  async createWebhook(webhook: Omit<Webhook, 'id' | 'user_id' | 'webhook_type' | 'created_at' | 'updated_at'> & { webhook_url: string }): Promise<ApiResponse<Webhook>> {
    return this.request<Webhook>('/api/webhooks', {
      method: 'POST',
      body: JSON.stringify({ ...webhook, webhook_type: 'discord' }),
    });
  }

  async updateWebhook(id: number, updates: Partial<Webhook>): Promise<ApiResponse<Webhook>> {
    return this.request<Webhook>(`/api/webhooks/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(updates),
    });
  }

  async deleteWebhook(id: number): Promise<ApiResponse<{ message: string }>> {
    return this.request<{ message: string }>(`/api/webhooks/${id}`, {
      method: 'DELETE',
    });
  }

  async batchEnableWebhooks(webhookIds?: number[]): Promise<ApiResponse<{ message: string; count: number }>> {
    return this.request<{ message: string; count: number }>(`/api/webhooks/batch/enable`, {
      method: 'POST',
      body: JSON.stringify({ webhook_ids: webhookIds || [] }),
    });
  }

  async batchDisableWebhooks(webhookIds?: number[]): Promise<ApiResponse<{ message: string; count: number }>> {
    return this.request<{ message: string; count: number }>(`/api/webhooks/batch/disable`, {
      method: 'POST',
      body: JSON.stringify({ webhook_ids: webhookIds || [] }),
    });
  }

  async batchDeleteWebhooks(webhookIds?: number[], confirmAll: boolean = false): Promise<ApiResponse<{ message: string; count: number }>> {
    return this.request<{ message: string; count: number }>(`/api/webhooks/batch/delete`, {
      method: 'POST',
      body: JSON.stringify({ webhook_ids: webhookIds || [], confirm_all: confirmAll }),
    });
  }

  // Items search endpoint for autocomplete
  async searchItems(query: string, limit?: number): Promise<ApiResponse<Array<{
    name: string;
    imageUrl?: string;
  }>>> {
    const params = new URLSearchParams({ q: query });
    if (limit) params.append('limit', limit.toString());
    
    return this.request<Array<{
      name: string;
      imageUrl?: string;
    }>>(`/api/items/search?${params.toString()}`);
  }

  // Generic GET method for admin endpoints
  async get<T = unknown>(endpoint: string): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, { method: 'GET' });
  }

  // Get current user profile
  async getUserProfile(options?: { allowRefresh?: boolean }): Promise<ApiResponse<{
    id: number;
    username: string;
    email: string;
    avatar_url: string;
    use_gravatar: boolean;
    is_admin: boolean;
    is_super_admin: boolean;
    has_password: boolean;
  }>> {
    return this.request('/api/user/profile', { method: 'GET' }, options?.allowRefresh ?? true);
  }

  // Generic DELETE method for admin endpoints
  async delete<T = unknown>(endpoint: string, data?: unknown): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, { 
      method: 'DELETE',
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  // Generic PATCH method for admin endpoints
  async patch<T = unknown>(endpoint: string, data?: unknown): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, {
      method: 'PATCH',
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  // Generic POST method for admin endpoints
  async post<T = unknown>(endpoint: string, data?: unknown): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, {
      method: 'POST',
      body: data ? JSON.stringify(data) : undefined,
    });
  }

  // Upload file via multipart/form-data (browser sets Content-Type boundary automatically)
  async uploadFile<T = unknown>(endpoint: string, formData: FormData): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, {
      method: 'POST',
      body: formData,
    });
  }

  // Get pending users (admin only)
  async getPendingUsers(): Promise<ApiResponse<Array<{
    id: number;
    username: string;
    email: string;
    created_at: string;
  }>>> {
    return this.get('/api/admin/pending-users');
  }

  // Approve a user (admin only)
  async approveUser(userId: number): Promise<ApiResponse<{ message: string }>> {
    return this.post(`/api/admin/approve-user/${userId}`);
  }

  // Reject a user (admin only)
  async rejectUser(userId: number): Promise<ApiResponse<{ message: string }>> {
    return this.post(`/api/admin/reject-user/${userId}`);
  }

  // Force scheduler run (super admin only)
  async forceSchedulerRun(): Promise<ApiResponse<{ message: string }>> {
    return this.post(`/api/admin/scheduler/force-run`);
  }

  // Test Sentry integration (super admin only)
  async testSentry(): Promise<ApiResponse<{ message: string }>> {
    return this.post(`/api/admin/test-sentry`);
  }

  // Get user's own audit logs
  async getUserAuditLogs(limit: number = 100): Promise<ApiResponse<AuditLog[]>> {
    return this.get(`/api/user/audit-logs?limit=${limit}`);
  }

  // Search users by username or email (admin only)
  async searchUsers(query: string, adminsOnly: boolean = false): Promise<ApiResponse<Array<{ id: number; username: string; email: string }>>> {
    const params = new URLSearchParams({ q: query });
    if (adminsOnly) params.append('admins_only', 'true');
    return this.get(`/api/admin/users/search?${params.toString()}`);
  }

  // Get all audit logs (admin only)
  async getAllAuditLogs(params?: {
    limit?: number;
    event_type?: string;
    user_id?: number;
  }): Promise<ApiResponse<AuditLog[]>> {
    const query = new URLSearchParams();
    if (params?.limit) query.append('limit', params.limit.toString());
    if (params?.event_type) query.append('event_type', params.event_type);
    if (params?.user_id) query.append('user_id', params.user_id.toString());
    return this.get(`/api/admin/audit-logs?${query.toString()}`);
  }

  // ==================== OAuth ====================

  /** Get enabled OAuth providers */
  async getOAuthProviders(): Promise<ApiResponse<{ providers: string[] }>> {
    return this.get('/api/auth/oauth/providers');
  }

  /** Build full URL to initiate OAuth flow (browser redirect) */
  getOAuthLoginUrl(provider: string, mode: 'login' | 'register' = 'login'): string {
    return `${this.baseURL}/api/auth/oauth/${provider}?mode=${mode}`;
  }

  /** Get pending OAuth registration info (email, suggested username, provider) */
  async getOAuthPendingRegistration(): Promise<ApiResponse<{ email: string; suggested_username: string; provider: string }>> {
    return this.get('/api/auth/oauth-pending-registration');
  }

  /** Finalize OAuth registration with TOS acceptance and chosen username */
  async finalizeOAuthRegistration(username: string, tosAccepted: boolean): Promise<ApiResponse<UserProfile>> {
    this.hasCalledLogout = false;
    return this.request('/api/auth/finalize-oauth-registration', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, tos_accepted: tosAccepted }),
    }, false);
  }

  /** Get linked OAuth accounts for current user */
  async getOAuthAccounts(): Promise<ApiResponse<OAuthAccount[]>> {
    return this.get('/api/user/oauth-accounts');
  }

  /** Unlink an OAuth provider */
  async unlinkOAuthAccount(provider: string): Promise<ApiResponse<{ message: string }>> {
    return this.request(`/api/user/oauth-accounts/${provider}`, { method: 'DELETE' });
  }

  // ==================== Passkeys / WebAuthn ====================

  /** List registered passkeys */
  async getPasskeys(): Promise<ApiResponse<PasskeyInfo[]>> {
    return this.get('/api/user/passkeys');
  }

  /** Get registration options for a new passkey */
  async getPasskeyRegisterOptions(): Promise<ApiResponse<PasskeyRegisterOptionsResponse>> {
    return this.post('/api/user/passkeys/register-options');
  }

  /** Verify passkey registration */
  async verifyPasskeyRegistration(credential: unknown, name?: string): Promise<ApiResponse<PasskeyInfo>> {
    return this.post('/api/user/passkeys/register-verify', { credential, name });
  }

  /** Rename a passkey */
  async renamePasskey(id: number, name: string): Promise<ApiResponse<{ id: number; name: string }>> {
    return this.patch(`/api/user/passkeys/${id}`, { name });
  }

  /** Delete a passkey */
  async deletePasskey(id: number): Promise<ApiResponse<{ message: string }>> {
    return this.delete(`/api/user/passkeys/${id}`);
  }

  /** Get passkey authentication options (no auth required) */
  async getPasskeyAuthOptions(): Promise<ApiResponse<PasskeyAuthOptionsResponse>> {
    return this.post('/api/auth/passkey/authenticate-options');
  }

  /** Verify passkey authentication (no auth required) */
  async verifyPasskeyAuth(credential: unknown, challengeKey: string): Promise<ApiResponse<UserProfile & { token_expires_at?: number }>> {
    this.hasCalledLogout = false;
    return this.request('/api/auth/passkey/authenticate-verify', {
      method: 'POST',
      body: JSON.stringify({ credential, challengeKey }),
    }, false);
  }

  // ==================== Admin Users (Paginated) ====================

  /** Get admin users with pagination */
  async getAdminUsers(params?: {
    limit?: number;
    offset?: number;
    sort_by?: string;
    sort_dir?: 'asc' | 'desc';
    search?: string;
    role?: string;
    status?: string;
  }): Promise<PaginatedResponse<AdminUser>> {
    const query = new URLSearchParams();
    if (params?.limit) query.append('limit', params.limit.toString());
    if (params?.offset) query.append('offset', params.offset.toString());
    if (params?.sort_by) query.append('sort_by', params.sort_by);
    if (params?.sort_dir) query.append('sort_dir', params.sort_dir);
    if (params?.search) query.append('search', params.search);
    if (params?.role && params.role !== 'all') query.append('role', params.role);
    if (params?.status && params.status !== 'all') query.append('status', params.status);
    const qs = query.toString();
    return this.get(`/api/admin/users${qs ? `?${qs}` : ''}`) as Promise<PaginatedResponse<AdminUser>>;
  }

  async getAdminUserDetail(userId: number): Promise<ApiResponse<AdminUserDetail>> {
    return this.get<AdminUserDetail>(`/api/admin/users/${userId}`);
  }

  async adminDeleteUserAvatar(userId: number): Promise<ApiResponse<{ avatar_url: string | null }>> {
    return this.delete(`/api/admin/users/${userId}/avatar`);
  }

  async adminRestrictUser(userId: number, data: { restriction_type: 'temporary' | 'permanent'; reason?: string; duration_hours?: number; ban_email?: boolean }): Promise<ApiResponse<unknown>> {
    return this.patch(`/api/admin/users/${userId}/restrict`, data);
  }

  async adminUnrestrictUser(userId: number, reason: string): Promise<ApiResponse<unknown>> {
    return this.patch(`/api/admin/users/${userId}/unrestrict`, { reason });
  }

  async adminDeleteSanction(sanctionId: number): Promise<ApiResponse<unknown>> {
    return this.delete(`/api/admin/sanctions/${sanctionId}`);
  }

  async adminChangeUsername(userId: number, username: string): Promise<ApiResponse<{ username: string }>> {
    return this.patch(`/api/admin/users/${userId}/username`, { username });
  }

  async adminResetUserData(userId: number, target: '2fa' | 'passkeys' | 'sessions'): Promise<ApiResponse<unknown>> {
    return this.post(`/api/admin/users/${userId}/reset`, { target });
  }

  async getAdminLogs(params?: { limit?: number; action?: string; admin_id?: number }): Promise<ApiResponse<AdminActionLog[]>> {
    const query = new URLSearchParams();
    if (params?.limit) query.append('limit', params.limit.toString());
    if (params?.action) query.append('action', params.action);
    if (params?.admin_id) query.append('admin_id', params.admin_id.toString());
    return this.get(`/api/admin/admin-logs?${query.toString()}`);
  }
}

export const apiClient = new ApiClient();
