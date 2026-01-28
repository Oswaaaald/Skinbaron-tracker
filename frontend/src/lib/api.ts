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
  allow_stickers?: boolean;
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
  allow_stickers?: boolean;
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
  skin_url: string;
  alert_type: 'match' | 'best_deal' | 'new_item';
  sent_at?: string;
}

export interface Webhook {
  id?: number;
  user_id: number;
  name: string;
  webhook_url?: string; // Only present when decrypt=true
  webhook_type: 'discord' | 'slack' | 'teams' | 'generic';
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

class ApiClient {
  private baseURL: string;
  private onLogout: (() => void) | null = null;
  private onRefresh: ((expiresAt: number) => void) | null = null;
  private refreshPromise: Promise<{ success: boolean; expiresAt?: number }> | null = null;
  private hasCalledLogout: boolean = false;

  constructor(baseURL: string = API_BASE_URL) {
    if (!baseURL) {
      throw new Error('NEXT_PUBLIC_API_URL environment variable is required');
    }
    this.baseURL = baseURL;
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
      if (options.body) headers['Content-Type'] = 'application/json';

      const response = await fetch(url, {
        headers: {
          ...headers,
          ...options.headers,
        },
        credentials: 'include',
        ...options,
      });

      let data: unknown = null;
      try {
        data = await response.json();
      } catch (_err) {
        // Non-JSON response
        const message = `Invalid JSON response (status ${response.status})`;
        throw new ApiError(message, response.status, url, options.method || 'GET', null);
      }

      if (!response.ok) {
        const errorPayload =
          data && typeof data === 'object'
            ? (data as { message?: string; error?: string })
            : undefined;
        const message = errorPayload?.message || errorPayload?.error || `HTTP ${response.status}`;

        const isAuthLogin = endpoint.startsWith('/api/auth/login');
        const isAuthRegister = endpoint.startsWith('/api/auth/register');
        const isAuthLogout = endpoint.startsWith('/api/auth/logout');

        const shouldAttemptRefresh =
          !isAuthLogin &&
          !isAuthRegister &&
          !isAuthLogout &&
          (response.status === 401 || response.status === 403) &&
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

  private async tryRefreshToken(): Promise<{ success: boolean; expiresAt?: number }> {
    // If a refresh is already in progress, wait for it instead of starting a new one
    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    // Start a new refresh and store the promise
    this.refreshPromise = (async () => {
      try {
        const url = `${this.baseURL}/api/auth/refresh`;
        const response = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({}),
          credentials: 'include',
        });

        if (!response.ok) {
          return { success: false };
        }
        const data = await response.json();
        return {
          success: Boolean(data?.success),
          expiresAt: data?.data?.token_expires_at,
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
  async login(email: string, password: string, totpCode?: string): Promise<ApiResponse<{ token_expires_at?: number } & UserProfile>> {
    this.hasCalledLogout = false; // Reset logout flag on new login
    return this.request(`/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password, totp_code: totpCode }),
      }, false);
  }

  async register(username: string, email: string, password: string): Promise<ApiResponse<{ token_expires_at?: number } & Partial<UserProfile>>> {
    this.hasCalledLogout = false; // Reset logout flag on new register
    return this.request(`/api/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ username, email, password }),
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
    return this.request<{ message: string }>(`/api/auth/logout`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({}),
    }, false);
  }

  // System endpoints
  async getSystemStatus() {
    return this.request<SystemStats>('/api/system/status');
  }



  // Rules endpoints
  async getRules(): Promise<ApiResponse<Rule[]>> {
    return this.request<Rule[]>('/api/rules');
  }

  async getRule(id: number): Promise<ApiResponse<Rule>> {
    return this.request<Rule>(`/api/rules/${id}`);
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

  async testRule(id: number, webhookTest: boolean = false, webhookOnly: boolean = false): Promise<ApiResponse<{
    matches: Array<{
      saleId: string;
      itemName: string;
      price: number;
      wearValue?: number;
      imageUrl?: string;
      [key: string]: unknown;
    }>;
    matchCount: number;
    webhookTest: boolean | null;
  }>> {
    return this.request<{
      matches: Array<{
        saleId: string;
        itemName: string;
        price: number;
        wearValue?: number;
        imageUrl?: string;
        [key: string]: unknown;
      }>;
      matchCount: number;
      webhookTest: boolean | null;
    }>(`/api/rules/${id}/test`, {
      method: 'POST',
      body: JSON.stringify({ 
        webhook_test: webhookTest,
        webhook_only: webhookOnly 
      }),
    });
  }

  // Alerts endpoints
  async getAlerts(params: {
    limit?: number;
    offset?: number;
    rule_id?: number;
    alert_type?: 'match' | 'best_deal' | 'new_item';
  } = {}): Promise<PaginatedResponse<Alert>> {
    const searchParams = new URLSearchParams();
    
    if (params.limit) searchParams.append('limit', params.limit.toString());
    if (params.offset) searchParams.append('offset', params.offset.toString());
    if (params.rule_id) searchParams.append('rule_id', params.rule_id.toString());
    if (params.alert_type) searchParams.append('alert_type', params.alert_type);

    const endpoint = `/api/alerts${searchParams.toString() ? '?' + searchParams.toString() : ''}`;
    return this.request<Alert[]>(endpoint) as Promise<PaginatedResponse<Alert>>;
  }

  async getAlert(id: number): Promise<ApiResponse<Alert>> {
    return this.request<Alert>(`/api/alerts/${id}`);
  }

  async getAlertStats(): Promise<ApiResponse<{
    totalRules: number;
    enabledRules: number;
    totalAlerts: number;
    todayAlerts: number;
    alertsByType: {
      match: number;
      best_deal: number;
      new_item: number;
    };
  }>> {
    return this.request('/api/alerts/stats');
  }

  async getUserStats(): Promise<ApiResponse<{
    totalRules: number;
    enabledRules: number;
    totalAlerts: number;
    todayAlerts: number;
    alertsByType: {
      match: number;
      best_deal: number;
      new_item: number;
    };
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

  async getWebhook(id: number, decrypt: boolean = false): Promise<ApiResponse<Webhook>> {
    const query = decrypt ? '?decrypt=true' : '';
    return this.request<Webhook>(`/api/webhooks/${id}${query}`);
  }

  async createWebhook(webhook: Omit<Webhook, 'id' | 'user_id' | 'created_at' | 'updated_at'> & { webhook_url: string }): Promise<ApiResponse<Webhook>> {
    return this.request<Webhook>('/api/webhooks', {
      method: 'POST',
      body: JSON.stringify(webhook),
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
    is_admin: boolean;
    is_super_admin: boolean;
  }>> {
    return this.request('/api/user/profile', { method: 'GET' }, options?.allowRefresh ?? true);
  }

  // Generic DELETE method for admin endpoints
  async delete<T = unknown>(endpoint: string): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, { method: 'DELETE' });
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

  // Get user's own audit logs
  async getUserAuditLogs(limit: number = 100): Promise<ApiResponse<AuditLog[]>> {
    return this.get(`/api/user/audit-logs?limit=${limit}`);
  }

  // Search users by username or email (admin only)
  async searchUsers(query: string): Promise<ApiResponse<Array<{ id: number; username: string; email: string }>>> {
    return this.get(`/api/admin/users/search?q=${encodeURIComponent(query)}`);
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
}

export const apiClient = new ApiClient();
export default apiClient;