import type {
  Alert,
  ApiResponse,
  CreateRuleData,
  PaginatedResponse,
  Rule,
  SystemStats,
  UserProfile,
  Webhook,
} from '../api-types';
import type { ApiClientRuntime } from './shared';

export type DataApiMethods = {
  getSystemStatus(): Promise<ApiResponse<SystemStats>>;
  getRules(): Promise<ApiResponse<Rule[]>>;
  createRule(rule: CreateRuleData): Promise<ApiResponse<Rule>>;
  updateRule(id: number, data: Partial<CreateRuleData>): Promise<ApiResponse<Rule>>;
  deleteRule(id: number): Promise<ApiResponse<{ message: string }>>;
  batchEnableRules(ruleIds?: number[]): Promise<ApiResponse<{ message: string; count: number }>>;
  batchDisableRules(ruleIds?: number[]): Promise<ApiResponse<{ message: string; count: number }>>;
  batchDeleteRules(ruleIds?: number[], confirmAll?: boolean): Promise<ApiResponse<{ message: string; count: number }>>;
  getAlerts(params?: {
    limit?: number;
    offset?: number;
    rule_id?: number;
    item_name?: string;
    sort_by?: 'date' | 'price_asc' | 'price_desc' | 'wear_asc' | 'wear_desc';
  }): Promise<PaginatedResponse<Alert>>;
  getAlertItemNames(): Promise<ApiResponse<string[]>>;
  getAlertStats(): Promise<ApiResponse<{
    totalRules: number;
    enabledRules: number;
    totalAlerts: number;
    todayAlerts: number;
  }>>;
  clearAllAlerts(): Promise<ApiResponse<{
    deletedCount: number;
    message: string;
  }>>;
  getWebhooks(decrypt?: boolean): Promise<ApiResponse<Webhook[]>>;
  createWebhook(webhook: Omit<Webhook, 'id' | 'user_id' | 'webhook_type' | 'created_at' | 'updated_at'> & { webhook_url: string }): Promise<ApiResponse<Webhook>>;
  updateWebhook(id: number, updates: Partial<Webhook>): Promise<ApiResponse<Webhook>>;
  deleteWebhook(id: number): Promise<ApiResponse<{ message: string }>>;
  batchEnableWebhooks(webhookIds?: number[]): Promise<ApiResponse<{ message: string; count: number }>>;
  batchDisableWebhooks(webhookIds?: number[]): Promise<ApiResponse<{ message: string; count: number }>>;
  batchDeleteWebhooks(webhookIds?: number[], confirmAll?: boolean): Promise<ApiResponse<{ message: string; count: number }>>;
  searchItems(query: string, limit?: number, options?: { signal?: AbortSignal }): Promise<ApiResponse<Array<{ name: string; imageUrl?: string }>>>;
  getUserProfile(options?: { allowRefresh?: boolean }): Promise<ApiResponse<UserProfile>>;
};

export function createDataApiMethods(client: ApiClientRuntime): DataApiMethods {
  return {
    async getSystemStatus() {
      return client.request<SystemStats>('/api/system/status');
    },

    async getRules(): Promise<ApiResponse<Rule[]>> {
      return client.request<Rule[]>('/api/rules');
    },

    async createRule(rule: CreateRuleData): Promise<ApiResponse<Rule>> {
      return client.request<Rule>('/api/rules', {
        method: 'POST',
        body: JSON.stringify(rule),
      });
    },

    async updateRule(id: number, data: Partial<CreateRuleData>): Promise<ApiResponse<Rule>> {
      return client.request<Rule>(`/api/rules/${id}`, {
        method: 'PATCH',
        body: JSON.stringify(data),
      });
    },

    async deleteRule(id: number): Promise<ApiResponse<{ message: string }>> {
      return client.request<{ message: string }>(`/api/rules/${id}`, {
        method: 'DELETE',
      });
    },

    async batchEnableRules(ruleIds?: number[]): Promise<ApiResponse<{ message: string; count: number }>> {
      return client.request<{ message: string; count: number }>(`/api/rules/batch/enable`, {
        method: 'POST',
        body: JSON.stringify({ rule_ids: ruleIds || [] }),
      });
    },

    async batchDisableRules(ruleIds?: number[]): Promise<ApiResponse<{ message: string; count: number }>> {
      return client.request<{ message: string; count: number }>(`/api/rules/batch/disable`, {
        method: 'POST',
        body: JSON.stringify({ rule_ids: ruleIds || [] }),
      });
    },

    async batchDeleteRules(ruleIds?: number[], confirmAll: boolean = false): Promise<ApiResponse<{ message: string; count: number }>> {
      return client.request<{ message: string; count: number }>(`/api/rules/batch/delete`, {
        method: 'POST',
        body: JSON.stringify({ rule_ids: ruleIds || [], confirm_all: confirmAll }),
      });
    },

    async getAlerts(params: {
      limit?: number;
      offset?: number;
      rule_id?: number;
      item_name?: string;
      sort_by?: 'date' | 'price_asc' | 'price_desc' | 'wear_asc' | 'wear_desc';
    } = {}): Promise<PaginatedResponse<Alert>> {
      const searchParams = new URLSearchParams();

      if (params.limit !== undefined) searchParams.append('limit', params.limit.toString());
      if (params.offset !== undefined) searchParams.append('offset', params.offset.toString());
      if (params.rule_id) searchParams.append('rule_id', params.rule_id.toString());
      if (params.item_name) searchParams.append('item_name', params.item_name);
      if (params.sort_by) searchParams.append('sort_by', params.sort_by);

      const endpoint = `/api/alerts${searchParams.toString() ? '?' + searchParams.toString() : ''}`;
      return client.request<Alert[]>(endpoint) as Promise<PaginatedResponse<Alert>>;
    },

    async getAlertItemNames(): Promise<ApiResponse<string[]>> {
      return client.request('/api/alerts/items');
    },

    async getAlertStats(): Promise<ApiResponse<{
      totalRules: number;
      enabledRules: number;
      totalAlerts: number;
      todayAlerts: number;
    }>> {
      return client.request('/api/alerts/stats');
    },

    async clearAllAlerts(): Promise<ApiResponse<{
      deletedCount: number;
      message: string;
    }>> {
      return client.request('/api/alerts/clear-all', {
        method: 'POST',
      });
    },

    async getWebhooks(decrypt: boolean = false): Promise<ApiResponse<Webhook[]>> {
      const query = decrypt ? '?decrypt=true' : '';
      return client.request<Webhook[]>(`/api/webhooks${query}`);
    },

    async createWebhook(webhook: Omit<Webhook, 'id' | 'user_id' | 'webhook_type' | 'created_at' | 'updated_at'> & { webhook_url: string }): Promise<ApiResponse<Webhook>> {
      return client.request<Webhook>('/api/webhooks', {
        method: 'POST',
        body: JSON.stringify({ ...webhook, webhook_type: 'discord' }),
      });
    },

    async updateWebhook(id: number, updates: Partial<Webhook>): Promise<ApiResponse<Webhook>> {
      return client.request<Webhook>(`/api/webhooks/${id}`, {
        method: 'PATCH',
        body: JSON.stringify(updates),
      });
    },

    async deleteWebhook(id: number): Promise<ApiResponse<{ message: string }>> {
      return client.request<{ message: string }>(`/api/webhooks/${id}`, {
        method: 'DELETE',
      });
    },

    async batchEnableWebhooks(webhookIds?: number[]): Promise<ApiResponse<{ message: string; count: number }>> {
      return client.request<{ message: string; count: number }>(`/api/webhooks/batch/enable`, {
        method: 'POST',
        body: JSON.stringify({ webhook_ids: webhookIds || [] }),
      });
    },

    async batchDisableWebhooks(webhookIds?: number[]): Promise<ApiResponse<{ message: string; count: number }>> {
      return client.request<{ message: string; count: number }>(`/api/webhooks/batch/disable`, {
        method: 'POST',
        body: JSON.stringify({ webhook_ids: webhookIds || [] }),
      });
    },

    async batchDeleteWebhooks(webhookIds?: number[], confirmAll: boolean = false): Promise<ApiResponse<{ message: string; count: number }>> {
      return client.request<{ message: string; count: number }>(`/api/webhooks/batch/delete`, {
        method: 'POST',
        body: JSON.stringify({ webhook_ids: webhookIds || [], confirm_all: confirmAll }),
      });
    },

    async searchItems(query: string, limit?: number, options?: { signal?: AbortSignal }): Promise<ApiResponse<Array<{
      name: string;
      imageUrl?: string;
    }>>> {
      const params = new URLSearchParams({ q: query });
      if (limit) params.append('limit', limit.toString());

      return client.request<Array<{
        name: string;
        imageUrl?: string;
      }>>(`/api/items/search?${params.toString()}`, { method: 'GET', signal: options?.signal });
    },

    async getUserProfile(options?: { allowRefresh?: boolean }): Promise<ApiResponse<UserProfile>> {
      return client.request<UserProfile>('/api/user/profile', { method: 'GET' }, options?.allowRefresh ?? true);
    },
  };
}
