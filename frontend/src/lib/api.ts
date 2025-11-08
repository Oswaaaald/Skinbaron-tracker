// API Client for SkinBaron Alerts Backend

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';

// Types matching backend schemas
export interface Rule {
  id?: number;
  user_id?: string;
  search_item: string;
  min_price?: number;
  max_price?: number;
  min_wear?: number;
  max_wear?: number;
  stattrak?: boolean;
  souvenir?: boolean;
  webhook_ids: number[]; // Array of webhook IDs (required)
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
  stattrak?: boolean;
  souvenir?: boolean;
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
  details?: any;
}

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
    errorCount: number;
    lastError: string | null;
  };
  database: {
    totalRules: number;
    enabledRules: number;
    totalAlerts: number;
    todayAlerts: number;
  };
  config: {
    nodeEnv: string;
    pollCron: string;
    enableBestDeals: boolean;
    enableNewestItems: boolean;
    feedsMaxPrice: number;
    feedsMaxWear: number;
  };
}

class ApiClient {
  private baseURL: string;
  private getAuthToken: (() => string | null) | null = null;

  constructor(baseURL: string = API_BASE_URL) {
    this.baseURL = baseURL;
  }

  // Method to set the auth token getter (will be called from auth context)
  setAuthTokenGetter(getter: () => string | null) {
    this.getAuthToken = getter;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<ApiResponse<T>> {
    try {
      const url = `${this.baseURL}${endpoint}`;
      
      // Build headers
      const headers: Record<string, string> = {};
      
      // Add Content-Type header if there's a body
      if (options.body) {
        headers['Content-Type'] = 'application/json';
      }
      
      // Add Authorization header if we have a token
      if (this.getAuthToken) {
        const token = this.getAuthToken();
        if (token) {
          headers['Authorization'] = `Bearer ${token}`;
        }
      }
      
      const response = await fetch(url, {
        headers: {
          ...headers,
          ...options.headers,
        },
        ...options,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.message || `HTTP ${response.status}`);
      }

      return data;
    } catch (error) {
      console.error('API Error:', error);
      throw error;
    }
  }

  // Health and System endpoints
  async getHealth() {
    return this.request<{
      status: string;
      timestamp: string;
      services: Record<string, string>;
      stats: {
        uptime: number;
        memory: NodeJS.MemoryUsage;
        version: string;
      };
    }>('/api/health');
  }

  async getSystemStatus() {
    return this.request<SystemStats>('/api/system/status');
  }

  // Scheduler endpoints
  async startScheduler() {
    return this.request<{ message: string }>('/api/system/scheduler/start', {
      method: 'POST',
    });
  }

  async stopScheduler() {
    return this.request<{ message: string }>('/api/system/scheduler/stop', {
      method: 'POST',
    });
  }

  async runScheduler() {
    return this.request<{ message: string }>('/api/system/scheduler/run', {
      method: 'POST',
    });
  }

  // Rules endpoints
  async getRules(): Promise<ApiResponse<Rule[]>> {
    const response = await this.request<Rule[]>('/api/rules');
    return response;
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

  async updateRule(id: number, data: CreateRuleData): Promise<ApiResponse<Rule>> {
    return this.request<Rule>(`/api/rules/${id}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  }

  async deleteRule(id: number): Promise<ApiResponse<{ message: string }>> {
    return this.request<{ message: string }>(`/api/rules/${id}`, {
      method: 'DELETE',
    });
  }

  async testRule(id: number, webhookTest: boolean = false, webhookOnly: boolean = false): Promise<ApiResponse<{
    matches: any[];
    matchCount: number;
    webhookTest: boolean | null;
  }>> {
    return this.request<{
      matches: any[];
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

  async getRecentAlerts(limit: number = 20): Promise<ApiResponse<Alert[]>> {
    return this.request<Alert[]>(`/api/alerts/recent?limit=${limit}`);
  }

  async getAlertsByRule(ruleId: number, params: {
    limit?: number;
    offset?: number;
  } = {}): Promise<ApiResponse<Alert[]>> {
    const searchParams = new URLSearchParams();
    
    if (params.limit) searchParams.append('limit', params.limit.toString());
    if (params.offset) searchParams.append('offset', params.offset.toString());

    const endpoint = `/api/alerts/by-rule/${ruleId}${searchParams.toString() ? '?' + searchParams.toString() : ''}`;
    return this.request<Alert[]>(endpoint);
  }

  async cleanupAlerts(): Promise<ApiResponse<{
    deletedCount: number;
    message: string;
  }>> {
    return this.request('/api/alerts/cleanup', {
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
      method: 'PUT',
      body: JSON.stringify(updates),
    });
  }

  async deleteWebhook(id: number): Promise<ApiResponse<{ message: string }>> {
    return this.request<{ message: string }>(`/api/webhooks/${id}`, {
      method: 'DELETE',
    });
  }

  async getActiveWebhooks(): Promise<ApiResponse<Webhook[]>> {
    return this.request<Webhook[]>('/api/webhooks/active');
  }

  // Authentication endpoints
  async login(email: string, password: string): Promise<ApiResponse<{
    id: number;
    username: string;
    email: string;
    token: string;
  }>> {
    return this.request('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  }

  async register(username: string, email: string, password: string): Promise<ApiResponse<{
    id: number;
    username: string;
    email: string;
    token: string;
  }>> {
    return this.request('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ username, email, password }),
    });
  }

  async changePassword(currentPassword: string, newPassword: string): Promise<ApiResponse<{ message: string }>> {
    return this.request('/api/auth/change-password', {
      method: 'POST',
      body: JSON.stringify({ currentPassword, newPassword }),
    });
  }

  async updateProfile(updates: { username?: string; email?: string }): Promise<ApiResponse<{
    id: number;
    username: string;
    email: string;
  }>> {
    return this.request('/api/auth/profile', {
      method: 'PUT',
      body: JSON.stringify(updates),
    });
  }
}

export const apiClient = new ApiClient();
export default apiClient;