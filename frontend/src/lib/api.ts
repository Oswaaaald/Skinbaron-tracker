// API Client for SkinBaron Alerts Backend

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';

// Types matching backend schemas
export interface Rule {
  id?: number;
  user_id: string;
  search_item: string;
  min_price?: number;
  max_price?: number;
  min_wear?: number;
  max_wear?: number;
  stattrak?: boolean;
  souvenir?: boolean;
  discord_webhook: string;
  enabled?: boolean;
  created_at?: string;
  updated_at?: string;
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

  constructor(baseURL: string = API_BASE_URL) {
    this.baseURL = baseURL;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<ApiResponse<T>> {
    try {
      const url = `${this.baseURL}${endpoint}`;
      const response = await fetch(url, {
        headers: {
          'Content-Type': 'application/json',
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
    }>('/health');
  }

  async getSystemStatus() {
    return this.request<SystemStats>('/status');
  }

  // Scheduler endpoints
  async startScheduler() {
    return this.request<{ message: string }>('/scheduler/start', {
      method: 'POST',
    });
  }

  async stopScheduler() {
    return this.request<{ message: string }>('/scheduler/stop', {
      method: 'POST',
    });
  }

  async runScheduler() {
    return this.request<{ message: string }>('/scheduler/run', {
      method: 'POST',
    });
  }

  // Rules endpoints
  async getRules(): Promise<ApiResponse<Rule[]>> {
    const response = await this.request<Rule[]>('/rules');
    return response;
  }

  async getRule(id: number): Promise<ApiResponse<Rule>> {
    return this.request<Rule>(`/rules/${id}`);
  }

  async createRule(rule: Omit<Rule, 'id' | 'created_at' | 'updated_at'>): Promise<ApiResponse<Rule>> {
    return this.request<Rule>('/rules', {
      method: 'POST',
      body: JSON.stringify(rule),
    });
  }

  async updateRule(id: number, updates: Partial<Rule>): Promise<ApiResponse<Rule>> {
    return this.request<Rule>(`/rules/${id}`, {
      method: 'PUT',
      body: JSON.stringify(updates),
    });
  }

  async deleteRule(id: number): Promise<ApiResponse<{ message: string }>> {
    return this.request<{ message: string }>(`/rules/${id}`, {
      method: 'DELETE',
    });
  }

  async testRule(id: number, webhookTest: boolean = false): Promise<ApiResponse<{
    matches: any[];
    matchCount: number;
    webhookTest: boolean | null;
  }>> {
    return this.request<{
      matches: any[];
      matchCount: number;
      webhookTest: boolean | null;
    }>(`/rules/${id}/test`, {
      method: 'POST',
      body: JSON.stringify({ webhook_test: webhookTest }),
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

    const endpoint = `/alerts${searchParams.toString() ? '?' + searchParams.toString() : ''}`;
    return this.request<Alert[]>(endpoint) as Promise<PaginatedResponse<Alert>>;
  }

  async getAlert(id: number): Promise<ApiResponse<Alert>> {
    return this.request<Alert>(`/alerts/${id}`);
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
    return this.request('/alerts/stats');
  }

  async getRecentAlerts(limit: number = 20): Promise<ApiResponse<Alert[]>> {
    return this.request<Alert[]>(`/alerts/recent?limit=${limit}`);
  }

  async getAlertsByRule(ruleId: number, params: {
    limit?: number;
    offset?: number;
  } = {}): Promise<ApiResponse<Alert[]>> {
    const searchParams = new URLSearchParams();
    
    if (params.limit) searchParams.append('limit', params.limit.toString());
    if (params.offset) searchParams.append('offset', params.offset.toString());

    const endpoint = `/alerts/by-rule/${ruleId}${searchParams.toString() ? '?' + searchParams.toString() : ''}`;
    return this.request<Alert[]>(endpoint);
  }

  async cleanupAlerts(): Promise<ApiResponse<{
    deletedCount: number;
    message: string;
  }>> {
    return this.request('/alerts/cleanup', {
      method: 'POST',
    });
  }
}

export const apiClient = new ApiClient();
export default apiClient;