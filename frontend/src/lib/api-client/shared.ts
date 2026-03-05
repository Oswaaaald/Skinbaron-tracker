import type { ApiResponse } from '../api-types';

export interface ApiClientRuntime {
  request<T>(endpoint: string, options?: RequestInit, allowRefresh?: boolean): Promise<ApiResponse<T>>;
  get<T = unknown>(endpoint: string): Promise<ApiResponse<T>>;
  delete<T = unknown>(endpoint: string, data?: unknown): Promise<ApiResponse<T>>;
  patch<T = unknown>(endpoint: string, data?: unknown): Promise<ApiResponse<T>>;
  post<T = unknown>(endpoint: string, data?: unknown): Promise<ApiResponse<T>>;
  resetLogoutState(): void;
  ensureCsrfToken(): Promise<void>;
  getBaseUrl(): string;
}
