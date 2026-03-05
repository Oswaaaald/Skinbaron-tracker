import type {
  AdminActionLog,
  AdminUser,
  AdminUserDetail,
  ApiResponse,
  AuditLog,
  PaginatedResponse,
} from '../api-types';
import type { ApiClientRuntime } from './shared';

export type AdminApiMethods = {
  getPendingUsers(): Promise<ApiResponse<Array<{
    id: number;
    username: string;
    email: string;
    created_at: string;
  }>>>;
  approveUser(userId: number): Promise<ApiResponse<{ message: string }>>;
  rejectUser(userId: number): Promise<ApiResponse<{ message: string }>>;
  forceSchedulerRun(): Promise<ApiResponse<{ message: string }>>;
  testSentry(): Promise<ApiResponse<{ message: string }>>;
  getUserAuditLogs(limit?: number): Promise<ApiResponse<AuditLog[]>>;
  searchUsers(query: string, adminsOnly?: boolean): Promise<ApiResponse<Array<{ id: number; username: string; email: string }>>>;
  getAllAuditLogs(params?: {
    limit?: number;
    event_type?: string;
    user_id?: number;
  }): Promise<ApiResponse<AuditLog[]>>;
  getAdminUsers(params?: {
    limit?: number;
    offset?: number;
    sort_by?: string;
    sort_dir?: 'asc' | 'desc';
    search?: string;
    role?: string;
    status?: string;
  }): Promise<PaginatedResponse<AdminUser>>;
  getAdminUserDetail(userId: number): Promise<ApiResponse<AdminUserDetail>>;
  adminDeleteUserAvatar(userId: number): Promise<ApiResponse<{ avatar_url: string | null }>>;
  adminRestrictUser(userId: number, data: { restriction_type: 'temporary' | 'permanent'; reason?: string; duration_hours?: number; ban_email?: boolean }): Promise<ApiResponse<unknown>>;
  adminUnrestrictUser(userId: number, reason: string): Promise<ApiResponse<unknown>>;
  adminDeleteSanction(sanctionId: number): Promise<ApiResponse<unknown>>;
  adminChangeUsername(userId: number, username: string): Promise<ApiResponse<{ username: string }>>;
  adminResetUserData(userId: number, target: '2fa' | 'passkeys' | 'sessions'): Promise<ApiResponse<unknown>>;
  getAdminLogs(params?: { limit?: number; action?: string; admin_id?: number }): Promise<ApiResponse<AdminActionLog[]>>;
};

export function createAdminApiMethods(client: ApiClientRuntime): AdminApiMethods {
  return {
    async getPendingUsers(): Promise<ApiResponse<Array<{
      id: number;
      username: string;
      email: string;
      created_at: string;
    }>>> {
      return client.get('/api/admin/pending-users');
    },

    async approveUser(userId: number): Promise<ApiResponse<{ message: string }>> {
      return client.post(`/api/admin/approve-user/${userId}`);
    },

    async rejectUser(userId: number): Promise<ApiResponse<{ message: string }>> {
      return client.post(`/api/admin/reject-user/${userId}`);
    },

    async forceSchedulerRun(): Promise<ApiResponse<{ message: string }>> {
      return client.post(`/api/admin/scheduler/force-run`);
    },

    async testSentry(): Promise<ApiResponse<{ message: string }>> {
      return client.post(`/api/admin/test-sentry`);
    },

    async getUserAuditLogs(limit: number = 100): Promise<ApiResponse<AuditLog[]>> {
      return client.get(`/api/user/audit-logs?limit=${limit}`);
    },

    async searchUsers(query: string, adminsOnly: boolean = false): Promise<ApiResponse<Array<{ id: number; username: string; email: string }>>> {
      const params = new URLSearchParams({ q: query });
      if (adminsOnly) params.append('admins_only', 'true');
      return client.get(`/api/admin/users/search?${params.toString()}`);
    },

    async getAllAuditLogs(params?: {
      limit?: number;
      event_type?: string;
      user_id?: number;
    }): Promise<ApiResponse<AuditLog[]>> {
      const query = new URLSearchParams();
      if (params?.limit) query.append('limit', params.limit.toString());
      if (params?.event_type) query.append('event_type', params.event_type);
      if (params?.user_id) query.append('user_id', params.user_id.toString());
      return client.get(`/api/admin/audit-logs?${query.toString()}`);
    },

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
      return client.get(`/api/admin/users${qs ? `?${qs}` : ''}`) as Promise<PaginatedResponse<AdminUser>>;
    },

    async getAdminUserDetail(userId: number): Promise<ApiResponse<AdminUserDetail>> {
      return client.get<AdminUserDetail>(`/api/admin/users/${userId}`);
    },

    async adminDeleteUserAvatar(userId: number): Promise<ApiResponse<{ avatar_url: string | null }>> {
      return client.delete(`/api/admin/users/${userId}/avatar`);
    },

    async adminRestrictUser(userId: number, data: { restriction_type: 'temporary' | 'permanent'; reason?: string; duration_hours?: number; ban_email?: boolean }): Promise<ApiResponse<unknown>> {
      return client.patch(`/api/admin/users/${userId}/restrict`, data);
    },

    async adminUnrestrictUser(userId: number, reason: string): Promise<ApiResponse<unknown>> {
      return client.patch(`/api/admin/users/${userId}/unrestrict`, { reason });
    },

    async adminDeleteSanction(sanctionId: number): Promise<ApiResponse<unknown>> {
      return client.delete(`/api/admin/sanctions/${sanctionId}`);
    },

    async adminChangeUsername(userId: number, username: string): Promise<ApiResponse<{ username: string }>> {
      return client.patch(`/api/admin/users/${userId}/username`, { username });
    },

    async adminResetUserData(userId: number, target: '2fa' | 'passkeys' | 'sessions'): Promise<ApiResponse<unknown>> {
      return client.post(`/api/admin/users/${userId}/reset`, { target });
    },

    async getAdminLogs(params?: { limit?: number; action?: string; admin_id?: number }): Promise<ApiResponse<AdminActionLog[]>> {
      const query = new URLSearchParams();
      if (params?.limit) query.append('limit', params.limit.toString());
      if (params?.action) query.append('action', params.action);
      if (params?.admin_id) query.append('admin_id', params.admin_id.toString());
      return client.get(`/api/admin/admin-logs?${query.toString()}`);
    },
  };
}
