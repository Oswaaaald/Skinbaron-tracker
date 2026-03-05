import type {
  ApiResponse,
  OAuthAccount,
  PasskeyAuthOptionsResponse,
  PasskeyInfo,
  PasskeyRegisterOptionsResponse,
  UserProfile,
} from '../api-types';
import type { ApiClientRuntime } from './shared';

export type AuthApiMethods = {
  login(email: string, password: string, totpCode?: string): Promise<ApiResponse<{ token_expires_at?: number; requires_2fa?: boolean } & UserProfile>>;
  verifyOAuth2FA(totpCode: string): Promise<ApiResponse<UserProfile>>;
  register(username: string, email: string, password: string): Promise<ApiResponse<{ token_expires_at?: number; token?: string } & Partial<UserProfile>>>;
  refresh(): Promise<ApiResponse<{ token_expires_at?: number }>>;
  logout(): Promise<ApiResponse<{ message: string }>>;
  getOAuthProviders(): Promise<ApiResponse<{ providers: string[] }>>;
  getOAuthLoginUrl(provider: string, mode?: 'login' | 'register'): string;
  getOAuthPendingRegistration(): Promise<ApiResponse<{ email: string; suggested_username: string; provider: string }>>;
  finalizeOAuthRegistration(username: string, tosAccepted: boolean): Promise<ApiResponse<UserProfile>>;
  getOAuthAccounts(): Promise<ApiResponse<OAuthAccount[]>>;
  unlinkOAuthAccount(provider: string): Promise<ApiResponse<{ message: string }>>;
  getPasskeys(): Promise<ApiResponse<PasskeyInfo[]>>;
  getPasskeyRegisterOptions(): Promise<ApiResponse<PasskeyRegisterOptionsResponse>>;
  verifyPasskeyRegistration(credential: unknown, name?: string): Promise<ApiResponse<PasskeyInfo>>;
  renamePasskey(id: number, name: string): Promise<ApiResponse<{ id: number; name: string }>>;
  deletePasskey(id: number): Promise<ApiResponse<{ message: string }>>;
  getPasskeyAuthOptions(): Promise<ApiResponse<PasskeyAuthOptionsResponse>>;
  verifyPasskeyAuth(credential: unknown, challengeKey: string): Promise<ApiResponse<UserProfile & { token_expires_at?: number }>>;
};

export function createAuthApiMethods(client: ApiClientRuntime): AuthApiMethods {
  return {
    async login(email: string, password: string, totpCode?: string): Promise<ApiResponse<{ token_expires_at?: number; requires_2fa?: boolean } & UserProfile>> {
      client.resetLogoutState();
      return client.request(`/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password, totp_code: totpCode }),
      }, false);
    },

    async verifyOAuth2FA(totpCode: string): Promise<ApiResponse<UserProfile>> {
      client.resetLogoutState();
      return client.request(`/api/auth/verify-oauth-2fa`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ totp_code: totpCode }),
      }, false);
    },

    async register(username: string, email: string, password: string): Promise<ApiResponse<{ token_expires_at?: number; token?: string } & Partial<UserProfile>>> {
      client.resetLogoutState();
      return client.request(`/api/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, email, password, tos_accepted: true }),
      }, false);
    },

    async refresh() {
      return client.request<{ token_expires_at?: number }>(`/api/auth/refresh`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({}),
      }, false);
    },

    async logout() {
      await client.ensureCsrfToken();

      return client.request<{ message: string }>(`/api/auth/logout`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({}),
      }, true); // allow CSRF auto-retry; auth refresh is skipped for logout
    },

    async getOAuthProviders(): Promise<ApiResponse<{ providers: string[] }>> {
      return client.get('/api/auth/oauth/providers');
    },

    getOAuthLoginUrl(provider: string, mode: 'login' | 'register' = 'login'): string {
      return `${client.getBaseUrl()}/api/auth/oauth/${provider}?mode=${mode}`;
    },

    async getOAuthPendingRegistration(): Promise<ApiResponse<{ email: string; suggested_username: string; provider: string }>> {
      return client.get('/api/auth/oauth-pending-registration');
    },

    async finalizeOAuthRegistration(username: string, tosAccepted: boolean): Promise<ApiResponse<UserProfile>> {
      client.resetLogoutState();
      return client.request('/api/auth/finalize-oauth-registration', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, tos_accepted: tosAccepted }),
      }, false);
    },

    async getOAuthAccounts(): Promise<ApiResponse<OAuthAccount[]>> {
      return client.get('/api/user/oauth-accounts');
    },

    async unlinkOAuthAccount(provider: string): Promise<ApiResponse<{ message: string }>> {
      return client.request(`/api/user/oauth-accounts/${provider}`, { method: 'DELETE' });
    },

    async getPasskeys(): Promise<ApiResponse<PasskeyInfo[]>> {
      return client.get('/api/user/passkeys');
    },

    async getPasskeyRegisterOptions(): Promise<ApiResponse<PasskeyRegisterOptionsResponse>> {
      return client.post('/api/user/passkeys/register-options');
    },

    async verifyPasskeyRegistration(credential: unknown, name?: string): Promise<ApiResponse<PasskeyInfo>> {
      return client.post('/api/user/passkeys/register-verify', { credential, name });
    },

    async renamePasskey(id: number, name: string): Promise<ApiResponse<{ id: number; name: string }>> {
      return client.patch(`/api/user/passkeys/${id}`, { name });
    },

    async deletePasskey(id: number): Promise<ApiResponse<{ message: string }>> {
      return client.delete(`/api/user/passkeys/${id}`);
    },

    async getPasskeyAuthOptions(): Promise<ApiResponse<PasskeyAuthOptionsResponse>> {
      return client.post('/api/auth/passkey/authenticate-options');
    },

    async verifyPasskeyAuth(credential: unknown, challengeKey: string): Promise<ApiResponse<UserProfile & { token_expires_at?: number }>> {
      client.resetLogoutState();
      return client.request('/api/auth/passkey/authenticate-verify', {
        method: 'POST',
        body: JSON.stringify({ credential, challengeKey }),
      }, false);
    },
  };
}
