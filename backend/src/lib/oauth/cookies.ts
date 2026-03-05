import { encryptCookie, decryptCookie } from '../../database/utils/encryption.js';

export const OAUTH_STATE_COOKIE = 'sb_oauth_state';
export const OAUTH_2FA_COOKIE = 'sb_oauth_2fa';
export const OAUTH_PENDING_REG_COOKIE = 'sb_oauth_pending_reg';

const STATE_TTL_MS = 10 * 60 * 1000; // 10 minutes
const PENDING_2FA_TTL_MS = 5 * 60 * 1000; // 5 minutes
const PENDING_REG_TTL_MS = 10 * 60 * 1000; // 10 minutes

export function encryptOAuthState(state: string, codeVerifier: string, linkUserId?: number, mode?: string): string {
  const payload = JSON.stringify({
    state,
    codeVerifier,
    exp: Date.now() + STATE_TTL_MS,
    ...(linkUserId != null && { linkUserId }),
    ...(mode && { mode }),
  });
  return encryptCookie(payload);
}

export function decryptOAuthState(cookieValue: string): { state: string; codeVerifier: string; linkUserId?: number; mode?: string } {
  const decrypted = decryptCookie(cookieValue);
  const payload = JSON.parse(decrypted) as { state: string; codeVerifier: string; exp: number; linkUserId?: number; mode?: string };

  if (Date.now() > payload.exp) {
    throw new Error('OAuth state has expired');
  }

  return {
    state: payload.state,
    codeVerifier: payload.codeVerifier,
    linkUserId: payload.linkUserId,
    mode: payload.mode,
  };
}

export function encryptOAuth2FAPending(userId: number, provider: string): string {
  const payload = JSON.stringify({ userId, provider, exp: Date.now() + PENDING_2FA_TTL_MS });
  return encryptCookie(payload);
}

export function decryptOAuth2FAPending(cookieValue: string): { userId: number; provider: string } {
  const decrypted = decryptCookie(cookieValue);
  const payload = JSON.parse(decrypted) as { userId: number; provider: string; exp: number };

  if (Date.now() > payload.exp) {
    throw new Error('OAuth 2FA challenge has expired');
  }

  return { userId: payload.userId, provider: payload.provider };
}

export function encryptOAuthPendingRegistration(data: {
  provider: string;
  providerAccountId: string;
  email: string;
  suggestedUsername: string;
}): string {
  const payload = JSON.stringify({ ...data, exp: Date.now() + PENDING_REG_TTL_MS });
  return encryptCookie(payload);
}

export function decryptOAuthPendingRegistration(cookieValue: string): {
  provider: string;
  providerAccountId: string;
  email: string;
  suggestedUsername: string;
} {
  const decrypted = decryptCookie(cookieValue);
  const payload = JSON.parse(decrypted) as {
    provider: string;
    providerAccountId: string;
    email: string;
    suggestedUsername: string;
    exp: number;
  };

  if (Date.now() > payload.exp) {
    throw new Error('OAuth registration session has expired');
  }

  return {
    provider: payload.provider,
    providerAccountId: payload.providerAccountId,
    email: payload.email,
    suggestedUsername: payload.suggestedUsername,
  };
}
