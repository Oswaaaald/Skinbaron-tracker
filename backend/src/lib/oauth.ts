import { Google, GitHub, Discord, generateState, generateCodeVerifier } from 'arctic';
import crypto from 'crypto';
import { appConfig } from './config.js';

// ==================== Types ====================

export type OAuthProviderName = 'google' | 'github' | 'discord';

export interface OAuthUserInfo {
  id: string;
  email: string;
  emailVerified: boolean;
  name?: string;
  avatar?: string;
}

/**
 * Unified wrapper that abstracts PKCE vs non-PKCE providers.
 * GitHub does not support PKCE; Google and Discord do.
 */
interface ProviderAdapter {
  createAuthorizationURL(state: string, codeVerifier: string, scopes: string[]): URL;
  validateAuthorizationCode(code: string, codeVerifier: string): Promise<string>;
}

function wrapPKCE(provider: Google | Discord): ProviderAdapter {
  return {
    createAuthorizationURL: (state, codeVerifier, scopes) =>
      provider.createAuthorizationURL(state, codeVerifier, scopes),
    validateAuthorizationCode: async (code, codeVerifier) => {
      const tokens = await provider.validateAuthorizationCode(code, codeVerifier);
      return tokens.accessToken();
    },
  };
}

function wrapNonPKCE(provider: GitHub): ProviderAdapter {
  return {
    createAuthorizationURL: (state, _codeVerifier, scopes) =>
      provider.createAuthorizationURL(state, scopes),
    validateAuthorizationCode: async (code, _codeVerifier) => {
      const tokens = await provider.validateAuthorizationCode(code);
      return tokens.accessToken();
    },
  };
}

// ==================== Provider registry ====================

const providers = new Map<OAuthProviderName, ProviderAdapter>();
const providerScopes = new Map<OAuthProviderName, string[]>();

function buildCallbackUrl(provider: OAuthProviderName): string {
  return `${appConfig.NEXT_PUBLIC_API_URL}/api/auth/oauth/${provider}/callback`;
}

/**
 * Initialize OAuth providers based on configured env vars.
 * Only providers with both client ID and secret are enabled.
 */
export function initOAuthProviders(): void {
  if (appConfig.GOOGLE_CLIENT_ID && appConfig.GOOGLE_CLIENT_SECRET) {
    providers.set('google', wrapPKCE(new Google(
      appConfig.GOOGLE_CLIENT_ID,
      appConfig.GOOGLE_CLIENT_SECRET,
      buildCallbackUrl('google'),
    )));
    providerScopes.set('google', ['openid', 'email', 'profile']);
  }

  if (appConfig.GITHUB_CLIENT_ID && appConfig.GITHUB_CLIENT_SECRET) {
    providers.set('github', wrapNonPKCE(new GitHub(
      appConfig.GITHUB_CLIENT_ID,
      appConfig.GITHUB_CLIENT_SECRET,
      buildCallbackUrl('github'),
    )));
    providerScopes.set('github', ['user:email', 'read:user']);
  }

  if (appConfig.DISCORD_CLIENT_ID && appConfig.DISCORD_CLIENT_SECRET) {
    providers.set('discord', wrapPKCE(new Discord(
      appConfig.DISCORD_CLIENT_ID,
      appConfig.DISCORD_CLIENT_SECRET,
      buildCallbackUrl('discord'),
    )));
    providerScopes.set('discord', ['identify', 'email']);
  }
}

/**
 * Get list of enabled OAuth providers
 */
export function getEnabledProviders(): OAuthProviderName[] {
  return Array.from(providers.keys());
}

/**
 * Check if a provider is enabled
 */
export function isProviderEnabled(provider: string): provider is OAuthProviderName {
  return providers.has(provider as OAuthProviderName);
}

// ==================== OAuth flow helpers ====================

/**
 * Create an authorization URL for a provider.
 * Returns the URL and the state/codeVerifier to store in a cookie.
 */
export function createAuthorizationUrl(provider: OAuthProviderName): {
  url: URL;
  state: string;
  codeVerifier: string;
} {
  const instance = providers.get(provider);
  if (!instance) throw new Error(`OAuth provider ${provider} is not configured`);

  const state = generateState();
  const codeVerifier = generateCodeVerifier();
  const scopes = providerScopes.get(provider) ?? [];
  const url = instance.createAuthorizationURL(state, codeVerifier, scopes);

  return { url, state, codeVerifier };
}

/**
 * Exchange an authorization code for user information.
 */
export async function exchangeCodeForUser(
  provider: OAuthProviderName,
  code: string,
  codeVerifier: string,
): Promise<OAuthUserInfo> {
  const instance = providers.get(provider);
  if (!instance) throw new Error(`OAuth provider ${provider} is not configured`);

  const accessToken = await instance.validateAuthorizationCode(code, codeVerifier);

  switch (provider) {
    case 'google':
      return fetchGoogleUser(accessToken);
    case 'github':
      return fetchGitHubUser(accessToken);
    case 'discord':
      return fetchDiscordUser(accessToken);
  }
}

// ==================== Provider-specific user info fetchers ====================

async function fetchGoogleUser(accessToken: string): Promise<OAuthUserInfo> {
  const response = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!response.ok) throw new Error('Failed to fetch Google user info');

  const data = await response.json() as {
    sub: string;
    email: string;
    email_verified: boolean;
    name?: string;
    picture?: string;
  };

  return {
    id: data.sub,
    email: data.email,
    emailVerified: data.email_verified,
    name: data.name,
    avatar: data.picture,
  };
}

async function fetchGitHubUser(accessToken: string): Promise<OAuthUserInfo> {
  const headers = {
    Authorization: `Bearer ${accessToken}`,
    Accept: 'application/json',
  };

  // Fetch user profile
  const userResponse = await fetch('https://api.github.com/user', { headers });
  if (!userResponse.ok) throw new Error('Failed to fetch GitHub user info');

  const userData = await userResponse.json() as {
    id: number;
    login: string;
    name?: string;
    avatar_url?: string;
    email?: string;
  };

  // Try to get email from /user/emails (requires "Email addresses" permission for GitHub Apps)
  let email: string | undefined;
  let emailVerified = false;

  try {
    const emailsResponse = await fetch('https://api.github.com/user/emails', { headers });
    if (emailsResponse.ok) {
      const emails = await emailsResponse.json() as Array<{
        email: string;
        primary: boolean;
        verified: boolean;
      }>;

      const primaryEmail = emails.find(e => e.primary && e.verified);
      const verifiedEmail = primaryEmail ?? emails.find(e => e.verified);

      if (verifiedEmail) {
        email = verifiedEmail.email;
        emailVerified = verifiedEmail.verified;
      }
    }
  } catch {
    // /user/emails endpoint not available (GitHub App missing "Email addresses" permission)
  }

  // Fallback: use email from user profile (may be null if user set it to private)
  if (!email && userData.email) {
    email = userData.email;
    emailVerified = true; // GitHub only shows verified emails on profiles
  }

  if (!email) {
    throw new Error(
      'No email found on your GitHub account. Make sure your GitHub email is public, ' +
      'or ask the administrator to enable "Email addresses" permission on the GitHub App.',
    );
  }

  return {
    id: String(userData.id),
    email,
    emailVerified,
    name: userData.name ?? userData.login,
    avatar: userData.avatar_url,
  };
}

async function fetchDiscordUser(accessToken: string): Promise<OAuthUserInfo> {
  const response = await fetch('https://discord.com/api/v10/users/@me', {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!response.ok) throw new Error('Failed to fetch Discord user info');

  const data = await response.json() as {
    id: string;
    username: string;
    global_name?: string;
    email?: string;
    verified?: boolean;
    avatar?: string;
  };

  if (!data.email) {
    throw new Error('No email found on your Discord account. Please add an email to your Discord account first.');
  }

  return {
    id: data.id,
    email: data.email,
    emailVerified: data.verified ?? false,
    name: data.global_name ?? data.username,
    avatar: data.avatar
      ? `https://cdn.discordapp.com/avatars/${data.id}/${data.avatar}.png`
      : undefined,
  };
}

// ==================== State cookie encryption ====================

const OAUTH_STATE_COOKIE = 'sb_oauth_state';
const STATE_TTL_MS = 10 * 60 * 1000; // 10 minutes

/**
 * Encrypt OAuth state (state + codeVerifier) into a cookie value.
 * Uses AES-256-GCM with the encryption key.
 */
export function encryptOAuthState(state: string, codeVerifier: string): string {
  const payload = JSON.stringify({ state, codeVerifier, exp: Date.now() + STATE_TTL_MS });
  const key = crypto.createHash('sha256').update(appConfig.ENCRYPTION_KEY).digest();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(payload, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString('base64url');
}

/**
 * Decrypt and validate OAuth state cookie value.
 * Throws if expired, tampered, or invalid.
 */
export function decryptOAuthState(cookieValue: string): { state: string; codeVerifier: string } {
  const buf = Buffer.from(cookieValue, 'base64url');
  const key = crypto.createHash('sha256').update(appConfig.ENCRYPTION_KEY).digest();
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const encrypted = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]).toString('utf8');
  const payload = JSON.parse(decrypted) as { state: string; codeVerifier: string; exp: number };

  if (Date.now() > payload.exp) {
    throw new Error('OAuth state has expired');
  }

  return { state: payload.state, codeVerifier: payload.codeVerifier };
}

export { OAUTH_STATE_COOKIE };
