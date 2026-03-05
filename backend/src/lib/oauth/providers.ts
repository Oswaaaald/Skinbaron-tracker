import { Google, GitHub, Discord, generateState, generateCodeVerifier } from 'arctic';
import { appConfig } from '../config.js';

export type OAuthProviderName = 'google' | 'github' | 'discord';

export interface OAuthUserInfo {
  id: string;
  email: string;
  emailVerified: boolean;
  name?: string;
  avatar?: string;
}

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

const providers = new Map<OAuthProviderName, ProviderAdapter>();
const providerScopes = new Map<OAuthProviderName, string[]>();

function buildCallbackUrl(provider: OAuthProviderName): string {
  return `${appConfig.NEXT_PUBLIC_API_URL}/api/auth/oauth/${provider}/callback`;
}

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

export function getEnabledProviders(): OAuthProviderName[] {
  return Array.from(providers.keys());
}

export function isProviderEnabled(provider: string): provider is OAuthProviderName {
  return providers.has(provider as OAuthProviderName);
}

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

  const userResponse = await fetch('https://api.github.com/user', { headers });
  if (!userResponse.ok) throw new Error('Failed to fetch GitHub user info');

  const userData = await userResponse.json() as {
    id: number;
    login: string;
    name?: string;
    avatar_url?: string;
    email?: string;
  };

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
    // /user/emails endpoint may be unavailable if GitHub app lacks permissions.
  }

  if (!email && userData.email) {
    email = userData.email;
    emailVerified = true;
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
