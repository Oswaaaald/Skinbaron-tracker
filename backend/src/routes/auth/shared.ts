import type { FastifyReply } from 'fastify';
import type { RateLimitConfig } from '../../lib/rate-limit.js';

export type AuthRateLimitConfig = RateLimitConfig;

export type AccessToken = {
  token: string;
  expiresAt: number;
};

export type RefreshToken = {
  token: string;
  expiresAt: number;
};

export type SetAuthCookies = (
  reply: FastifyReply,
  accessToken: AccessToken,
  refreshToken: RefreshToken,
) => void;

export type AuthRoutesContext = {
  authRateLimitConfig: AuthRateLimitConfig;
  setAuthCookies: SetAuthCookies;
};
