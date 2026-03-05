import type { FastifyReply } from 'fastify';

export type AuthRateLimitConfig = {
  max: number;
  timeWindow: string;
  errorResponseBuilder: () => {
    statusCode: number;
    success: boolean;
    error: string;
    message: string;
  };
};

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
