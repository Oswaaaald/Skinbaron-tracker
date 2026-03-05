export type SecurityRateLimitConfig = {
  max: number;
  timeWindow: string;
  errorResponseBuilder: () => {
    statusCode: number;
    success: boolean;
    error: string;
    message: string;
  };
};

export type RegisterUserSecurityRoutesOptions = {
  sensitiveOperationRateLimit: SecurityRateLimitConfig;
};

// TTL constants for pending challenges (stored in PostgreSQL)
export const PENDING_2FA_TTL = 10 * 60 * 1000; // 10 minutes
export const WEBAUTHN_CHALLENGE_TTL = 5 * 60 * 1000; // 5 minutes
