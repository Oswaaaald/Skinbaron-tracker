export type AdminRateLimitConfig = {
  max: number;
  timeWindow: string;
  errorResponseBuilder: () => {
    statusCode: number;
    success: boolean;
    error: string;
    message: string;
  };
};

export type RegisterAdminRouteOptions = {
  adminWriteRateLimit: AdminRateLimitConfig;
};
