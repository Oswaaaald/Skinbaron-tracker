export function isMutatingMethod(method: string | undefined): boolean {
  return ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method || 'GET')
}

export function isCsrfError(status: number, code?: string): boolean {
  return status === 403 && Boolean(code?.startsWith('CSRF_TOKEN_'))
}

function isAuthEndpoint(endpoint: string): boolean {
  return (
    endpoint.startsWith('/api/auth/login') ||
    endpoint.startsWith('/api/auth/register')
  )
}

export function shouldAttemptTokenRefresh(endpoint: string, status: number, allowRefresh: boolean): boolean {
  return !isAuthEndpoint(endpoint) && status === 401 && allowRefresh
}
