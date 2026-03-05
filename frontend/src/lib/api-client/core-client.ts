import { logger } from '../logger'
import type { ApiResponse } from '../api-types'

const API_BASE_URL = process.env['NEXT_PUBLIC_API_URL'] || ''

export class ApiError extends Error {
  status: number
  body: unknown
  url: string
  method: string

  constructor(message: string, status: number, url: string, method: string, body: unknown) {
    super(message)
    this.status = status
    this.body = body
    this.url = url
    this.method = method
  }
}

export class CoreApiClient {
  private baseURL: string
  private onLogout: (() => void) | null = null
  private onRefresh: ((expiresAt: number) => void) | null = null
  private refreshPromise: Promise<{ success: boolean; expiresAt?: number; rateLimited?: boolean }> | null = null
  private hasCalledLogout = false
  private csrfToken: string | null = null

  private static readonly REFRESH_COOLDOWN_MS = 10_000

  constructor(baseURL: string = API_BASE_URL) {
    if (!baseURL && typeof window !== 'undefined') {
      throw new Error('NEXT_PUBLIC_API_URL environment variable is required')
    }
    this.baseURL = baseURL

    if (typeof window !== 'undefined') {
      void this.initCsrfToken()
    }
  }

  private async initCsrfToken() {
    try {
      const response = await fetch(`${this.baseURL}/api/csrf-token`, {
        credentials: 'include',
      })
      if (response.ok) {
        const data = await response.json() as ApiResponse<{ csrf_token: string }>
        if (data.success && data.data?.csrf_token) {
          this.csrfToken = data.data.csrf_token
        }
      }
    } catch (error) {
      logger.warn('Failed to initialize CSRF token:', error)
    }
  }

  async ensureCsrfToken() {
    if (!this.csrfToken && typeof window !== 'undefined') {
      await this.initCsrfToken()
    }
  }

  resetLogoutState() {
    this.hasCalledLogout = false
  }

  getBaseUrl() {
    return this.baseURL
  }

  ensureSuccess<T>(response: ApiResponse<T>, fallbackMessage?: string): ApiResponse<T> {
    if (!response.success) {
      const message = response.message || response.error || fallbackMessage || 'Request failed'
      throw new Error(message)
    }
    return response
  }

  setLogoutCallback(callback: () => void) {
    this.onLogout = callback
  }

  setRefreshCallback(callback: (expiresAt: number) => void) {
    this.onRefresh = callback
  }

  async request<T>(endpoint: string, options: RequestInit = {}, allowRefresh: boolean = true): Promise<ApiResponse<T>> {
    try {
      const url = `${this.baseURL}${endpoint}`
      const headers: Record<string, string> = {}
      if (options.body && !(options.body instanceof FormData)) headers['Content-Type'] = 'application/json'

      const isMutating = ['POST', 'PUT', 'PATCH', 'DELETE'].includes(options.method || 'GET')
      if (isMutating) {
        if (!this.csrfToken) {
          await this.initCsrfToken()
        }
        if (this.csrfToken) {
          headers['x-csrf-token'] = this.csrfToken
        }
      }

      const response = await fetch(url, {
        ...options,
        headers: {
          ...headers,
          ...options.headers,
        },
        credentials: 'include',
      })

      let data: unknown = null
      try {
        data = await response.json()
      } catch {
        throw new ApiError(`Invalid JSON response (status ${response.status})`, response.status, url, options.method || 'GET', null)
      }

      if (!response.ok) {
        const errorPayload =
          data && typeof data === 'object'
            ? (data as { message?: string; error?: string; code?: string })
            : undefined
        const message = errorPayload?.message || errorPayload?.error || `HTTP ${response.status}`

        const isAuthLogin = endpoint.startsWith('/api/auth/login')
        const isAuthRegister = endpoint.startsWith('/api/auth/register')
        const isAuthLogout = endpoint.startsWith('/api/auth/logout')

        const isCsrfError = response.status === 403 && errorPayload?.code?.startsWith('CSRF_TOKEN_')
        if (isCsrfError && allowRefresh) {
          await this.initCsrfToken()
          return this.request<T>(endpoint, options, false)
        }

        const shouldAttemptRefresh =
          !isAuthLogin &&
          !isAuthRegister &&
          !isAuthLogout &&
          response.status === 401 &&
          allowRefresh

        if (shouldAttemptRefresh) {
          const refreshResult = await this.tryRefreshToken()
          if (refreshResult.success) {
            if (this.onRefresh && refreshResult.expiresAt) {
              this.onRefresh(refreshResult.expiresAt)
            }
            this.hasCalledLogout = false
            return this.request<T>(endpoint, options, false)
          }
          if (refreshResult.rateLimited) {
            return {
              success: false,
              error: 'Rate limited — please wait a moment',
              message: 'Rate limited — please wait a moment',
              status: 429,
            }
          }
          if (this.onLogout && !this.hasCalledLogout) {
            this.hasCalledLogout = true
            this.onLogout()
          }
        }

        return {
          success: false,
          error: message,
          message,
          details: data,
          status: response.status,
        }
      }

      if (!data || typeof data !== 'object') {
        return {
          success: false,
          error: 'Unexpected API response format',
          message: 'Unexpected API response format',
          details: data,
          status: response.status,
        }
      }

      const parsed = data as Partial<ApiResponse<T>>
      if (typeof parsed.success !== 'boolean') {
        return {
          success: false,
          error: 'Invalid API response contract: missing success flag',
          message: 'Invalid API response contract',
          details: data,
          status: response.status,
        }
      }

      return { ...(parsed as ApiResponse<T>), status: parsed.status ?? response.status }
    } catch (error) {
      const message = (error as Error).message || 'Network error'
      if (process.env.NODE_ENV === 'development') {
        logger.warn('API request failed:', message)
      }
      return { success: false, error: message, message } as ApiResponse<T>
    }
  }

  async tryRefreshToken(): Promise<{ success: boolean; expiresAt?: number; rateLimited?: boolean }> {
    if (this.refreshPromise) {
      return this.refreshPromise
    }

    if (typeof sessionStorage !== 'undefined') {
      const lastRefresh = Number(sessionStorage.getItem('_last_refresh') || '0')
      if (Date.now() - lastRefresh < CoreApiClient.REFRESH_COOLDOWN_MS) {
        return { success: false, rateLimited: true }
      }
    }

    this.refreshPromise = (async () => {
      try {
        const result = await this.request<{ token_expires_at?: number }>('/api/auth/refresh', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({}),
        }, false)
        if (result?.success) {
          try {
            sessionStorage.setItem('_last_refresh', String(Date.now()))
          } catch {
            // ignore
          }
        }
        const isRateLimited = !result?.success && (result as { status?: number })?.status === 429
        return {
          success: Boolean(result?.success),
          expiresAt: result?.data?.token_expires_at,
          rateLimited: isRateLimited,
        }
      } catch (error) {
        if (process.env.NODE_ENV === 'development') {
          logger.warn('Token refresh failed:', (error as Error).message)
        }
        return { success: false }
      } finally {
        this.refreshPromise = null
      }
    })()

    return this.refreshPromise
  }

  async get<T = unknown>(endpoint: string): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, { method: 'GET' })
  }

  async delete<T = unknown>(endpoint: string, data?: unknown): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, {
      method: 'DELETE',
      body: data ? JSON.stringify(data) : undefined,
    })
  }

  async patch<T = unknown>(endpoint: string, data?: unknown): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, {
      method: 'PATCH',
      body: data ? JSON.stringify(data) : undefined,
    })
  }

  async post<T = unknown>(endpoint: string, data?: unknown): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, {
      method: 'POST',
      body: data ? JSON.stringify(data) : undefined,
    })
  }

  async uploadFile<T = unknown>(endpoint: string, formData: FormData): Promise<ApiResponse<T>> {
    return this.request<T>(endpoint, {
      method: 'POST',
      body: formData,
    })
  }
}
