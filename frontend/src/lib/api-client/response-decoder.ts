import type { ApiResponse } from '../api-types'

export async function decodeJsonResponse(response: Response, url: string, method: string): Promise<unknown> {
  try {
    return await response.json()
  } catch {
    throw new Error(`Invalid JSON response (status ${response.status}) for ${method} ${url}`)
  }
}

export function normalizeSuccessResponse<T>(raw: unknown, status: number): ApiResponse<T> {
  if (!raw || typeof raw !== 'object') {
    return {
      success: false,
      error: 'Unexpected API response format',
      message: 'Unexpected API response format',
      details: raw,
      status,
    }
  }

  const parsed = raw as Partial<ApiResponse<T>>
  if (typeof parsed.success !== 'boolean') {
    return {
      success: false,
      error: 'Invalid API response contract: missing success flag',
      message: 'Invalid API response contract',
      details: raw,
      status,
    }
  }

  return { ...(parsed as ApiResponse<T>), status: parsed.status ?? status }
}

export function buildErrorResponse<T>(status: number, data: unknown): ApiResponse<T> {
  const errorPayload =
    data && typeof data === 'object'
      ? (data as { message?: string; error?: string })
      : undefined
  const message = errorPayload?.message || errorPayload?.error || `HTTP ${status}`

  return {
    success: false,
    error: message,
    message,
    details: data,
    status,
  }
}
