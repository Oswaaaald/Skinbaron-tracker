import 'server-only'
import { cookies } from 'next/headers'
import { ACCESS_COOKIE, REFRESH_COOKIE } from './auth-cookies'

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080'

function decodeExpiry(token: string | undefined): number | null {
  if (!token) return null
  try {
    const [, payload] = token.split('.')
    if (!payload) return null
    const data = JSON.parse(Buffer.from(payload, 'base64').toString())
    if (data?.exp) return data.exp * 1000
  } catch (_err) {
    return null
  }
  return null
}

async function setCookie(name: string, value: string, expiresAt: number | null) {
  const store = await cookies()
  store.set(name, value, {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    secure: process.env.NODE_ENV === 'production',
    expires: expiresAt ? new Date(expiresAt) : undefined,
  })
}

async function clearCookie(name: string) {
  const store = await cookies()
  store.set(name, '', {
    httpOnly: true,
    sameSite: 'lax',
    path: '/',
    secure: process.env.NODE_ENV === 'production',
    expires: new Date(0),
  })
}

async function refreshWithCookie(refreshToken: string) {
  const response = await fetch(`${API_BASE_URL}/api/auth/refresh`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh_token: refreshToken }),
    cache: 'no-store',
  })

  if (!response.ok) return null
  const data = await response.json()
  if (!data?.success) return null

  const setCookieHeaders: string[] =
    // Next.js/undici
    (response.headers as any).getSetCookie?.() ||
    // node-fetch style
    (response.headers as any).raw?.()['set-cookie'] ||
    // fallback single header
    (response.headers.get('set-cookie') ? [response.headers.get('set-cookie') as string] : [])

  let accessToken: string | undefined
  let refreshTok: string | undefined

  for (const cookieStr of setCookieHeaders) {
    const accessMatch = cookieStr.match(/sb_access=([^;]+)/)
    const refreshMatch = cookieStr.match(/sb_refresh=([^;]+)/)
    if (accessMatch) accessToken = accessMatch[1]
    if (refreshMatch) refreshTok = refreshMatch[1]
  }

  // If backend didn’t set cookies (shouldn’t happen), fall back to body tokens if present
  const token = accessToken || data?.data?.token
  const refreshBody = refreshTok || data?.data?.refresh_token

  if (!token || !refreshBody) return null

  const accessExp = data?.data?.token_expires_at ?? decodeExpiry(token)
  const refreshExp = decodeExpiry(refreshBody)

  await setCookie(ACCESS_COOKIE, token, accessExp ?? null)
  await setCookie(REFRESH_COOKIE, refreshBody, refreshExp ?? null)

  return {
    token,
    refreshToken: refreshBody,
    accessExpiresAt: accessExp,
    refreshExpiresAt: refreshExp,
  }
}

async function fetchWithAuth(path: string, init: RequestInit = {}) {
  const cookieStore = await cookies()
  const access = cookieStore.get(ACCESS_COOKIE)?.value
  const refresh = cookieStore.get(REFRESH_COOKIE)?.value

  const doFetch = async (token?: string) => {
    const headers = new Headers(init.headers as HeadersInit)
    if (token) headers.set('Authorization', `Bearer ${token}`)

    return fetch(`${API_BASE_URL}${path}`, {
      ...init,
      headers,
      cache: 'no-store',
    })
  }

  let res = await doFetch(access)
  if ((res.status === 401 || res.status === 403) && refresh) {
    const refreshed = await refreshWithCookie(refresh)
    if (refreshed?.token) {
      res = await doFetch(refreshed.token)
    }
  }

  return res
}

export async function getServerSession() {
  const cookieStore = await cookies()
  const access = cookieStore.get(ACCESS_COOKIE)?.value
  const refresh = cookieStore.get(REFRESH_COOKIE)?.value

  if (!access && !refresh) return null

  let tokenToUse = access
  let refreshToUse = refresh

  let res = await fetchWithAuth('/api/auth/me', { method: 'GET' })

  if (res.status === 401 || res.status === 403) {
    // Attempted refresh already inside fetchWithAuth, but if still unauthorized, clear
    await clearCookie(ACCESS_COOKIE)
    await clearCookie(REFRESH_COOKIE)
    return null
  }

  const data = await res.json()
  if (!data?.success || !data?.data) {
    return null
  }

  // If token was refreshed, pick latest cookies
  const refreshedStore = await cookies()
  const newAccess = refreshedStore.get(ACCESS_COOKIE)?.value
  const newRefresh = refreshedStore.get(REFRESH_COOKIE)?.value
  if (newAccess) tokenToUse = newAccess
  if (newRefresh) refreshToUse = newRefresh

  if (!tokenToUse) return null

  return {
    user: data.data as {
      id: number
      username: string
      email: string
      avatar_url?: string
      is_admin?: boolean
      is_super_admin?: boolean
    },
    token: tokenToUse,
    refreshToken: refreshToUse ?? null,
    expiresAt: decodeExpiry(tokenToUse) || null,
    refreshExpiresAt: decodeExpiry(refreshToUse || undefined) || null,
  }
}

export { ACCESS_COOKIE, REFRESH_COOKIE }
