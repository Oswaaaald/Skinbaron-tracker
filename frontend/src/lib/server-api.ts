import 'server-only'
import { cookies } from 'next/headers'
import { ACCESS_COOKIE, REFRESH_COOKIE } from './auth-cookies'

const API_BASE_URL = process.env['NEXT_PUBLIC_API_URL'] || 'http://localhost:8080'

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

async function fetchWithAuth(path: string, init: RequestInit = {}) {
  const cookieStore = await cookies()
  const access = cookieStore.get(ACCESS_COOKIE)?.value

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
