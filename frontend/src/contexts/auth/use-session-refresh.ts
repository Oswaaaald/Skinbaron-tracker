'use client'

import { useEffect } from 'react'
import { apiClient } from '@/lib/api'
import type { User } from '@/contexts/auth-context.types'

type UseSessionRefreshParams = {
  user: User | null
  accessExpiry: number | null
  setUser: (user: User | null) => void
  setAccessExpiry: (expiry: number | null) => void
}

export function useSessionRefresh({ user, accessExpiry, setUser, setAccessExpiry }: UseSessionRefreshParams) {
  useEffect(() => {
    if (!user || !accessExpiry) return

    const now = Date.now()
    const msToRefresh = Math.max(accessExpiry - now - 60_000, 0)

    const timer = setTimeout(() => {
      void (async () => {
        try {
          const refreshed = await apiClient.tryRefreshToken()
          if (refreshed.success && refreshed.expiresAt) {
            setAccessExpiry(refreshed.expiresAt)
          } else if (!refreshed.success) {
            setUser(null)
            setAccessExpiry(null)
          }
        } catch {
          setUser(null)
          setAccessExpiry(null)
        }
      })()
    }, msToRefresh)

    return () => clearTimeout(timer)
  }, [accessExpiry, setAccessExpiry, setUser, user])
}
