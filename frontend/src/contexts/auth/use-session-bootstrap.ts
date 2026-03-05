'use client'

import { useEffect } from 'react'
import { apiClient } from '@/lib/api'
import { logger } from '@/lib/logger'
import type { InitialAuthState, User } from '@/contexts/auth-context.types'

type UseSessionBootstrapParams = {
  initialAuth?: InitialAuthState | null
  setUser: (user: User | null) => void
  setAccessExpiry: (expiry: number | null) => void
  setIsLoading: (value: boolean) => void
  setIsReady: (value: boolean) => void
}

export function useSessionBootstrap({
  initialAuth,
  setUser,
  setAccessExpiry,
  setIsLoading,
  setIsReady,
}: UseSessionBootstrapParams) {
  useEffect(() => {
    const loadSession = async () => {
      try {
        if (initialAuth?.user) {
          setUser(initialAuth.user)
          setAccessExpiry(initialAuth.expiresAt ?? null)
          setIsLoading(false)
          setIsReady(true)
          return
        }

        const hasSessionFlag = typeof window !== 'undefined' && localStorage.getItem('has_session') === 'true'
        const isOAuthCallback = typeof window !== 'undefined' && new URLSearchParams(window.location.search).get('oauth') === 'success'

        if (isOAuthCallback && typeof window !== 'undefined') {
          const url = new URL(window.location.href)
          url.searchParams.delete('oauth')
          window.history.replaceState({}, '', url.pathname + url.search)
          localStorage.setItem('has_session', 'true')
        }

        if (!hasSessionFlag && !isOAuthCallback) {
          setUser(null)
          setIsLoading(false)
          setIsReady(true)
          return
        }

        const me = await apiClient.getUserProfile({ allowRefresh: hasSessionFlag || isOAuthCallback })
        if (me.success && me.data) {
          setUser(me.data)
          if (typeof window !== 'undefined') {
            localStorage.setItem('has_session', 'true')
          }
        } else {
          const isRateLimited = (me as { status?: number }).status === 429
          setUser(null)
          if (typeof window !== 'undefined' && !isRateLimited) {
            localStorage.removeItem('has_session')
          }
        }
      } catch (err) {
        setUser(null)
        logger.error('Session load error:', err)
      } finally {
        setIsLoading(false)
        setIsReady(true)
      }
    }

    void loadSession()
  }, [initialAuth, setAccessExpiry, setIsLoading, setIsReady, setUser])
}
