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

function getResponseStatus(value: unknown): number | null {
  if (!value || typeof value !== 'object') {
    return null
  }
  const maybeStatus = (value as { status?: unknown }).status
  return typeof maybeStatus === 'number' ? maybeStatus : null
}

function isAuthStatus(status: number | null): boolean {
  return status === 401 || status === 403
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms)
  })
}

export function useSessionBootstrap({
  initialAuth,
  setUser,
  setAccessExpiry,
  setIsLoading,
  setIsReady,
}: UseSessionBootstrapParams) {
  useEffect(() => {
    let cancelled = false

    const loadSession = async () => {
      try {
        if (initialAuth?.user) {
          if (cancelled) {
            return
          }
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
          if (cancelled) {
            return
          }
          setUser(null)
          setIsLoading(false)
          setIsReady(true)
          return
        }

        const maxAttempts = 3
        let me: Awaited<ReturnType<typeof apiClient.getUserProfile>> | null = null
        for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
          if (cancelled) {
            return
          }
          me = await apiClient.getUserProfile({ allowRefresh: hasSessionFlag || isOAuthCallback })
          const status = getResponseStatus(me)
          const terminalFailure = isAuthStatus(status) || status === 429 || attempt === maxAttempts
          if (me.success || terminalFailure) {
            break
          }
          await delay(attempt * 250)
        }

        if (cancelled || !me) {
          return
        }

        if (me.success && me.data) {
          setUser(me.data)
          if (typeof window !== 'undefined') {
            localStorage.setItem('has_session', 'true')
          }
        } else {
          const status = getResponseStatus(me)
          const isRateLimited = status === 429
          const isAuthFailure = isAuthStatus(status)
          setUser(null)
          if (typeof window !== 'undefined' && isAuthFailure) {
            localStorage.removeItem('has_session')
          }
          if (!isAuthFailure && !isRateLimited) {
            logger.warn('Transient session bootstrap failure; keeping session flag', {
              status,
              message: me.message,
              error: me.error,
            })
          }
        }
      } catch (err) {
        if (cancelled) {
          return
        }
        setUser(null)
        logger.error('Session load error:', err)
      } finally {
        if (cancelled) {
          return
        }
        setIsLoading(false)
        setIsReady(true)
      }
    }

    void loadSession()

    return () => {
      cancelled = true
    }
  }, [initialAuth, setAccessExpiry, setIsLoading, setIsReady, setUser])
}
