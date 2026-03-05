'use client'

import { useCallback } from 'react'
import type { QueryClient } from '@tanstack/react-query'
import { apiClient, ApiError } from '@/lib/api'
import { logger } from '@/lib/logger'
import type { User } from '@/contexts/auth-context.types'

type UseAuthActionsParams = {
  setUser: (user: User | null) => void
  setAccessExpiry: (expiry: number | null) => void
  setIsReady: (ready: boolean) => void
  queryClient: QueryClient
}

export function useAuthActions({ setUser, setAccessExpiry, setIsReady, queryClient }: UseAuthActionsParams) {
  const login = useCallback(async (email: string, password: string, totpCode?: string): Promise<{
    success: boolean
    error?: string
    requires2FA?: boolean
    restrictionExpiresAt?: string
  }> => {
    try {
      const data = await apiClient.login(email, password, totpCode)

      if (data.success && data.data) {
        if (data.data.requires_2fa) {
          return { success: false, requires2FA: true }
        }

        const { token_expires_at: exp, requires_2fa: _r2fa, ...userData } = data.data
        setUser(userData)
        setAccessExpiry(exp ?? null)
        setIsReady(true)

        if (typeof window !== 'undefined') {
          localStorage.setItem('has_session', 'true')
        }
        return { success: true, requires2FA: false }
      }

      return {
        success: false,
        requires2FA: false,
        error: data.message || data.error || 'Login failed',
        restrictionExpiresAt: (data.details as { data?: { restriction_expires_at?: string } } | undefined)?.data?.restriction_expires_at,
      }
    } catch (error) {
      const message = error instanceof ApiError ? error.message : 'Network error. Please try again.'
      logger.error('Login error:', error)
      return { success: false, requires2FA: false, error: message }
    }
  }, [setAccessExpiry, setIsReady, setUser])

  const register = useCallback(async (username: string, email: string, password: string) => {
    try {
      const data = await apiClient.register(username, email, password)

      if (data.success) {
        if (data.data?.pending_approval) {
          return {
            success: true,
            error: data.message || 'Registration successful! Your account is awaiting admin approval.',
          }
        }

        const tokenExpiresAt = data.data?.token_expires_at ?? null
        if (tokenExpiresAt) {
          setAccessExpiry(tokenExpiresAt)
        }

        if (
          data.data?.id &&
          data.data.username &&
          data.data.email &&
          typeof data.data.is_admin === 'boolean' &&
          typeof data.data.is_super_admin === 'boolean' &&
          typeof data.data.use_gravatar === 'boolean' &&
          typeof data.data.has_password === 'boolean' &&
          'avatar_url' in data.data
        ) {
          setUser({
            id: data.data.id,
            username: data.data.username,
            email: data.data.email,
            avatar_url: data.data.avatar_url ?? null,
            is_admin: data.data.is_admin,
            is_super_admin: data.data.is_super_admin,
            use_gravatar: data.data.use_gravatar,
            has_password: data.data.has_password,
          })
        } else {
          const me = await apiClient.getUserProfile({ allowRefresh: true })
          if (me.success && me.data) {
            setUser(me.data)
          }
        }

        if (typeof window !== 'undefined') {
          localStorage.setItem('has_session', 'true')
        }
        return { success: true }
      }

      return {
        success: false,
        error: data.message || data.error || 'Registration failed',
      }
    } catch (error) {
      const message = error instanceof ApiError ? error.message : 'Network error. Please try again.'
      logger.error('Registration error:', error)
      return { success: false, error: message }
    }
  }, [setAccessExpiry, setUser])

  const logout = useCallback(async () => {
    try {
      await apiClient.logout()
    } catch {
      // Best-effort logout
    }

    setUser(null)
    setAccessExpiry(null)
    setIsReady(true)
    queryClient.clear()

    try {
      if (typeof window !== 'undefined') {
        localStorage.removeItem('has_session')
      }
    } catch {
      // localStorage unavailable
    }
  }, [queryClient, setAccessExpiry, setIsReady, setUser])

  return { login, register, logout }
}
