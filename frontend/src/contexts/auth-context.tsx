'use client'

import { createContext, useCallback, useEffect, useMemo, useState, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { apiClient } from '@/lib/api'
import type { AuthContextType, InitialAuthState, User } from './auth-context.types'
import { useAuthActions } from './auth/use-auth-actions'
import { useFocusProfileSync } from './auth/use-focus-profile-sync'
import { useSessionBootstrap } from './auth/use-session-bootstrap'
import { useSessionRefresh } from './auth/use-session-refresh'

export type { AuthContextType, InitialAuthState, User } from './auth-context.types'

export const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children, initialAuth }: { children: ReactNode; initialAuth?: InitialAuthState | null }) {
  const [user, setUser] = useState<User | null>(initialAuth?.user ?? null)
  const [isLoading, setIsLoading] = useState(true)
  const [isReady, setIsReady] = useState(false)
  const [accessExpiry, setAccessExpiry] = useState<number | null>(initialAuth?.expiresAt ?? null)

  const isAuthenticated = !!user
  const queryClient = useQueryClient()

  const updateUser = useCallback((userData: Partial<User>) => {
    setUser((prev) => (prev ? { ...prev, ...userData } : null))
  }, [])

  useSessionBootstrap({ initialAuth, setUser, setAccessExpiry, setIsLoading, setIsReady })
  useFocusProfileSync({ user, updateUser })
  useSessionRefresh({ user, accessExpiry, setUser, setAccessExpiry })

  const { login, register, logout } = useAuthActions({
    setUser,
    setAccessExpiry,
    setIsReady,
    queryClient,
  })

  // Register API-client callbacks once the provider is mounted
  useEffect(() => {
    apiClient.setLogoutCallback(() => {
      setUser(null)
      setAccessExpiry(null)
      queryClient.clear()
      try {
        localStorage.removeItem('has_session')
      } catch {
        // ignore localStorage failures
      }
    })

    apiClient.setRefreshCallback((expiresAt: number) => {
      setAccessExpiry(expiresAt)
    })

    return () => {
      apiClient.setLogoutCallback(() => {})
      apiClient.setRefreshCallback(() => {})
    }
  }, [queryClient])

  const contextValue = useMemo<AuthContextType>(() => ({
    user,
    isLoading,
    isAuthenticated,
    isReady,
    login,
    register,
    logout,
    updateUser,
  }), [user, isLoading, isAuthenticated, isReady, login, register, logout, updateUser])

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  )
}

export { useAuth } from './use-auth'
