'use client'

import { createContext, useContext, useEffect, useState, ReactNode } from 'react'
import { apiClient, ApiError } from '@/lib/api'

export interface User {
  id: number
  username: string
  email: string
  avatar_url?: string
  is_admin?: boolean
  is_super_admin?: boolean
}

export interface AuthContextType {
  user: User | null
  token: string | null
  refreshToken: string | null
  isLoading: boolean
  isAuthenticated: boolean
  isReady: boolean // New flag to indicate auth state is fully initialized
  login: (email: string, password: string, totpCode?: string) => Promise<{ success: boolean; error?: string; requires2FA?: boolean }>
  register: (username: string, email: string, password: string) => Promise<{ success: boolean; error?: string }>
  logout: () => Promise<void>
  updateUser: (userData: Partial<User>) => void
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

type InitialAuthState = {
  user: User
  token: string
  refreshToken: string | null
  expiresAt: number | null
  refreshExpiresAt: number | null
}

export function AuthProvider({ children, initialAuth }: { children: ReactNode; initialAuth?: InitialAuthState | null }) {
  const [user, setUser] = useState<User | null>(initialAuth?.user ?? null)
  const [token, setToken] = useState<string | null>(null)
  const [refreshToken, setRefreshToken] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isReady, setIsReady] = useState(false)
  const [accessExpiry, setAccessExpiry] = useState<number | null>(initialAuth?.expiresAt ?? null)

  const isAuthenticated = !!user

  // Initialize auth state from server session or fetch /me if cookies exist
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

        // Don't trigger refresh/logout when no session yet
        const me = await apiClient.getUserProfile({ allowRefresh: false })
        if (me.success && me.data) {
          setUser(me.data as User)
        }
      } catch (_err) {
        setUser(null)
      } finally {
        setIsLoading(false)
        setIsReady(true)
      }
    }

    loadSession()
  }, [initialAuth])

  // Setup logout callback for when user is deleted/invalid
  useEffect(() => {
    apiClient.setLogoutCallback(() => {
      setUser(null)
      setToken(null)
      setRefreshToken(null)
      setAccessExpiry(null)
      window.location.href = '/'
    })
  }, [])

  // Keep a lightweight profile refresh on focus when authenticated
  useEffect(() => {
    if (!user) return

    const checkUserProfile = async () => {
      try {
        const response = await apiClient.getUserProfile({ allowRefresh: true })
        if (response.success && response.data) {
          updateUser({
            username: response.data.username,
            email: response.data.email,
            avatar_url: response.data.avatar_url,
            is_admin: response.data.is_admin,
            is_super_admin: response.data.is_super_admin,
          })
        }
      } catch (_error) {
        // Ignore failures; will retry on next focus
      }
    }

    const handleFocus = () => checkUserProfile()
    window.addEventListener('focus', handleFocus)
    checkUserProfile()

    return () => {
      window.removeEventListener('focus', handleFocus)
    }
  }, [user])

  const login = async (email: string, password: string, totpCode?: string): Promise<{
    success: boolean;
    error?: string;
    requires2FA?: boolean;
  }> => {
    try {
      const data = await apiClient.login(email, password, totpCode)

      if (data.success && data.data) {
        if ((data.data as any).requires_2fa) {
          return { success: false, requires2FA: true }
        }

        const { token_expires_at: _exp, ...userData } = data.data as any
        setUser(userData)
        setAccessExpiry(_exp ?? null)
        setIsReady(true)
        return { success: true, requires2FA: false }
      }

      return {
        success: false,
        requires2FA: false,
        error: data.message || data.error || 'Login failed',
      }
    } catch (error) {
      const message = error instanceof ApiError ? error.message : 'Network error. Please try again.'
      console.error('Login error:', error)
      return { success: false, requires2FA: false, error: message }
    }
  }

  const register = async (username: string, email: string, password: string) => {
    try {
      const data = await apiClient.register(username, email, password)

      if (data.success) {
        if (data.data && !(data.data as any).token) {
          return {
            success: true,
            error: data.message || 'Registration successful! Your account is awaiting admin approval.',
          }
        }

        if (data.data && (data.data as any).token) {
          const { token_expires_at: _exp, ...userData } = data.data as any
          setUser(userData as User)
          setAccessExpiry(_exp ?? null)
          setIsReady(true)
          return { success: true }
        }
      }

      return {
        success: false,
        error: data.message || data.error || 'Registration failed',
      }
    } catch (error) {
      const message = error instanceof ApiError ? error.message : 'Network error. Please try again.'
      console.error('Registration error:', error)
      return { success: false, error: message }
    }
  }

  const logout = async () => {
    try {
      await apiClient.logout()
    } catch (error) {
      // Best-effort logout
    }
    setUser(null)
    setToken(null)
    setRefreshToken(null)
    setAccessExpiry(null)
    setIsReady(true)
  }

  // Proactively refresh shortly before access expiry using HttpOnly cookies
  useEffect(() => {
    if (!user || !accessExpiry) return

    const now = Date.now()
    const msToRefresh = Math.max(accessExpiry - now - 60_000, 0)

    const timer = setTimeout(async () => {
      try {
        const refreshed = await apiClient.refresh()
        if (refreshed.success && refreshed.data?.token_expires_at) {
          setAccessExpiry(refreshed.data.token_expires_at)
        } else if (!refreshed.success) {
          setUser(null)
          setAccessExpiry(null)
        }
      } catch (_err) {
        setUser(null)
        setAccessExpiry(null)
      }
    }, msToRefresh)

    return () => clearTimeout(timer)
  }, [user, accessExpiry])

  const updateUser = (userData: Partial<User>) => {
    if (user) {
      const updatedUser = { ...user, ...userData }
      setUser(updatedUser)
    }
  }

  const contextValue: AuthContextType = {
    user,
    token,
    refreshToken,
    isLoading,
    isAuthenticated,
    isReady,
    login,
    register,
    logout,
    updateUser,
  }

  return (
    <AuthContext.Provider value={contextValue}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider')
  }
  return context
}