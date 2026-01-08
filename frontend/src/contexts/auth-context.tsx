'use client'

import { createContext, useContext, useEffect, useState, ReactNode } from 'react'
import { apiClient } from '@/lib/api'

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
  isLoading: boolean
  isAuthenticated: boolean
  isReady: boolean // New flag to indicate auth state is fully initialized
  login: (email: string, password: string) => Promise<{ success: boolean; error?: string }>
  register: (username: string, email: string, password: string) => Promise<{ success: boolean; error?: string }>
  logout: () => void
  updateUser: (userData: Partial<User>) => void
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

const AUTH_STORAGE_KEY = 'skinbaron_auth'

interface AuthStorage {
  token: string
  user: User
  expiresAt: number
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [token, setToken] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isReady, setIsReady] = useState(false)

  const isAuthenticated = !!user && !!token

  // Load auth state from localStorage on mount
  useEffect(() => {
    const loadAuthState = async () => {
      try {
        const stored = localStorage.getItem(AUTH_STORAGE_KEY)
        if (stored) {
          const authData: AuthStorage = JSON.parse(stored)
          
          // Check if token is expired
          if (authData.expiresAt > Date.now()) {
            setUser(authData.user)
            setToken(authData.token)
            
            // Force refresh profile to ensure we have latest fields (like is_super_admin)
            try {
              const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080'
              const response = await fetch(`${API_BASE_URL}/api/user/profile`, {
                headers: {
                  'Authorization': `Bearer ${authData.token}`,
                },
              })
              
              if (response.ok) {
                const data = await response.json()
                if (data.success && data.data) {
                  const updatedUser = { ...authData.user, ...data.data }
                  setUser(updatedUser)
                  authData.user = updatedUser
                  localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(authData))
                  console.log('✅ Profile refreshed on mount:', updatedUser)
                }
              }
            } catch (error) {
              console.error('Failed to refresh profile on mount:', error)
            }
            
            // Wait a bit to ensure state updates are processed
            await new Promise(resolve => setTimeout(resolve, 50))
          } else {
            // Token expired, clear storage
            localStorage.removeItem(AUTH_STORAGE_KEY)
          }
        }
      } catch (error) {
        console.error('Failed to load auth state:', error)
        localStorage.removeItem(AUTH_STORAGE_KEY)
      } finally {
        setIsLoading(false)
        setIsReady(true)
      }
    }

    loadAuthState()
  }, [])

  // Setup API client with auth token getter
  useEffect(() => {
    apiClient.setAuthTokenGetter(() => {
      // Always read from localStorage to get the latest token
      // This avoids React state timing issues
      try {
        const stored = localStorage.getItem(AUTH_STORAGE_KEY)
        if (stored) {
          const authData: AuthStorage = JSON.parse(stored)
          // Check if token is still valid
          if (authData.expiresAt > Date.now()) {
            return authData.token
          }
        }
      } catch (error) {
        // Silent fail
      }
      return null
    })
  }, []) // Run only once on mount

  // Check token validity periodically and refresh if needed
  useEffect(() => {
    if (!token || !user) return

    const checkTokenValidity = async () => {
      try {
        // Try to make a simple authenticated request
        const response = await apiClient.getHealth()
        if (!response.success) {
          // Token might be invalid, logout user
          console.warn('Token validation failed, logging out')
          logout()
        }
      } catch (error) {
        console.error('Token check failed:', error)
        // If it's an auth error, logout
        if (error instanceof Error && error.message.includes('token')) {
          logout()
        }
      }
    }

    const checkUserProfile = async () => {
      try {
        // Check if user profile has changed (e.g., admin status)
        const response = await apiClient.getUserProfile()
        if (response.success && response.data) {
          // Get the latest user from localStorage to avoid stale closure
          const stored = localStorage.getItem(AUTH_STORAGE_KEY)
          if (!stored) return
          
          const authData: AuthStorage = JSON.parse(stored)
          const currentUser = authData.user
          const serverUser = response.data
          
          // Check if critical fields have changed
          if (currentUser.is_admin !== serverUser.is_admin ||
              currentUser.is_super_admin !== serverUser.is_super_admin ||
              currentUser.username !== serverUser.username ||
              currentUser.email !== serverUser.email ||
              currentUser.avatar_url !== serverUser.avatar_url) {
            console.log('User profile changed, updating...', {
              old: currentUser,
              new: serverUser
            })
            updateUser({
              username: serverUser.username,
              email: serverUser.email,
              avatar_url: serverUser.avatar_url,
              is_admin: serverUser.is_admin,
              is_super_admin: serverUser.is_super_admin,
            })
          }
        }
      } catch (error) {
        console.error('Profile check failed:', error)
      }
    }

    // Listen for custom event when admin status changes
    const handleProfileChanged = () => {
      console.log('Profile change event received, checking profile...')
      checkUserProfile()
    }
    window.addEventListener('user-profile-changed', handleProfileChanged)

    // Check token every 5 minutes
    const tokenInterval = setInterval(checkTokenValidity, 5 * 60 * 1000)
    // Check profile every 2 seconds for real-time updates
    const profileInterval = setInterval(checkUserProfile, 2 * 1000)
    
    // Check both immediately
    checkTokenValidity()
    checkUserProfile()

    return () => {
      clearInterval(tokenInterval)
      clearInterval(profileInterval)
      window.removeEventListener('user-profile-changed', handleProfileChanged)
    }
  }, [token]) // Only depend on token

  const saveAuthState = async (token: string, user: User) => {
    // JWT tokens from our backend expire in 7 days
    const expiresAt = Date.now() + (7 * 24 * 60 * 60 * 1000)
    
    const authData: AuthStorage = {
      token,
      user,
      expiresAt
    }

    localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(authData))
    setUser(user)
    setToken(token)
    
    // Wait for state updates to propagate BEFORE setting isReady
    await new Promise(resolve => setTimeout(resolve, 100))
    setIsReady(true)
  }

  const clearAuthState = () => {
    localStorage.removeItem(AUTH_STORAGE_KEY)
    setUser(null)
    setToken(null)
    setIsReady(false)
  }

  const login = async (email: string, password: string) => {
    try {
      const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080'
      
      const response = await fetch(`${API_BASE_URL}/api/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      })

      const data = await response.json()

      if (data.success && data.data) {
        const { token, ...userData } = data.data
        await saveAuthState(token, userData)
        return { success: true }
      } else {
        return { 
          success: false, 
          error: data.message || data.error || 'Login failed' 
        }
      }
    } catch (error) {
      console.error('Login error:', error)
      return { 
        success: false, 
        error: 'Network error. Please try again.' 
      }
    }
  }

  const register = async (username: string, email: string, password: string) => {
    try {
      const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080'
      
      const response = await fetch(`${API_BASE_URL}/api/auth/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, email, password }),
      })

      const data = await response.json()

      if (data.success) {
        // Check if user needs approval (no token provided)
        if (data.data && !data.data.token) {
          return { 
            success: true,
            error: data.message || 'Registration successful! Your account is awaiting admin approval.'
          }
        }
        
        // User approved, has token
        if (data.data && data.data.token) {
          const { token, ...userData } = data.data
          await saveAuthState(token, userData)
          return { success: true }
        }
      }
      
      return { 
        success: false, 
        error: data.message || data.error || 'Registration failed' 
      }
    } catch (error) {
      console.error('Registration error:', error)
      return { 
        success: false, 
        error: 'Network error. Please try again.' 
      }
    }
  }

  const logout = () => {
    clearAuthState()
  }

  const updateUser = (userData: Partial<User>) => {
    if (user) {
      const updatedUser = { ...user, ...userData }
      setUser(updatedUser)
      
      // Update localStorage too if we have a token
      if (token) {
        const stored = localStorage.getItem(AUTH_STORAGE_KEY)
        if (stored) {
          const authData: AuthStorage = JSON.parse(stored)
          authData.user = updatedUser
          localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(authData))
        }
      }
    }
  }

  const contextValue: AuthContextType = {
    user,
    token,
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