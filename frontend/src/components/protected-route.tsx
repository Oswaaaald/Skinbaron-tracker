'use client'

import { useAuth } from '@/contexts/auth-context'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { AuthForm } from '@/components/auth-form'
import { useState } from 'react'

interface ProtectedRouteProps {
  children: React.ReactNode
}

export function ProtectedRoute({ children }: ProtectedRouteProps) {
  const { isAuthenticated, isLoading, isReady } = useAuth()
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login')

  // Show loading spinner while checking authentication status
  if (isLoading || !isReady) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <LoadingSpinner className="h-8 w-8 mx-auto mb-4" />
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </div>
    )
  }

  // Show auth form if not authenticated (only after ready)
  if (!isAuthenticated) {
    return (
      <AuthForm 
        mode={authMode} 
        onToggleMode={() => setAuthMode(authMode === 'login' ? 'register' : 'login')} 
      />
    )
  }

  // Render protected content if authenticated
  return <>{children}</>
}