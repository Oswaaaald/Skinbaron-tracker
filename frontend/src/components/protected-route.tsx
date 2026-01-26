'use client'

import { useAuth } from '@/contexts/auth-context'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { AuthForm } from '@/components/auth-form'
import { useState } from 'react'

interface ProtectedRouteProps {
  children: React.ReactNode
  requireAdmin?: boolean
}

export function ProtectedRoute({ children, requireAdmin = false }: ProtectedRouteProps) {
  const { isAuthenticated, isLoading, isReady, user } = useAuth()
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

  // Check admin requirement
  if (requireAdmin && !user?.is_admin) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="text-center space-y-4 p-8">
          <div className="text-6xl mb-4">🔒</div>
          <h1 className="text-3xl font-bold text-foreground">Access Denied</h1>
          <p className="text-muted-foreground max-w-md">
            You don&apos;t have permission to access this page. Admin privileges are required.
          </p>
          <a 
            href="/" 
            className="inline-block mt-4 px-6 py-3 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 transition-colors"
          >
            Go to Dashboard
          </a>
        </div>
      </div>
    )
  }

  // Render protected content if authenticated
  return <>{children}</>
}