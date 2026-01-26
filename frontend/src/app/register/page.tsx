'use client'

import { AuthForm } from "@/components/auth-form"
import { useRouter } from "next/navigation"
import { useAuth } from "@/contexts/auth-context"
import { useEffect } from "react"

export default function RegisterPage() {
  const router = useRouter()
  const { isAuthenticated, isLoading, isReady } = useAuth()

  useEffect(() => {
    if (isAuthenticated) {
      router.push('/')
    }
  }, [isAuthenticated, router])

  if (isLoading || !isReady || isAuthenticated) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <AuthForm 
        mode="register" 
        onToggleMode={() => router.push('/login')} 
      />
    </div>
  )
}
