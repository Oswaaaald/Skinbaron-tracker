'use client'

import { AuthForm } from "@/components/auth-form"
import { useRouter } from "next/navigation"
import { useAuth } from "@/contexts/auth-context"
import { useEffect } from "react"
import { LoadingSpinner } from "@/components/ui/loading-spinner"

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
      <div className="min-h-screen w-full flex flex-col items-center justify-center bg-background">
        <LoadingSpinner size="lg" />
        <p className="text-muted-foreground mt-2">Loading...</p>
      </div>
    )
  }

  return (
    <AuthForm 
      mode="register" 
      onToggleMode={() => router.push('/login')} 
    />
  )
}
