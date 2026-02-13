'use client'

import { AuthForm } from "@/components/auth-form"
import { useRouter } from "next/navigation"
import { useAuth } from "@/contexts/auth-context"
import { useEffect } from "react"
import { LoadingState } from "@/components/ui/loading-state"

export default function RegisterPage() {
  const router = useRouter()
  const { isAuthenticated, isLoading, isReady } = useAuth()

  useEffect(() => {
    if (isAuthenticated) {
      router.push('/')
    }
  }, [isAuthenticated, router])

  if (isLoading || !isReady || isAuthenticated) {
    return <LoadingState variant="page" />
  }

  return (
    <AuthForm 
      mode="register" 
      onToggleMode={() => router.push('/login')} 
    />
  )
}
