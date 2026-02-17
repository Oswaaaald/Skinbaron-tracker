'use client'

import { lazy, Suspense } from 'react'
import { useRouter } from "next/navigation"
import { useAuth } from "@/contexts/auth-context"
import { useEffect } from "react"
import { LoadingState } from "@/components/ui/loading-state"

const AuthForm = lazy(() => import('@/components/auth-form').then(m => ({ default: m.AuthForm })))

export default function LoginPage() {
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
    <Suspense fallback={<LoadingState variant="page" />}>
      <AuthForm 
        mode="login" 
        onToggleMode={() => router.push('/register')} 
      />
    </Suspense>
  )
}
