'use client'

import { lazy, Suspense } from 'react'
import { useRouter } from "next/navigation"
import { useAuth } from "@/contexts/auth-context"
import { useEffect } from "react"
import { AuthFormSkeleton } from "@/components/ui/skeletons"

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
    return <AuthFormSkeleton />
  }

  return (
    <Suspense fallback={<AuthFormSkeleton />}>
      <AuthForm 
        mode="login" 
        onToggleMode={() => router.push('/register')} 
      />
    </Suspense>
  )
}
