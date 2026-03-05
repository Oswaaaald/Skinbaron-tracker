'use client'

import { useRouter } from "next/navigation"
import { useAuth } from "@/contexts/auth-context"
import { useEffect } from "react"
import { AuthFormSkeleton } from "@/components/ui/skeletons"
import { AuthForm } from "@/components/auth/form"

export default function RegisterPage() {
  const router = useRouter()
  const { isAuthenticated, isReady } = useAuth()

  useEffect(() => {
    if (isReady && isAuthenticated) {
      router.replace('/alerts')
    }
  }, [isReady, isAuthenticated, router])

  if (isReady && isAuthenticated) {
    return <AuthFormSkeleton />
  }

  return <AuthForm mode="register" onToggleMode={() => router.push('/login')} />
}
