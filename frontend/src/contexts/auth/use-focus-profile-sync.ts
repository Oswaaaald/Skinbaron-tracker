'use client'

import { useEffect, useRef } from 'react'
import { apiClient } from '@/lib/api'
import type { User } from '@/contexts/auth-context.types'

type UseFocusProfileSyncParams = {
  user: User | null
  updateUser: (userData: Partial<User>) => void
}

export function useFocusProfileSync({ user, updateUser }: UseFocusProfileSyncParams) {
  const lastCheckRef = useRef(0)
  const isCheckingRef = useRef(false)

  useEffect(() => {
    if (!user) return

    const checkUserProfile = async () => {
      const now = Date.now()
      if (isCheckingRef.current) return
      if (now - lastCheckRef.current < 30_000) return

      isCheckingRef.current = true
      try {
        const response = await apiClient.getUserProfile({ allowRefresh: true })
        if (response.success && response.data) {
          updateUser({
            username: response.data.username,
            email: response.data.email,
            avatar_url: response.data.avatar_url,
            is_admin: response.data.is_admin,
            is_super_admin: response.data.is_super_admin,
            has_password: response.data.has_password,
            use_gravatar: response.data.use_gravatar,
          })
        }
      } catch {
        // Ignore failures; next focus will retry
      } finally {
        lastCheckRef.current = Date.now()
        isCheckingRef.current = false
      }
    }

    const handleFocus = () => { void checkUserProfile() }
    window.addEventListener('focus', handleFocus)

    return () => {
      window.removeEventListener('focus', handleFocus)
    }
  }, [user, updateUser])
}
