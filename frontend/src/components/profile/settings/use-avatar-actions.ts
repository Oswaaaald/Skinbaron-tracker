'use client'

import { useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { apiClient } from '@/lib/api'
import { QUERY_KEYS } from '@/lib/constants'
import { extractErrorMessage } from '@/lib/utils'

interface ToastFn {
  (params: { title?: string; description?: string; variant?: 'default' | 'destructive' }): void
}

interface UseAvatarActionsParams {
  updateUser: (data: { avatar_url?: string | null; use_gravatar?: boolean }) => void
  toast: ToastFn
}

export function useAvatarActions({ updateUser, toast }: UseAvatarActionsParams) {
  const queryClient = useQueryClient()
  const [avatarUploading, setAvatarUploading] = useState(false)
  const [avatarDeleting, setAvatarDeleting] = useState(false)
  const [gravatarToggling, setGravatarToggling] = useState(false)

  const handleAvatarUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    e.target.value = ''

    const allowedTypes = ['image/png', 'image/jpeg', 'image/webp', 'image/gif']
    if (!allowedTypes.includes(file.type)) {
      toast({ title: '❌ Invalid file type', description: 'Please upload a PNG, JPEG, WebP, or GIF image', variant: 'destructive' })
      return
    }
    if (file.size > 5 * 1024 * 1024) {
      toast({ title: '❌ File too large', description: 'Maximum file size is 5 MB', variant: 'destructive' })
      return
    }

    setAvatarUploading(true)
    try {
      const formData = new FormData()
      formData.append('file', file)
      const response = await apiClient.uploadFile<{ avatar_url: string }>('/api/user/avatar', formData)
      if (response.success && response.data) {
        updateUser({ avatar_url: response.data.avatar_url })
        toast({ title: '✅ Avatar updated', description: 'Your avatar has been uploaded successfully' })
        void queryClient.invalidateQueries({ queryKey: [QUERY_KEYS.USER_PROFILE] })
      } else {
        toast({ title: '❌ Upload failed', description: response.message || 'Failed to upload avatar', variant: 'destructive' })
      }
    } catch (error) {
      toast({ title: '❌ Upload failed', description: extractErrorMessage(error, 'Failed to upload avatar'), variant: 'destructive' })
    } finally {
      setAvatarUploading(false)
    }
  }

  const handleAvatarDelete = async () => {
    setAvatarDeleting(true)
    try {
      const response = await apiClient.delete<{ avatar_url: string | null }>('/api/user/avatar')
      if (response.success) {
        updateUser({ avatar_url: response.data?.avatar_url ?? null })
        toast({ title: '✅ Avatar removed', description: 'Your custom avatar has been removed' })
        void queryClient.invalidateQueries({ queryKey: [QUERY_KEYS.USER_PROFILE] })
      } else {
        toast({ title: '❌ Remove failed', description: response.message || 'Failed to remove avatar', variant: 'destructive' })
      }
    } catch (error) {
      toast({ title: '❌ Remove failed', description: extractErrorMessage(error, 'Failed to remove avatar'), variant: 'destructive' })
    } finally {
      setAvatarDeleting(false)
    }
  }

  const handleGravatarToggle = async (checked: boolean) => {
    setGravatarToggling(true)
    try {
      const response = await apiClient.patch<{ use_gravatar: boolean; avatar_url: string | null }>('/api/user/avatar-settings', { use_gravatar: checked })
      if (response.success && response.data) {
        updateUser({ use_gravatar: response.data.use_gravatar, avatar_url: response.data.avatar_url ?? null })
        toast({
          title: checked ? '✅ Gravatar enabled' : '✅ Gravatar disabled',
          description: checked ? 'Your Gravatar will be used as fallback' : 'Gravatar fallback has been disabled',
        })
        void queryClient.invalidateQueries({ queryKey: [QUERY_KEYS.USER_PROFILE] })
      } else {
        toast({ title: '❌ Update failed', description: response.message || 'Failed to update setting', variant: 'destructive' })
      }
    } catch (error) {
      toast({ title: '❌ Update failed', description: extractErrorMessage(error, 'Failed to update avatar settings'), variant: 'destructive' })
    } finally {
      setGravatarToggling(false)
    }
  }

  return {
    avatarUploading,
    avatarDeleting,
    gravatarToggling,
    handleAvatarUpload,
    handleAvatarDelete,
    handleGravatarToggle,
  }
}
