'use client'

import { apiClient } from '@/lib/api'
import { QUERY_KEYS } from '@/lib/constants'
import { extractErrorMessage } from '@/lib/utils'
import { useApiMutation } from '@/hooks/use-api-mutation'
import type { FormSection } from '@/hooks/use-form-state'

interface ToastFn {
  (params: { title?: string; description?: string; variant?: 'default' | 'destructive' }): void
}

interface UserLike {
  id?: number
  username?: string
  email?: string
  avatar_url?: string | null
  use_gravatar?: boolean
  is_admin?: boolean
  has_password?: boolean
}

interface ProfileMutationsParams {
  user: UserLike | null
  updateUser: (user: Partial<UserLike>) => void
  logout: () => Promise<void>
  toast: ToastFn
  setError: (section: FormSection, message: string) => void
  setSuccess: (section: FormSection, message: string) => void
  clear: (section: FormSection) => void
  setDeleteError: (message: string) => void
  setDeletePassword: (value: string) => void
  setCurrentPassword: (value: string) => void
  setNewPassword: (value: string) => void
  setConfirmPassword: (value: string) => void
  setDisableTwoFactorDialog: (open: boolean) => void
  setTwoFactorPassword: (value: string) => void
}

export function useProfileMutations({
  user,
  updateUser,
  logout,
  toast,
  setError,
  setSuccess,
  clear,
  setDeleteError,
  setDeletePassword,
  setCurrentPassword,
  setNewPassword,
  setConfirmPassword,
  setDisableTwoFactorDialog,
  setTwoFactorPassword,
}: ProfileMutationsParams) {
  const updateProfileMutation = useApiMutation(
    (data: { username?: string; email?: string }) => apiClient.patch('/api/user/profile', data),
    {
      invalidateKeys: [[QUERY_KEYS.USER_PROFILE], [QUERY_KEYS.ADMIN_USERS], [QUERY_KEYS.USER_AUDIT_LOGS]],
      successMessage: 'Profile updated successfully',
      onSuccess: (response) => {
        if (response?.data) {
          const userData = response.data as { id: number; username: string; email: string; avatar_url?: string | null; use_gravatar?: boolean; is_admin?: boolean }
          updateUser({
            id: userData.id,
            username: userData.username,
            email: userData.email,
            avatar_url: userData.avatar_url ?? null,
            use_gravatar: userData.use_gravatar,
            is_admin: userData.is_admin,
          })
        }
        setSuccess('profile', 'Profile updated successfully')
      },
      onError: (error: unknown) => setError('profile', extractErrorMessage(error, 'Failed to update profile')),
    }
  )

  const updatePasswordMutation = useApiMutation(
    (data: { current_password: string; new_password: string }) => apiClient.patch('/api/user/password', data),
    {
      invalidateKeys: [[QUERY_KEYS.USER_AUDIT_LOGS]],
      successMessage: 'Password updated successfully',
      onSuccess: () => {
        setSuccess('password', 'Password updated successfully')
        setCurrentPassword('')
        setNewPassword('')
        setConfirmPassword('')
      },
      onError: (error: unknown) => setError('password', extractErrorMessage(error, 'Failed to update password')),
    }
  )

  const setPasswordMutation = useApiMutation(
    (data: { new_password: string }) => apiClient.post('/api/user/set-password', data),
    {
      invalidateKeys: [[QUERY_KEYS.USER_AUDIT_LOGS], [QUERY_KEYS.USER_PROFILE]],
      successMessage: 'Password set successfully',
      onSuccess: () => {
        setSuccess('password', 'Password set successfully! You can now use it to log in.')
        setNewPassword('')
        setConfirmPassword('')
        if (user) updateUser({ ...user, has_password: true })
      },
      onError: (error: unknown) => setError('password', extractErrorMessage(error, 'Failed to set password')),
    }
  )

  const deleteAccountMutation = useApiMutation(
    (data: { password?: string; totp_code?: string }) => apiClient.delete('/api/user/account', data),
    {
      onSuccess: () => {
        toast({ title: '✅ Account deleted', description: 'Your account has been permanently deleted' })
        void logout()
      },
      onError: (error: unknown) => {
        setDeleteError(extractErrorMessage(error, 'Failed to delete account'))
        setDeletePassword('')
      },
    }
  )

  const disableTwoFactorMutation = useApiMutation(
    (data?: { password?: string; totp_code?: string }) => apiClient.post('/api/user/2fa/disable', data ?? {}),
    {
      invalidateKeys: [[QUERY_KEYS.TWO_FA_STATUS]],
      successMessage: 'Two-factor authentication disabled successfully',
      onSuccess: () => {
        setSuccess('general', 'Two-factor authentication disabled successfully')
        clear('twoFactor')
        setDisableTwoFactorDialog(false)
        setTwoFactorPassword('')
      },
      onError: (error: unknown) => setError('twoFactor', extractErrorMessage(error, 'Failed to disable 2FA')),
    }
  )

  return {
    updateProfileMutation,
    updatePasswordMutation,
    setPasswordMutation,
    deleteAccountMutation,
    disableTwoFactorMutation,
  }
}
