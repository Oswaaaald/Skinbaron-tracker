import { apiClient } from '@/lib/api'
import { extractErrorMessage } from '@/lib/utils'

interface ToastFn {
  (params: { title?: string; description?: string; variant?: 'default' | 'destructive' }): void
}

interface CreateAdminUserDetailActionsParams {
  userId: number | null
  onOpenChange: (open: boolean) => void
  toast: ToastFn
  invalidateAll: () => void
  restrictionType: 'temporary' | 'permanent'
  durationHours: number
  restrictReason: string
  banEmail: boolean
  unrestrictReason: string
  newUsername: string
  setRemovingAvatar: (value: boolean) => void
  setEditingUsername: (value: boolean) => void
  setNewUsername: (value: string) => void
  setModerating: (value: string | null) => void
  setConfirmRestrict: (value: boolean) => void
  setRestrictReason: (value: string) => void
  setDurationHours: (value: number) => void
  setRestrictionType: (value: 'temporary' | 'permanent') => void
  setConfirmUnrestrict: (value: boolean) => void
  setUnrestrictReason: (value: string) => void
  setConfirmDelete: (value: boolean) => void
  setConfirmToggleAdmin: (value: 'grant' | 'revoke' | null) => void
  setConfirmReset: (value: '2fa' | 'passkeys' | 'sessions' | null) => void
  setConfirmDeleteSanction: (value: number | null) => void
}

export function createAdminUserDetailActions({
  userId,
  onOpenChange,
  toast,
  invalidateAll,
  restrictionType,
  durationHours,
  restrictReason,
  banEmail,
  unrestrictReason,
  newUsername,
  setRemovingAvatar,
  setEditingUsername,
  setNewUsername,
  setModerating,
  setConfirmRestrict,
  setRestrictReason,
  setDurationHours,
  setRestrictionType,
  setConfirmUnrestrict,
  setUnrestrictReason,
  setConfirmDelete,
  setConfirmToggleAdmin,
  setConfirmReset,
  setConfirmDeleteSanction,
}: CreateAdminUserDetailActionsParams) {
  const handleRemoveAvatar = async () => {
    if (!userId) return
    setRemovingAvatar(true)
    try {
      const res = await apiClient.adminDeleteUserAvatar(userId)
      if (res.success) {
        toast({ title: '✅ Avatar removed', description: 'User avatar has been removed' })
        invalidateAll()
      } else {
        toast({ title: '❌ Failed', description: res.message || 'Failed to remove avatar', variant: 'destructive' })
      }
    } catch (error) {
      toast({ title: '❌ Failed', description: extractErrorMessage(error, 'Failed to remove avatar'), variant: 'destructive' })
    } finally {
      setRemovingAvatar(false)
    }
  }

  const handleChangeUsername = async () => {
    if (!userId || !newUsername.trim()) return
    setModerating('username')
    try {
      const res = await apiClient.adminChangeUsername(userId, newUsername.trim())
      if (res.success) {
        toast({ title: '✅ Username changed', description: res.message })
        setEditingUsername(false)
        setNewUsername('')
        invalidateAll()
      } else {
        toast({ title: '❌ Failed', description: res.message || 'Failed', variant: 'destructive' })
      }
    } catch (error) {
      toast({ title: '❌ Failed', description: extractErrorMessage(error, 'Failed'), variant: 'destructive' })
    } finally {
      setModerating(null)
    }
  }

  const handleRestrict = async () => {
    if (!userId) return
    setModerating('restrict')
    try {
      const res = await apiClient.adminRestrictUser(userId, {
        restriction_type: restrictionType,
        reason: restrictReason || undefined,
        duration_hours: restrictionType === 'temporary' ? durationHours : undefined,
        ban_email: restrictionType === 'permanent' ? banEmail : undefined,
      })
      if (res.success) {
        toast({ title: '🚫 User restricted', description: res.message })
        invalidateAll()
      } else {
        toast({ title: '❌ Failed', description: res.message || 'Failed', variant: 'destructive' })
      }
    } catch (error) {
      toast({ title: '❌ Failed', description: extractErrorMessage(error, 'Failed'), variant: 'destructive' })
    } finally {
      setModerating(null)
      setConfirmRestrict(false)
      setTimeout(() => {
        setRestrictReason('')
        setDurationHours(24)
        setRestrictionType('temporary')
      }, 200)
    }
  }

  const handleUnrestrict = async () => {
    if (!userId || !unrestrictReason.trim()) return
    setModerating('unrestrict')
    try {
      const res = await apiClient.adminUnrestrictUser(userId, unrestrictReason.trim())
      if (res.success) {
        toast({ title: '✅ User unrestricted', description: res.message })
        invalidateAll()
      } else {
        toast({ title: '❌ Failed', description: res.message || 'Failed', variant: 'destructive' })
      }
    } catch (error) {
      toast({ title: '❌ Failed', description: extractErrorMessage(error, 'Failed'), variant: 'destructive' })
    } finally {
      setModerating(null)
      setConfirmUnrestrict(false)
      setTimeout(() => setUnrestrictReason(''), 200)
    }
  }

  const handleDeleteUser = async () => {
    if (!userId) return
    setModerating('delete')
    try {
      const res = await apiClient.delete(`/api/admin/users/${userId}`)
      if (res.success) {
        toast({ title: '✅ User deleted', description: 'User account has been permanently deleted' })
        invalidateAll()
        onOpenChange(false)
      } else {
        toast({ title: '❌ Failed', description: res.message || 'Failed', variant: 'destructive' })
      }
    } catch (error) {
      toast({ title: '❌ Failed', description: extractErrorMessage(error, 'Failed'), variant: 'destructive' })
    } finally {
      setModerating(null)
      setConfirmDelete(false)
    }
  }

  const handleToggleAdmin = async (grant: boolean) => {
    if (!userId) return
    setModerating('admin')
    try {
      const res = await apiClient.patch(`/api/admin/users/${userId}/admin`, { is_admin: grant })
      if (res.success) {
        toast({ title: grant ? '✅ Admin granted' : '✅ Admin revoked', description: res.message })
        window.dispatchEvent(new CustomEvent('user-profile-changed'))
        invalidateAll()
      } else {
        toast({ title: '❌ Failed', description: res.message || 'Failed', variant: 'destructive' })
      }
    } catch (error) {
      toast({ title: '❌ Failed', description: extractErrorMessage(error, 'Failed'), variant: 'destructive' })
    } finally {
      setModerating(null)
      setConfirmToggleAdmin(null)
    }
  }

  const handleReset = async (target: '2fa' | 'passkeys' | 'sessions') => {
    if (!userId) return
    setModerating(`reset-${target}`)
    try {
      const res = await apiClient.adminResetUserData(userId, target)
      if (res.success) {
        const labels = { '2fa': '2FA', passkeys: 'Passkeys', sessions: 'Sessions' } as const
        toast({ title: `✅ ${labels[target]} reset`, description: res.message || `${labels[target]} have been reset successfully` })
        invalidateAll()
      } else {
        toast({ title: '❌ Failed', description: res.message || 'Failed', variant: 'destructive' })
      }
    } catch (error) {
      toast({ title: '❌ Failed', description: extractErrorMessage(error, 'Failed'), variant: 'destructive' })
    } finally {
      setModerating(null)
      setConfirmReset(null)
    }
  }

  const handleDeleteSanction = async (sanctionId: number) => {
    setModerating('delete-sanction')
    try {
      const res = await apiClient.adminDeleteSanction(sanctionId)
      if (res.success) {
        toast({ title: '✅ Sanction deleted', description: 'Sanction has been removed from history' })
        invalidateAll()
      } else {
        toast({ title: '❌ Failed', description: res.message || 'Failed', variant: 'destructive' })
      }
    } catch (error) {
      toast({ title: '❌ Failed', description: extractErrorMessage(error, 'Failed'), variant: 'destructive' })
    } finally {
      setModerating(null)
      setConfirmDeleteSanction(null)
    }
  }

  return {
    handleRemoveAvatar,
    handleChangeUsername,
    handleRestrict,
    handleUnrestrict,
    handleDeleteUser,
    handleToggleAdmin,
    handleReset,
    handleDeleteSanction,
  }
}
