'use client'

import { useEffect, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Dialog, DialogContent } from '@/components/ui/dialog'
import { useAuth } from '@/contexts/auth-context'
import { useToast } from '@/hooks/use-toast'
import { apiClient, type AdminUserDetail } from '@/lib/api'
import { QUERY_KEYS } from '@/lib/constants'
import { createAdminUserDetailActions } from '@/components/admin-user-detail/actions'
import { AdminUserDetailContent } from '@/components/admin-user-detail/content'
import { ModerationDialogs } from '@/components/admin-user-detail/moderation-dialogs'
import { SecurityDialogs } from '@/components/admin-user-detail/security-dialogs'

interface AdminUserDetailDialogProps {
  userId: number | null
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function AdminUserDetailDialog({ userId, open, onOpenChange }: AdminUserDetailDialogProps) {
  const { toast } = useToast()
  const { user: currentUser } = useAuth()
  const queryClient = useQueryClient()

  const [removingAvatar, setRemovingAvatar] = useState(false)
  const [editingUsername, setEditingUsername] = useState(false)
  const [newUsername, setNewUsername] = useState('')
  const [restrictionType, setRestrictionType] = useState<'temporary' | 'permanent'>('temporary')
  const [durationHours, setDurationHours] = useState<number>(24)
  const [restrictReason, setRestrictReason] = useState('')
  const [banEmail, setBanEmail] = useState(true)
  const [unrestrictReason, setUnrestrictReason] = useState('')
  const [confirmRestrict, setConfirmRestrict] = useState(false)
  const [confirmUnrestrict, setConfirmUnrestrict] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [confirmToggleAdmin, setConfirmToggleAdmin] = useState<'grant' | 'revoke' | null>(null)
  const [confirmDeleteSanction, setConfirmDeleteSanction] = useState<number | null>(null)
  const [confirmReset, setConfirmReset] = useState<'2fa' | 'passkeys' | 'sessions' | null>(null)
  const [confirmRemoveAvatar, setConfirmRemoveAvatar] = useState(false)
  const [confirmChangeUsername, setConfirmChangeUsername] = useState(false)

  const [moderating, setModerating] = useState<string | null>(null)
  useEffect(() => {
    /* eslint-disable react-hooks/set-state-in-effect */
    setEditingUsername(false)
    setNewUsername('')
    setRemovingAvatar(false)
    setRestrictionType('temporary')
    setDurationHours(24)
    setRestrictReason('')
    setBanEmail(true)
    setUnrestrictReason('')
    setConfirmRestrict(false)
    setConfirmUnrestrict(false)
    setConfirmDelete(false)
    setConfirmToggleAdmin(null)
    setConfirmRemoveAvatar(false)
    setConfirmChangeUsername(false)
    setConfirmDeleteSanction(null)
    setConfirmReset(null)
    setModerating(null)
    /* eslint-enable react-hooks/set-state-in-effect */
  }, [userId])

  const { data: detail, isLoading } = useQuery({
    queryKey: ['admin-user-detail', userId],
    queryFn: async () => {
      const res = apiClient.ensureSuccess(await apiClient.getAdminUserDetail(userId ?? 0), 'Failed to load user detail')
      return res.data as AdminUserDetail
    },
    enabled: open && userId !== null,
    staleTime: 30_000,
  })

  const invalidateAll = () => {
    void queryClient.invalidateQueries({ queryKey: ['admin-user-detail', userId] })
    void queryClient.invalidateQueries({ queryKey: [QUERY_KEYS.ADMIN_USERS] })
    void queryClient.invalidateQueries({ queryKey: [QUERY_KEYS.ADMIN_STATS] })
    void queryClient.invalidateQueries({ queryKey: [QUERY_KEYS.ADMIN_AUDIT_LOGS] })
  }
  const {
    handleRemoveAvatar,
    handleChangeUsername,
    handleRestrict,
    handleUnrestrict,
    handleDeleteUser,
    handleToggleAdmin,
    handleReset,
    handleDeleteSanction,
  } = createAdminUserDetailActions({
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
  })

  const isCurrentUser = !!detail && currentUser?.id === detail.id
  const isRestrictionExpired =
    !!detail?.is_restricted &&
    detail.restriction_type === 'temporary' &&
    !!detail.restriction_expires_at &&
    new Date(detail.restriction_expires_at) <= new Date()

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="max-w-7xl max-h-[90vh] overflow-y-auto">
          <AdminUserDetailContent
            detail={detail}
            isLoading={isLoading}
            isCurrentUser={isCurrentUser}
            isRestrictionExpired={isRestrictionExpired}
            currentUserIsSuperAdmin={currentUser?.is_super_admin}
            removingAvatar={removingAvatar}
            editingUsername={editingUsername}
            newUsername={newUsername}
            moderating={moderating}
            restrictionType={restrictionType}
            durationHours={durationHours}
            restrictReason={restrictReason}
            banEmail={banEmail}
            unrestrictReason={unrestrictReason}
            onStartEditUsername={() => { setEditingUsername(true); setNewUsername(detail?.username ?? '') }}
            onCancelEditUsername={() => { setEditingUsername(false); setNewUsername('') }}
            onNewUsernameChange={setNewUsername}
            onConfirmChangeUsername={() => setConfirmChangeUsername(true)}
            onAskRemoveAvatar={() => setConfirmRemoveAvatar(true)}
            onAskReset2FA={() => setConfirmReset('2fa')}
            onAskResetPasskeys={() => setConfirmReset('passkeys')}
            onRestrictionTypeChange={setRestrictionType}
            onDurationHoursChange={setDurationHours}
            onRestrictReasonChange={setRestrictReason}
            onBanEmailChange={setBanEmail}
            onUnrestrictReasonChange={setUnrestrictReason}
            onAskConfirmRestrict={() => setConfirmRestrict(true)}
            onAskConfirmUnrestrict={() => setConfirmUnrestrict(true)}
            onAskToggleAdmin={setConfirmToggleAdmin}
            onAskDeleteUser={() => setConfirmDelete(true)}
            onAskResetSessions={() => setConfirmReset('sessions')}
            onAskDeleteSanction={setConfirmDeleteSanction}
          />
        </DialogContent>
      </Dialog>

      <ModerationDialogs
        detail={detail}
        moderating={moderating}
        restrictionType={restrictionType}
        durationHours={durationHours}
        restrictReason={restrictReason}
        banEmail={banEmail}
        unrestrictReason={unrestrictReason}
        confirmRestrict={confirmRestrict}
        setConfirmRestrict={setConfirmRestrict}
        confirmUnrestrict={confirmUnrestrict}
        setConfirmUnrestrict={setConfirmUnrestrict}
        confirmDelete={confirmDelete}
        setConfirmDelete={setConfirmDelete}
        confirmDeleteSanction={confirmDeleteSanction}
        setConfirmDeleteSanction={setConfirmDeleteSanction}
        lastDeleteSanction={confirmDeleteSanction ?? 0}
        onConfirmRestrict={() => void handleRestrict()}
        onConfirmUnrestrict={() => void handleUnrestrict()}
        onConfirmDeleteUser={() => void handleDeleteUser()}
        onConfirmDeleteSanction={(id) => void handleDeleteSanction(id)}
      />

      <SecurityDialogs
        username={detail?.username}
        passkeysCount={detail?.passkeys.length ?? 0}
        newUsername={newUsername}
        removingAvatar={removingAvatar}
        moderating={moderating}
        confirmToggleAdmin={confirmToggleAdmin}
        setConfirmToggleAdmin={setConfirmToggleAdmin}
        lastToggleAdmin={confirmToggleAdmin ?? 'grant'}
        confirmReset={confirmReset}
        setConfirmReset={setConfirmReset}
        lastReset={confirmReset ?? '2fa'}
        confirmRemoveAvatar={confirmRemoveAvatar}
        setConfirmRemoveAvatar={setConfirmRemoveAvatar}
        confirmChangeUsername={confirmChangeUsername}
        setConfirmChangeUsername={setConfirmChangeUsername}
        onConfirmToggleAdmin={(grant) => void handleToggleAdmin(grant)}
        onConfirmReset={(target) => void handleReset(target)}
        onConfirmRemoveAvatar={() => {
          setConfirmRemoveAvatar(false)
          void handleRemoveAvatar()
        }}
        onConfirmChangeUsername={() => {
          setConfirmChangeUsername(false)
          void handleChangeUsername()
        }}
      />
    </>
  )
}
