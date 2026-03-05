'use client'

import type { AdminUserDetail } from '@/lib/api'
import { User } from 'lucide-react'
import { DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { UserDetailSkeleton } from '@/components/ui/skeletons'
import { AdminUserDetailLeftColumn } from '@/components/admin/user-detail/left-column'
import { AdminUserDetailRightColumn } from '@/components/admin/user-detail/right-column'

interface AdminUserDetailContentProps {
  detail?: AdminUserDetail
  isLoading: boolean
  isCurrentUser: boolean
  isRestrictionExpired: boolean
  currentUserIsSuperAdmin?: boolean
  removingAvatar: boolean
  editingUsername: boolean
  newUsername: string
  moderating: string | null
  restrictionType: 'temporary' | 'permanent'
  durationHours: number
  restrictReason: string
  banEmail: boolean
  unrestrictReason: string
  onStartEditUsername: () => void
  onCancelEditUsername: () => void
  onNewUsernameChange: (value: string) => void
  onConfirmChangeUsername: () => void
  onAskRemoveAvatar: () => void
  onAskReset2FA: () => void
  onAskResetPasskeys: () => void
  onRestrictionTypeChange: (value: 'temporary' | 'permanent') => void
  onDurationHoursChange: (hours: number) => void
  onRestrictReasonChange: (value: string) => void
  onBanEmailChange: (value: boolean) => void
  onUnrestrictReasonChange: (value: string) => void
  onAskConfirmRestrict: () => void
  onAskConfirmUnrestrict: () => void
  onAskToggleAdmin: (action: 'grant' | 'revoke') => void
  onAskDeleteUser: () => void
  onAskResetSessions: () => void
  onAskDeleteSanction: (id: number) => void
}

export function AdminUserDetailContent({
  detail,
  isLoading,
  isCurrentUser,
  isRestrictionExpired,
  currentUserIsSuperAdmin,
  removingAvatar,
  editingUsername,
  newUsername,
  moderating,
  restrictionType,
  durationHours,
  restrictReason,
  banEmail,
  unrestrictReason,
  onStartEditUsername,
  onCancelEditUsername,
  onNewUsernameChange,
  onConfirmChangeUsername,
  onAskRemoveAvatar,
  onAskReset2FA,
  onAskResetPasskeys,
  onRestrictionTypeChange,
  onDurationHoursChange,
  onRestrictReasonChange,
  onBanEmailChange,
  onUnrestrictReasonChange,
  onAskConfirmRestrict,
  onAskConfirmUnrestrict,
  onAskToggleAdmin,
  onAskDeleteUser,
  onAskResetSessions,
  onAskDeleteSanction,
}: AdminUserDetailContentProps) {
  return (
    <>
      <DialogHeader>
        <DialogTitle className="flex items-center gap-2 text-lg">
          <User className="h-5 w-5" />
          User Profile — {detail?.username ?? '...'}
        </DialogTitle>
        <DialogDescription>GDPR-audited — This access is logged.</DialogDescription>
      </DialogHeader>

      {isLoading ? (
        <UserDetailSkeleton />
      ) : detail ? (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <AdminUserDetailLeftColumn
            detail={detail}
            isCurrentUser={isCurrentUser}
            isRestrictionExpired={isRestrictionExpired}
            removingAvatar={removingAvatar}
            editingUsername={editingUsername}
            newUsername={newUsername}
            moderating={moderating}
            onStartEditUsername={onStartEditUsername}
            onCancelEditUsername={onCancelEditUsername}
            onNewUsernameChange={onNewUsernameChange}
            onConfirmChangeUsername={onConfirmChangeUsername}
            onAskRemoveAvatar={onAskRemoveAvatar}
            onAskReset2FA={onAskReset2FA}
            onAskResetPasskeys={onAskResetPasskeys}
          />

          <AdminUserDetailRightColumn
            detail={detail}
            isCurrentUser={isCurrentUser}
            isRestrictionExpired={isRestrictionExpired}
            currentUserIsSuperAdmin={currentUserIsSuperAdmin}
            restrictionType={restrictionType}
            durationHours={durationHours}
            restrictReason={restrictReason}
            banEmail={banEmail}
            unrestrictReason={unrestrictReason}
            moderating={moderating}
            onRestrictionTypeChange={onRestrictionTypeChange}
            onDurationHoursChange={onDurationHoursChange}
            onRestrictReasonChange={onRestrictReasonChange}
            onBanEmailChange={onBanEmailChange}
            onUnrestrictReasonChange={onUnrestrictReasonChange}
            onAskConfirmRestrict={onAskConfirmRestrict}
            onAskConfirmUnrestrict={onAskConfirmUnrestrict}
            onAskToggleAdmin={onAskToggleAdmin}
            onAskDeleteUser={onAskDeleteUser}
            onAskResetSessions={onAskResetSessions}
            onAskDeleteSanction={onAskDeleteSanction}
          />

          <div className="md:col-span-2">
            <p className="text-xs text-muted-foreground text-center">
              🔒 This data access has been logged in accordance with GDPR Art. 5(1)(f) — integrity & confidentiality.
            </p>
          </div>
        </div>
      ) : null}
    </>
  )
}
