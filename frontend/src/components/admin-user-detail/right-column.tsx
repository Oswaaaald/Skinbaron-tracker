'use client'

import { Ban, Check, Clock, FileWarning, ScrollText, Trash2 } from 'lucide-react'
import type { AdminUserDetail, Sanction } from '@/lib/api'
import { formatDateTime } from '@/lib/formatters'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { DURATION_PRESETS, formatDuration } from '@/components/admin-user-detail/constants'
import { AdminActionsCard } from '@/components/admin-user-detail/admin-actions-card'

interface AdminUserDetailRightColumnProps {
  detail: AdminUserDetail
  isCurrentUser: boolean
  isRestrictionExpired: boolean
  currentUserIsSuperAdmin?: boolean
  restrictionType: 'temporary' | 'permanent'
  durationHours: number
  restrictReason: string
  banEmail: boolean
  unrestrictReason: string
  moderating: string | null
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

export function AdminUserDetailRightColumn({
  detail,
  isCurrentUser,
  isRestrictionExpired,
  currentUserIsSuperAdmin,
  restrictionType,
  durationHours,
  restrictReason,
  banEmail,
  unrestrictReason,
  moderating,
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
}: AdminUserDetailRightColumnProps) {
  return (
    <div className="space-y-4">
      {!detail.is_super_admin && !isCurrentUser && (
        <Card className="border-amber-500/30">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2 text-amber-600 dark:text-amber-400">
              <FileWarning className="h-4 w-4" />
              Moderation
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {detail.is_restricted && !isRestrictionExpired ? (
              <div className="space-y-3">
                <div className="rounded-md bg-red-500/10 border border-red-500/20 p-3 space-y-1">
                  <p className="text-sm font-medium text-red-600 dark:text-red-400 flex items-center gap-2">
                    <Ban className="h-4 w-4" />
                    Account is {detail.restriction_type === 'permanent' ? 'permanently' : 'temporarily'} restricted
                  </p>
                  {detail.restriction_reason && <p className="text-xs text-muted-foreground">Reason: {detail.restriction_reason}</p>}
                  {detail.restricted_at && <p className="text-xs text-muted-foreground">Since: {formatDateTime(detail.restricted_at)}</p>}
                  {detail.restriction_type === 'temporary' && detail.restriction_expires_at && (
                    <p className="text-xs text-muted-foreground">Expires: {formatDateTime(detail.restriction_expires_at)}</p>
                  )}
                </div>
                <div className="space-y-2">
                  <Label className="text-xs font-medium">Reason for unrestriction *</Label>
                  <Input
                    value={unrestrictReason}
                    onChange={(e) => onUnrestrictReasonChange(e.target.value)}
                    placeholder="Why is this user being unrestricted?"
                    className="h-8 text-sm"
                    maxLength={500}
                  />
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={onAskConfirmUnrestrict}
                    disabled={moderating !== null || !unrestrictReason.trim()}
                    className="w-full"
                  >
                    {moderating === 'unrestrict' ? <LoadingSpinner size="sm" inline /> : 'Remove Restriction'}
                  </Button>
                </div>
              </div>
            ) : (
              <div className="space-y-3">
                <div className="space-y-2">
                  <Label className="text-xs font-medium">Restriction type</Label>
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      variant={restrictionType === 'temporary' ? 'default' : 'outline'}
                      onClick={() => onRestrictionTypeChange('temporary')}
                      className="flex-1"
                    >
                      <Clock className="h-3 w-3 mr-1.5" />
                      Temporary
                    </Button>
                    <Button
                      size="sm"
                      variant={restrictionType === 'permanent' ? 'destructive' : 'outline'}
                      onClick={() => onRestrictionTypeChange('permanent')}
                      className="flex-1"
                    >
                      <Ban className="h-3 w-3 mr-1.5" />
                      Permanent
                    </Button>
                  </div>
                </div>

                {restrictionType === 'temporary' && (
                  <div className="space-y-2">
                    <Label className="text-xs font-medium">Duration</Label>
                    <div className="flex flex-wrap gap-1.5">
                      {DURATION_PRESETS.map((preset) => (
                        <Button
                          key={preset.hours}
                          size="sm"
                          variant={durationHours === preset.hours ? 'default' : 'outline'}
                          onClick={() => onDurationHoursChange(preset.hours)}
                          className="h-7 px-2.5 text-xs"
                        >
                          {preset.label}
                        </Button>
                      ))}
                    </div>
                    <p className="text-[11px] text-muted-foreground">
                      Restriction will expire automatically after {formatDuration(durationHours)}
                    </p>
                  </div>
                )}

                {restrictionType === 'permanent' && (
                  <label className="flex items-center gap-2 text-xs text-muted-foreground">
                    <input type="checkbox" checked={banEmail} onChange={(e) => onBanEmailChange(e.target.checked)} className="rounded" />
                    Also ban email ({detail.email}) and linked OAuth emails to prevent re-registration
                  </label>
                )}

                <div className="space-y-2">
                  <Label className="text-xs font-medium">Reason *</Label>
                  <Input
                    value={restrictReason}
                    onChange={(e) => onRestrictReasonChange(e.target.value)}
                    placeholder="Why is this user being restricted?"
                    className="h-8 text-sm"
                    maxLength={500}
                  />
                </div>

                <Button
                  size="sm"
                  variant="destructive"
                  onClick={onAskConfirmRestrict}
                  disabled={moderating !== null || !restrictReason.trim()}
                  className="w-full gap-1.5"
                >
                  {moderating === 'restrict' ? <LoadingSpinner size="sm" inline /> : <><Ban className="h-3.5 w-3.5" />Restrict User ({restrictionType === 'permanent' ? 'Permanent' : formatDuration(durationHours)})</>}
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {!detail.is_super_admin && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <ScrollText className="h-4 w-4" />
              Sanctions History
              {detail.sanctions.length > 0 && <Badge variant="secondary" className="text-[10px] px-1.5">{detail.sanctions.length}</Badge>}
            </CardTitle>
          </CardHeader>
          <CardContent>
            {detail.sanctions.length === 0 ? (
              <p className="text-xs text-muted-foreground text-center py-4">No sanctions recorded</p>
            ) : (
              <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
                {detail.sanctions.map((sanction: Sanction) => (
                  <div key={sanction.id} className={`rounded-md border px-3 py-2 text-xs space-y-1 ${sanction.action === 'restrict' ? 'border-red-500/20 bg-red-500/5' : 'border-green-500/20 bg-green-500/5'}`}>
                    <div className="flex items-center justify-between">
                      <span className="font-medium flex items-center gap-1.5">
                        {sanction.action === 'restrict' ? <Ban className="h-3 w-3 text-red-500" /> : <Check className="h-3 w-3 text-green-500" />}
                        {sanction.action === 'restrict' ? 'Restricted' : 'Unrestricted'}
                        {sanction.restriction_type && sanction.action === 'restrict' && (
                          <Badge variant="outline" className="text-[9px] px-1 py-0 ml-1">
                            {sanction.restriction_type === 'permanent' ? 'Permanent' : `${formatDuration(sanction.duration_hours ?? 0)}`}
                          </Badge>
                        )}
                      </span>
                      <span className="text-muted-foreground">{formatDateTime(sanction.created_at)}</span>
                    </div>
                    <p className="text-muted-foreground">By <span className="font-medium text-foreground">{sanction.admin_username}</span></p>
                    {sanction.reason && <p className="text-muted-foreground italic">&quot;{sanction.reason}&quot;</p>}
                    {sanction.expires_at && sanction.action === 'restrict' && <p className="text-muted-foreground">Expires: {formatDateTime(sanction.expires_at)}</p>}
                    {currentUserIsSuperAdmin && (
                      <div className="flex justify-end pt-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-6 px-2 text-[10px] text-destructive hover:text-destructive"
                          onClick={() => onAskDeleteSanction(sanction.id)}
                          disabled={moderating !== null}
                        >
                          <Trash2 className="h-3 w-3 mr-1" />Delete
                        </Button>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {!detail.is_super_admin && !isCurrentUser && currentUserIsSuperAdmin && (
        <AdminActionsCard
          isAdmin={detail.is_admin}
          isCurrentUser={isCurrentUser}
          currentUserIsSuperAdmin={currentUserIsSuperAdmin}
          moderating={moderating}
          onAskToggleAdmin={onAskToggleAdmin}
          onAskResetSessions={onAskResetSessions}
          onAskDeleteUser={onAskDeleteUser}
        />
      )}
    </div>
  )
}
