'use client'

import { useState, useRef } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { UserDetailSkeleton } from '@/components/ui/skeletons'
import { Label } from '@/components/ui/label'
import { Shield, ShieldOff, Key, Link2, ShieldCheck, Fingerprint, Clock, Mail, User, AlertTriangle, Camera, Trash2, Ban, Pencil, Check, X, FileWarning, ScrollText, RotateCcw, LogOut } from 'lucide-react'
import { apiClient, type AdminUserDetail, type Sanction } from '@/lib/api'
import { useToast } from '@/hooks/use-toast'
import { extractErrorMessage } from '@/lib/utils'
import { Input } from '@/components/ui/input'
import { QUERY_KEYS } from '@/lib/constants'
import { useAuth } from '@/contexts/auth-context'
import { PROVIDER_ICONS } from '@/lib/oauth-icons'
import { UserAvatar } from '@/components/ui/user-avatar'

interface AdminUserDetailDialogProps {
  userId: number | null
  open: boolean
  onOpenChange: (open: boolean) => void
}

const DURATION_PRESETS = [
  { label: '1h', hours: 1 },
  { label: '6h', hours: 6 },
  { label: '12h', hours: 12 },
  { label: '24h', hours: 24 },
  { label: '3d', hours: 72 },
  { label: '7d', hours: 168 },
  { label: '14d', hours: 336 },
  { label: '30d', hours: 720 },
] as const

function formatDate(dateStr: string | null | undefined): string {
  if (!dateStr) return '—'
  return new Date(dateStr).toLocaleString('en-GB', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    timeZone: 'Europe/Paris',
  })
}

function formatDuration(hours: number): string {
  if (hours < 24) return `${hours}h`
  const days = Math.floor(hours / 24)
  const rem = hours % 24
  return rem > 0 ? `${days}d ${rem}h` : `${days}d`
}

export function AdminUserDetailDialog({ userId, open, onOpenChange }: AdminUserDetailDialogProps) {
  const { toast } = useToast()
  const { user: currentUser } = useAuth()
  const queryClient = useQueryClient()

  // Avatar
  const [removingAvatar, setRemovingAvatar] = useState(false)

  // Username editing
  const [editingUsername, setEditingUsername] = useState(false)
  const [newUsername, setNewUsername] = useState('')

  // Restriction form
  const [restrictionType, setRestrictionType] = useState<'temporary' | 'permanent'>('temporary')
  const [durationHours, setDurationHours] = useState<number>(24)
  const [restrictReason, setRestrictReason] = useState('')
  const [banEmail, setBanEmail] = useState(true)

  // Unrestrict form
  const [unrestrictReason, setUnrestrictReason] = useState('')

  // Confirmation dialogs
  const [confirmRestrict, setConfirmRestrict] = useState(false)
  const [confirmUnrestrict, setConfirmUnrestrict] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [confirmToggleAdmin, setConfirmToggleAdmin] = useState<'grant' | 'revoke' | null>(null)
  const [confirmDeleteSanction, setConfirmDeleteSanction] = useState<number | null>(null)
  const [confirmReset, setConfirmReset] = useState<'2fa' | 'passkeys' | 'sessions' | null>(null)
  // Keep last non-null values so dialog text stays stable during close animation
  const lastToggleAdmin = useRef<'grant' | 'revoke'>('grant')
  const lastReset = useRef<'2fa' | 'passkeys' | 'sessions'>('2fa')
  const lastDeleteSanction = useRef<number>(0)
  if (confirmToggleAdmin) lastToggleAdmin.current = confirmToggleAdmin
  if (confirmReset) lastReset.current = confirmReset
  if (confirmDeleteSanction) lastDeleteSanction.current = confirmDeleteSanction

  // Loading states
  const [moderating, setModerating] = useState<string | null>(null)

  const { data: detail, isLoading } = useQuery({
    queryKey: ['admin-user-detail', userId],
    queryFn: async () => {
      const res = apiClient.ensureSuccess(
        await apiClient.getAdminUserDetail(userId ?? 0),
        'Failed to load user detail'
      )
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
      // Delay form reset until after close animation
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

  const isCurrentUser = detail && currentUser?.id === detail.id
  const isRestrictionExpired = detail?.is_restricted && detail.restriction_type === 'temporary' && detail.restriction_expires_at && new Date(detail.restriction_expires_at) <= new Date()

  return (
    <>
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-7xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-lg">
            <User className="h-5 w-5" />
            User Profile — {detail?.username ?? '...'}
          </DialogTitle>
          <DialogDescription>
            GDPR-audited — This access is logged.
          </DialogDescription>
        </DialogHeader>

        {isLoading ? (
          <UserDetailSkeleton />
        ) : detail ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* LEFT COLUMN — Info */}
            <div className="space-y-4">
              {/* Identity */}
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <User className="h-4 w-4" />
                    Identity
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {/* Avatar */}
                  <div className="flex items-center gap-4">
                    <UserAvatar
                      src={detail.avatar_url}
                      alt={detail.username}
                      fallback={detail.username.slice(0, 2).toUpperCase()}
                      size={64}
                      className="ring-2 ring-border"
                    />
                    <div className="flex-1 min-w-0">
                      <p className="font-semibold text-base truncate">{detail.username}</p>
                      <p className="text-xs text-muted-foreground flex items-center gap-1">
                        <Camera className="h-3 w-3" />
                        {detail.has_custom_avatar ? 'Custom avatar' : detail.avatar_url ? 'Gravatar' : 'No avatar'}
                      </p>
                    </div>
                    {detail.has_custom_avatar && (
                      <Button variant="outline" size="sm" onClick={() => void handleRemoveAvatar()} disabled={removingAvatar} className="text-destructive hover:text-destructive shrink-0">
                        {removingAvatar ? <LoadingSpinner size="sm" inline /> : <><Trash2 className="h-3.5 w-3.5 mr-1.5" /> Remove</>}
                      </Button>
                    )}
                  </div>
                  <Separator />
                  <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                    <div>
                      <span className="text-muted-foreground">Username</span>
                      <div className="flex items-center gap-1.5">
                        {editingUsername ? (
                          <>
                            <Input
                              value={newUsername}
                              onChange={e => setNewUsername(e.target.value)}
                              className="h-7 text-sm w-28"
                              placeholder={detail.username}
                              maxLength={32}
                              onKeyDown={e => { if (e.key === 'Enter') void handleChangeUsername(); if (e.key === 'Escape') { setEditingUsername(false); setNewUsername('') } }}
                            />
                            <Button variant="ghost" size="icon" className="h-6 w-6" onClick={() => void handleChangeUsername()} disabled={moderating === 'username' || !newUsername.trim()}>
                              <Check className="h-3 w-3" />
                            </Button>
                            <Button variant="ghost" size="icon" className="h-6 w-6" onClick={() => { setEditingUsername(false); setNewUsername('') }}>
                              <X className="h-3 w-3" />
                            </Button>
                          </>
                        ) : (
                          <>
                            <p className="font-medium">{detail.username}</p>
                            {!detail.is_super_admin && (
                              <Button variant="ghost" size="icon" className="h-6 w-6" onClick={() => { setEditingUsername(true); setNewUsername(detail.username) }}>
                                <Pencil className="h-3 w-3" />
                              </Button>
                            )}
                          </>
                        )}
                      </div>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Email</span>
                      <p className="font-medium flex items-center gap-1 text-xs">
                        <Mail className="h-3 w-3" />
                        {detail.email}
                      </p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Role</span>
                      <div className="mt-0.5">
                        {detail.is_super_admin ? (
                          <Badge className="gap-1 bg-gradient-to-r from-purple-600 to-pink-600 text-white">
                            <Shield className="h-3 w-3" />
                            Super Admin
                          </Badge>
                        ) : detail.is_admin ? (
                          <Badge variant="default" className="gap-1">
                            <Shield className="h-3 w-3" />
                            Admin
                          </Badge>
                        ) : (
                          <Badge variant="outline">User</Badge>
                        )}
                      </div>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Status</span>
                      <div className="mt-0.5 flex flex-wrap gap-1">
                        {detail.is_restricted && detail.restriction_type === 'permanent' ? (
                          <Badge variant="destructive" className="gap-1">
                            <Ban className="h-3 w-3" />
                            Permanently Restricted
                          </Badge>
                        ) : detail.is_restricted && detail.restriction_type === 'temporary' && !isRestrictionExpired ? (
                          <Badge variant="secondary" className="gap-1 bg-orange-500/15 text-orange-600 dark:text-orange-400">
                            <Clock className="h-3 w-3" />
                            Restricted until {formatDate(detail.restriction_expires_at)}
                          </Badge>
                        ) : (
                          <Badge variant={detail.is_approved ? 'default' : 'secondary'}>
                            {detail.is_approved ? 'Active' : 'Pending'}
                          </Badge>
                        )}
                      </div>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Registered</span>
                      <p className="font-medium text-xs">{formatDate(detail.created_at)}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Last Updated</span>
                      <p className="font-medium text-xs">{formatDate(detail.updated_at)}</p>
                    </div>
                    <div>
                      <span className="text-muted-foreground">ToS Accepted</span>
                      <p className="font-medium text-xs">{detail.tos_accepted_at ? formatDate(detail.tos_accepted_at) : <span className="text-amber-500 flex items-center gap-1"><AlertTriangle className="h-3 w-3" /> Not accepted</span>}</p>
                    </div>
                  </div>
                </CardContent>
              </Card>

              {/* Security */}
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <ShieldCheck className="h-4 w-4" />
                    Security
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground flex items-center gap-1.5">
                      <Key className="h-3.5 w-3.5" />
                      Two-Factor Auth (TOTP)
                    </span>
                    <div className="flex items-center gap-2">
                      <Badge variant={detail.totp_enabled ? 'default' : 'outline'}>
                        {detail.totp_enabled ? '✅ Enabled' : '❌ Disabled'}
                      </Badge>
                      {detail.totp_enabled && !detail.is_super_admin && !isCurrentUser && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-6 px-2 text-[10px] text-destructive hover:text-destructive"
                          onClick={() => setConfirmReset('2fa')}
                          disabled={moderating !== null}
                        >
                          <RotateCcw className="h-3 w-3 mr-1" />
                          Reset
                        </Button>
                      )}
                    </div>
                  </div>

                  <Separator />

                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm text-muted-foreground flex items-center gap-1.5">
                        <Fingerprint className="h-3.5 w-3.5" />
                        Passkeys
                      </span>
                      <div className="flex items-center gap-2">
                        <Badge variant="secondary">{detail.passkeys.length}</Badge>
                        {detail.passkeys.length > 0 && !detail.is_super_admin && !isCurrentUser && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="h-6 px-2 text-[10px] text-destructive hover:text-destructive"
                            onClick={() => setConfirmReset('passkeys')}
                            disabled={moderating !== null}
                          >
                            <Trash2 className="h-3 w-3 mr-1" />
                            Remove all
                          </Button>
                        )}
                      </div>
                    </div>
                    {detail.passkeys.length > 0 ? (
                      <div className="space-y-1.5">
                        {detail.passkeys.map(pk => (
                          <div key={pk.id} className="flex items-center justify-between bg-muted/50 rounded-md px-3 py-1.5 text-xs">
                            <span className="font-medium">{pk.name}</span>
                            <div className="flex items-center gap-2">
                              <Badge variant={pk.device_type === 'multiDevice' ? 'secondary' : 'outline'} className="text-[10px] px-1.5">
                                {pk.device_type === 'multiDevice' ? 'Synced' : 'Device-bound'}
                              </Badge>
                              <span className="text-muted-foreground">
                                {pk.last_used_at ? `Used ${formatDate(pk.last_used_at)}` : 'Never used'}
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-xs text-muted-foreground">No passkeys registered</p>
                    )}
                  </div>
                </CardContent>
              </Card>

              {/* Linked Accounts */}
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <Link2 className="h-4 w-4" />
                    Linked Accounts
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {detail.oauth_accounts.length > 0 ? (
                    <div className="space-y-1.5">
                      {detail.oauth_accounts.map(acc => (
                        <div key={acc.id} className="flex items-center justify-between bg-muted/50 rounded-md px-3 py-1.5 text-sm">
                          <span className="flex items-center gap-2">
                            {PROVIDER_ICONS[acc.provider as keyof typeof PROVIDER_ICONS] ?? <Link2 className="h-4 w-4" />}
                            <span className="font-medium capitalize">{acc.provider}</span>
                          </span>
                          <span className="text-xs text-muted-foreground">
                            {acc.provider_email || 'No email'}
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-muted-foreground">No linked accounts</p>
                  )}
                </CardContent>
              </Card>

              {/* Activity Stats */}
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-medium flex items-center gap-2">
                    <Clock className="h-4 w-4" />
                    Activity
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-3 gap-3 text-sm">
                    <div className="bg-muted/50 rounded-md px-3 py-2">
                      <span className="text-muted-foreground text-xs">Rules</span>
                      <p className="font-bold">{detail.stats.active_rules_count} / {detail.stats.rules_count}</p>
                      <span className="text-[10px] text-muted-foreground">active / total</span>
                    </div>
                    <div className="bg-muted/50 rounded-md px-3 py-2">
                      <span className="text-muted-foreground text-xs">Webhooks</span>
                      <p className="font-bold">{detail.stats.active_webhooks_count} / {detail.stats.webhooks_count}</p>
                      <span className="text-[10px] text-muted-foreground">active / total</span>
                    </div>
                    <div className="bg-muted/50 rounded-md px-3 py-2">
                      <span className="text-muted-foreground text-xs">Alerts</span>
                      <p className="font-bold">{detail.stats.alerts_count}</p>
                      <span className="text-[10px] text-muted-foreground">total received</span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* RIGHT COLUMN — Actions & History */}
            <div className="space-y-4">
              {/* Moderation — Restrict / Unrestrict */}
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
                      /* Currently restricted → show unrestrict form */
                      <div className="space-y-3">
                        <div className="rounded-md bg-red-500/10 border border-red-500/20 p-3 space-y-1">
                          <p className="text-sm font-medium text-red-600 dark:text-red-400 flex items-center gap-2">
                            <Ban className="h-4 w-4" />
                            Account is {detail.restriction_type === 'permanent' ? 'permanently' : 'temporarily'} restricted
                          </p>
                          {detail.restriction_reason && (
                            <p className="text-xs text-muted-foreground">Reason: {detail.restriction_reason}</p>
                          )}
                          {detail.restricted_at && (
                            <p className="text-xs text-muted-foreground">Since: {formatDate(detail.restricted_at)}</p>
                          )}
                          {detail.restriction_type === 'temporary' && detail.restriction_expires_at && (
                            <p className="text-xs text-muted-foreground">Expires: {formatDate(detail.restriction_expires_at)}</p>
                          )}
                        </div>
                        <div className="space-y-2">
                          <Label className="text-xs font-medium">Reason for unrestriction *</Label>
                          <Input
                            value={unrestrictReason}
                            onChange={e => setUnrestrictReason(e.target.value)}
                            placeholder="Why is this user being unrestricted?"
                            className="h-8 text-sm"
                            maxLength={500}
                          />
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => setConfirmUnrestrict(true)}
                            disabled={moderating !== null || !unrestrictReason.trim()}
                            className="w-full"
                          >
                            {moderating === 'unrestrict' ? <LoadingSpinner size="sm" inline /> : 'Remove Restriction'}
                          </Button>
                        </div>
                      </div>
                    ) : (
                      /* Not restricted → show restrict form */
                      <div className="space-y-3">
                        <div className="space-y-2">
                          <Label className="text-xs font-medium">Restriction type</Label>
                          <div className="flex gap-2">
                            <Button
                              size="sm"
                              variant={restrictionType === 'temporary' ? 'default' : 'outline'}
                              onClick={() => setRestrictionType('temporary')}
                              className="flex-1"
                            >
                              <Clock className="h-3 w-3 mr-1.5" />
                              Temporary
                            </Button>
                            <Button
                              size="sm"
                              variant={restrictionType === 'permanent' ? 'destructive' : 'outline'}
                              onClick={() => setRestrictionType('permanent')}
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
                              {DURATION_PRESETS.map(preset => (
                                <Button
                                  key={preset.hours}
                                  size="sm"
                                  variant={durationHours === preset.hours ? 'default' : 'outline'}
                                  onClick={() => setDurationHours(preset.hours)}
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
                            <input
                              type="checkbox"
                              checked={banEmail}
                              onChange={e => setBanEmail(e.target.checked)}
                              className="rounded"
                            />
                            Also ban email ({detail.email}) and linked OAuth emails to prevent re-registration
                          </label>
                        )}

                        <div className="space-y-2">
                          <Label className="text-xs font-medium">Reason *</Label>
                          <Input
                            value={restrictReason}
                            onChange={e => setRestrictReason(e.target.value)}
                            placeholder="Why is this user being restricted?"
                            className="h-8 text-sm"
                            maxLength={500}
                          />
                        </div>

                        <Button
                          size="sm"
                          variant="destructive"
                          onClick={() => setConfirmRestrict(true)}
                          disabled={moderating !== null || !restrictReason.trim()}
                          className="w-full gap-1.5"
                        >
                          {moderating === 'restrict' ? (
                            <LoadingSpinner size="sm" inline />
                          ) : (
                            <>
                              <Ban className="h-3.5 w-3.5" />
                              Restrict User ({restrictionType === 'permanent' ? 'Permanent' : formatDuration(durationHours)})
                            </>
                          )}
                        </Button>
                      </div>
                    )}
                  </CardContent>
                </Card>
              )}

              {/* Sanctions History (Casier) */}
              {!detail.is_super_admin && (
                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-medium flex items-center gap-2">
                      <ScrollText className="h-4 w-4" />
                      Sanctions History
                      {detail.sanctions.length > 0 && (
                        <Badge variant="secondary" className="text-[10px] px-1.5">{detail.sanctions.length}</Badge>
                      )}
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    {detail.sanctions.length === 0 ? (
                      <p className="text-xs text-muted-foreground text-center py-4">No sanctions recorded</p>
                    ) : (
                      <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
                        {detail.sanctions.map((s: Sanction) => (
                          <div key={s.id} className={`rounded-md border px-3 py-2 text-xs space-y-1 ${s.action === 'restrict' ? 'border-red-500/20 bg-red-500/5' : 'border-green-500/20 bg-green-500/5'}`}>
                            <div className="flex items-center justify-between">
                              <span className="font-medium flex items-center gap-1.5">
                                {s.action === 'restrict' ? (
                                  <Ban className="h-3 w-3 text-red-500" />
                                ) : (
                                  <Check className="h-3 w-3 text-green-500" />
                                )}
                                {s.action === 'restrict' ? 'Restricted' : 'Unrestricted'}
                                {s.restriction_type && s.action === 'restrict' && (
                                  <Badge variant="outline" className="text-[9px] px-1 py-0 ml-1">
                                    {s.restriction_type === 'permanent' ? 'Permanent' : `${formatDuration(s.duration_hours ?? 0)}`}
                                  </Badge>
                                )}
                              </span>
                              <span className="text-muted-foreground">{formatDate(s.created_at)}</span>
                            </div>
                            <p className="text-muted-foreground">
                              By <span className="font-medium text-foreground">{s.admin_username}</span>
                            </p>
                            {s.reason && (
                              <p className="text-muted-foreground italic">&quot;{s.reason}&quot;</p>
                            )}
                            {s.expires_at && s.action === 'restrict' && (
                              <p className="text-muted-foreground">Expires: {formatDate(s.expires_at)}</p>
                            )}
                            {currentUser?.is_super_admin && (
                              <div className="flex justify-end pt-1">
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="h-6 px-2 text-[10px] text-destructive hover:text-destructive"
                                  onClick={() => setConfirmDeleteSanction(s.id)}
                                  disabled={moderating !== null}
                                >
                                  <Trash2 className="h-3 w-3 mr-1" />
                                  Delete
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

              {/* Admin Actions */}
              {!detail.is_super_admin && !isCurrentUser && currentUser?.is_super_admin && (
                <Card className="border-red-500/20">
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-medium flex items-center gap-2 text-red-600 dark:text-red-400">
                      <Shield className="h-4 w-4" />
                      Admin Actions
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {/* Toggle Admin */}
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium">Admin privileges</p>
                        <p className="text-xs text-muted-foreground">
                          {detail.is_admin ? 'This user has admin access' : 'Grant admin access to this user'}
                        </p>
                      </div>
                      {detail.is_admin ? (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => setConfirmToggleAdmin('revoke')}
                          disabled={moderating !== null || !!isCurrentUser || !currentUser?.is_super_admin}
                          title={!currentUser?.is_super_admin ? 'Only super admins can manage admin status' : isCurrentUser ? 'Cannot modify your own status' : undefined}
                        >
                          <ShieldOff className="h-3.5 w-3.5 mr-1.5" />
                          Revoke Admin
                        </Button>
                      ) : (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => setConfirmToggleAdmin('grant')}
                          disabled={moderating !== null || !currentUser?.is_super_admin}
                          title={!currentUser?.is_super_admin ? 'Only super admins can grant admin status' : undefined}
                        >
                          <Shield className="h-3.5 w-3.5 mr-1.5" />
                          Grant Admin
                        </Button>
                      )}
                    </div>

                    <Separator />

                    {/* Revoke Sessions */}
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium">Revoke all sessions</p>
                        <p className="text-xs text-muted-foreground">
                          Force logout from all devices
                        </p>
                      </div>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => setConfirmReset('sessions')}
                        disabled={moderating !== null}
                        className="text-destructive hover:text-destructive"
                      >
                        <LogOut className="h-3.5 w-3.5 mr-1.5" />
                        Revoke
                      </Button>
                    </div>

                    <Separator />

                    {/* Delete Account */}
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-medium text-red-600 dark:text-red-400">Delete account</p>
                        <p className="text-xs text-muted-foreground">
                          Permanently delete this user and all their data
                        </p>
                      </div>
                      <Button
                        size="sm"
                        variant="destructive"
                        onClick={() => setConfirmDelete(true)}
                        disabled={moderating !== null || !!isCurrentUser || !currentUser?.is_super_admin}
                        title={isCurrentUser ? 'Cannot delete your own account' : !currentUser?.is_super_admin ? 'Only super admins can delete users' : undefined}
                      >
                        <Trash2 className="h-3.5 w-3.5 mr-1.5" />
                        Delete
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>

            {/* GDPR Notice (full width) */}
            <div className="md:col-span-2">
              <p className="text-[10px] text-muted-foreground text-center">
                🔒 This data access has been logged in accordance with GDPR Art. 5(1)(f) — integrity & confidentiality.
              </p>
            </div>
          </div>
        ) : null}
      </DialogContent>
    </Dialog>

    {/* Confirm Restrict */}
    <Dialog open={confirmRestrict} onOpenChange={setConfirmRestrict}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Confirm Restriction</DialogTitle>
          <DialogDescription>
            You are about to {restrictionType === 'permanent' ? 'permanently' : `temporarily (${formatDuration(durationHours)})`} restrict <strong>{detail?.username}</strong>.
            {restrictReason && <><br />Reason: &quot;{restrictReason}&quot;</>}
            {restrictionType === 'permanent' && banEmail && <><br />Email <strong>{detail?.email}</strong> will also be banned.</>}
            <br /><br />
            The user will be immediately logged out and unable to access the platform.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" disabled={moderating === 'restrict'} onClick={() => setConfirmRestrict(false)}>Cancel</Button>
          <Button
            variant="destructive"
            onClick={() => void handleRestrict()}
            disabled={moderating === 'restrict'}
          >
            {moderating === 'restrict' ? 'Restricting...' : 'Confirm Restriction'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    {/* Confirm Unrestrict */}
    <Dialog open={confirmUnrestrict} onOpenChange={setConfirmUnrestrict}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Confirm Unrestriction</DialogTitle>
          <DialogDescription>
            You are about to remove the restriction on <strong>{detail?.username}</strong>.
            <br />Reason: &quot;{unrestrictReason}&quot;
            <br /><br />
            The user will be able to log in and use the platform again.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" disabled={moderating === 'unrestrict'} onClick={() => setConfirmUnrestrict(false)}>Cancel</Button>
          <Button
            onClick={() => void handleUnrestrict()}
            disabled={moderating === 'unrestrict'}
          >
            {moderating === 'unrestrict' ? 'Unrestricting...' : 'Confirm Unrestriction'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    {/* Confirm Delete */}
    <Dialog open={confirmDelete} onOpenChange={setConfirmDelete}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Delete User Account</DialogTitle>
          <DialogDescription>
            Are you sure you want to permanently delete <strong>{detail?.username}</strong>?
            <br /><br />
            This will permanently remove their account and all associated data (rules, alerts, webhooks). This action cannot be undone.
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" disabled={moderating === 'delete'} onClick={() => setConfirmDelete(false)}>Cancel</Button>
          <Button
            variant="destructive"
            onClick={() => void handleDeleteUser()}
            disabled={moderating === 'delete'}
          >
            {moderating === 'delete' ? 'Deleting...' : 'Delete User'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    {/* Confirm Toggle Admin */}
    <Dialog open={confirmToggleAdmin !== null} onOpenChange={(open) => { if (!open) setConfirmToggleAdmin(null) }}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{lastToggleAdmin.current === 'grant' ? 'Grant Admin Access' : 'Revoke Admin Access'}</DialogTitle>
          <DialogDescription>
            Are you sure you want to {lastToggleAdmin.current === 'grant' ? 'grant admin privileges to' : 'revoke admin privileges from'} <strong>{detail?.username}</strong>?
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" disabled={moderating === 'admin'} onClick={() => setConfirmToggleAdmin(null)}>Cancel</Button>
          <Button
            onClick={() => void handleToggleAdmin(confirmToggleAdmin === 'grant')}
            disabled={moderating === 'admin'}
          >
            {moderating === 'admin' ? 'Updating...' : 'Confirm'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    {/* Confirm Reset */}
    <Dialog open={confirmReset !== null} onOpenChange={(open) => { if (!open) setConfirmReset(null) }}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>
            {lastReset.current === '2fa' && 'Reset Two-Factor Authentication'}
            {lastReset.current === 'passkeys' && 'Remove All Passkeys'}
            {lastReset.current === 'sessions' && 'Revoke All Sessions'}
          </DialogTitle>
          <DialogDescription>
            {lastReset.current === '2fa' && (
              <>Are you sure you want to reset 2FA for <strong>{detail?.username}</strong>? This will disable TOTP and delete all recovery codes. The user will need to set up 2FA again.</>
            )}
            {lastReset.current === 'passkeys' && (
              <>Are you sure you want to remove all passkeys ({detail?.passkeys.length}) for <strong>{detail?.username}</strong>? The user will lose all passwordless login methods.</>
            )}
            {lastReset.current === 'sessions' && (
              <>Are you sure you want to revoke all sessions for <strong>{detail?.username}</strong>? The user will be immediately logged out from all devices.</>
            )}
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" disabled={moderating?.startsWith('reset-')} onClick={() => setConfirmReset(null)}>Cancel</Button>
          <Button
            variant="destructive"
            onClick={() => { if (confirmReset) void handleReset(confirmReset) }}
            disabled={moderating?.startsWith('reset-')}
          >
            {moderating?.startsWith('reset-') ? 'Processing...' : 'Confirm'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    {/* Confirm Delete Sanction */}
    <Dialog open={confirmDeleteSanction !== null} onOpenChange={(open) => { if (!open) setConfirmDeleteSanction(null) }}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Delete Sanction</DialogTitle>
          <DialogDescription>
            Are you sure you want to delete this sanction from the history?
            {(() => {
              const s = detail?.sanctions.find(s => s.id === lastDeleteSanction.current)
              if (!s) return null
              const isActive = s.action === 'restrict' && detail?.is_restricted && detail.sanctions.filter(x => x.action === 'restrict')[0]?.id === s.id
              return (
                <>
                  <br /><br />
                  {isActive && <><strong>This is the currently active restriction — the user will be unrestricted.</strong><br /><br /></>}
                  This action cannot be undone.
                </>
              )
            })()}
          </DialogDescription>
        </DialogHeader>
        <DialogFooter>
          <Button variant="outline" disabled={moderating === 'delete-sanction'} onClick={() => setConfirmDeleteSanction(null)}>Cancel</Button>
          <Button
            variant="destructive"
            onClick={() => { if (confirmDeleteSanction) void handleDeleteSanction(confirmDeleteSanction) }}
            disabled={moderating === 'delete-sanction'}
          >
            {moderating === 'delete-sanction' ? 'Deleting...' : 'Delete Sanction'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
    </>
  )
}
