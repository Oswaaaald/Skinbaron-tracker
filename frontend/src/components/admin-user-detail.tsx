'use client'

import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '@/components/ui/alert-dialog'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { Label } from '@/components/ui/label'
import { Shield, ShieldOff, Key, Link2, ShieldCheck, Fingerprint, Clock, Mail, User, AlertTriangle, Camera, Trash2, Ban, Pencil, Check, X, FileWarning, ScrollText } from 'lucide-react'
import { apiClient, type AdminUserDetail, type Sanction } from '@/lib/api'
import { useToast } from '@/hooks/use-toast'
import { extractErrorMessage } from '@/lib/utils'
import { Input } from '@/components/ui/input'
import { QUERY_KEYS } from '@/lib/constants'
import { useAuth } from '@/contexts/auth-context'
import Image from 'next/image'
import type { ReactNode } from 'react'

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

const PROVIDER_ICONS: Record<string, ReactNode> = {
  google: <svg className="h-4 w-4" viewBox="0 0 24 24"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>,
  github: <svg className="h-4 w-4" viewBox="0 0 24 24" fill="currentColor"><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>,
  discord: <svg className="h-4 w-4" viewBox="0 0 24 24" fill="#5865F2"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/></svg>,
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

  // Loading states
  const [moderating, setModerating] = useState<string | null>(null)

  const { data: detail, isLoading } = useQuery({
    queryKey: ['admin-user-detail', userId],
    queryFn: async () => {
      const res = apiClient.ensureSuccess(
        await apiClient.getAdminUserDetail(userId!),
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
        setRestrictReason('')
        setDurationHours(24)
        setRestrictionType('temporary')
        invalidateAll()
      } else {
        toast({ title: '❌ Failed', description: res.message || 'Failed', variant: 'destructive' })
      }
    } catch (error) {
      toast({ title: '❌ Failed', description: extractErrorMessage(error, 'Failed'), variant: 'destructive' })
    } finally {
      setModerating(null)
      setConfirmRestrict(false)
    }
  }

  const handleUnrestrict = async () => {
    if (!userId || !unrestrictReason.trim()) return
    setModerating('unrestrict')
    try {
      const res = await apiClient.adminUnrestrictUser(userId, unrestrictReason.trim())
      if (res.success) {
        toast({ title: '✅ User unrestricted', description: res.message })
        setUnrestrictReason('')
        invalidateAll()
      } else {
        toast({ title: '❌ Failed', description: res.message || 'Failed', variant: 'destructive' })
      }
    } catch (error) {
      toast({ title: '❌ Failed', description: extractErrorMessage(error, 'Failed'), variant: 'destructive' })
    } finally {
      setModerating(null)
      setConfirmUnrestrict(false)
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
          <div className="flex items-center justify-center py-16">
            <LoadingSpinner size="lg" />
          </div>
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
                    <div className="h-16 w-16 rounded-full overflow-hidden ring-2 ring-border bg-muted flex items-center justify-center shrink-0">
                      {detail.avatar_url ? (
                        <Image src={detail.avatar_url} alt={detail.username} width={64} height={64} className="h-full w-full object-cover" unoptimized />
                      ) : (
                        <span className="text-xl font-semibold text-muted-foreground">
                          {detail.username.slice(0, 2).toUpperCase()}
                        </span>
                      )}
                    </div>
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
                    <Badge variant={detail.totp_enabled ? 'default' : 'outline'}>
                      {detail.totp_enabled ? '✅ Enabled' : '❌ Disabled'}
                    </Badge>
                  </div>

                  <Separator />

                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm text-muted-foreground flex items-center gap-1.5">
                        <Fingerprint className="h-3.5 w-3.5" />
                        Passkeys
                      </span>
                      <Badge variant="secondary">{detail.passkeys.length}</Badge>
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
                            {PROVIDER_ICONS[acc.provider] ?? <Link2 className="h-4 w-4" />}
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
                            Also ban email ({detail.email}) to prevent re-registration
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
                          </div>
                        ))}
                      </div>
                    )}
                  </CardContent>
                </Card>
              )}

              {/* Admin Actions */}
              {!detail.is_super_admin && !isCurrentUser && (
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
                        disabled={moderating !== null || !!isCurrentUser || (detail.is_admin && !currentUser?.is_super_admin)}
                        title={isCurrentUser ? 'Cannot delete your own account' : undefined}
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
    <AlertDialog open={confirmRestrict} onOpenChange={setConfirmRestrict}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Confirm Restriction</AlertDialogTitle>
          <AlertDialogDescription>
            You are about to {restrictionType === 'permanent' ? 'permanently' : `temporarily (${formatDuration(durationHours)})`} restrict <strong>{detail?.username}</strong>.
            {restrictReason && <><br />Reason: &quot;{restrictReason}&quot;</>}
            {restrictionType === 'permanent' && banEmail && <><br />Email <strong>{detail?.email}</strong> will also be banned.</>}
            <br /><br />
            The user will be immediately logged out and unable to access the platform.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={moderating === 'restrict'}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            onClick={(e) => { e.preventDefault(); void handleRestrict() }}
            disabled={moderating === 'restrict'}
            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
          >
            {moderating === 'restrict' ? 'Restricting...' : 'Confirm Restriction'}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>

    {/* Confirm Unrestrict */}
    <AlertDialog open={confirmUnrestrict} onOpenChange={setConfirmUnrestrict}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Confirm Unrestriction</AlertDialogTitle>
          <AlertDialogDescription>
            You are about to remove the restriction on <strong>{detail?.username}</strong>.
            <br />Reason: &quot;{unrestrictReason}&quot;
            <br /><br />
            The user will be able to log in and use the platform again.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={moderating === 'unrestrict'}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            onClick={(e) => { e.preventDefault(); void handleUnrestrict() }}
            disabled={moderating === 'unrestrict'}
          >
            {moderating === 'unrestrict' ? 'Unrestricting...' : 'Confirm Unrestriction'}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>

    {/* Confirm Delete */}
    <AlertDialog open={confirmDelete} onOpenChange={setConfirmDelete}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete User Account</AlertDialogTitle>
          <AlertDialogDescription>
            Are you sure you want to permanently delete <strong>{detail?.username}</strong>?
            <br /><br />
            This will permanently remove their account and all associated data (rules, alerts, webhooks). This action cannot be undone.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={moderating === 'delete'}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            onClick={(e) => { e.preventDefault(); void handleDeleteUser() }}
            disabled={moderating === 'delete'}
            className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
          >
            {moderating === 'delete' ? 'Deleting...' : 'Delete User'}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>

    {/* Confirm Toggle Admin */}
    <AlertDialog open={confirmToggleAdmin !== null} onOpenChange={(open) => { if (!open) setConfirmToggleAdmin(null) }}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{confirmToggleAdmin === 'grant' ? 'Grant Admin Access' : 'Revoke Admin Access'}</AlertDialogTitle>
          <AlertDialogDescription>
            Are you sure you want to {confirmToggleAdmin === 'grant' ? 'grant admin privileges to' : 'revoke admin privileges from'} <strong>{detail?.username}</strong>?
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={moderating === 'admin'}>Cancel</AlertDialogCancel>
          <AlertDialogAction
            onClick={(e) => { e.preventDefault(); void handleToggleAdmin(confirmToggleAdmin === 'grant') }}
            disabled={moderating === 'admin'}
          >
            {moderating === 'admin' ? 'Updating...' : 'Confirm'}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
    </>
  )
}
