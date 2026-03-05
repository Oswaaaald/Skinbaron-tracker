'use client'

import { Camera, Check, Clock, Link2, Mail, Pencil, RotateCcw, Shield, ShieldCheck, Trash2, User, X, Key, Fingerprint, AlertTriangle, Ban } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Separator } from '@/components/ui/separator'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { UserAvatar } from '@/components/ui/user-avatar'
import { PROVIDER_ICONS } from '@/lib/oauth-icons'
import { formatDateTime } from '@/lib/formatters'
import type { AdminUserDetail } from '@/lib/api'

interface AdminUserDetailLeftColumnProps {
  detail: AdminUserDetail
  isCurrentUser: boolean
  isRestrictionExpired: boolean
  removingAvatar: boolean
  editingUsername: boolean
  newUsername: string
  moderating: string | null
  onStartEditUsername: () => void
  onCancelEditUsername: () => void
  onNewUsernameChange: (value: string) => void
  onConfirmChangeUsername: () => void
  onAskRemoveAvatar: () => void
  onAskReset2FA: () => void
  onAskResetPasskeys: () => void
}

export function AdminUserDetailLeftColumn({
  detail,
  isCurrentUser,
  isRestrictionExpired,
  removingAvatar,
  editingUsername,
  newUsername,
  moderating,
  onStartEditUsername,
  onCancelEditUsername,
  onNewUsernameChange,
  onConfirmChangeUsername,
  onAskRemoveAvatar,
  onAskReset2FA,
  onAskResetPasskeys,
}: AdminUserDetailLeftColumnProps) {
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <User className="h-4 w-4" />
            Identity
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center gap-4">
            <UserAvatar
              src={detail.avatar_url}
              alt=""
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
              <Button
                variant="outline"
                size="sm"
                onClick={onAskRemoveAvatar}
                disabled={removingAvatar}
                className="text-destructive hover:text-destructive shrink-0"
              >
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
                      onChange={(e) => onNewUsernameChange(e.target.value)}
                      className="h-7 text-sm w-28"
                      placeholder={detail.username}
                      maxLength={32}
                      aria-label="New username"
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') {
                          e.preventDefault()
                          requestAnimationFrame(onConfirmChangeUsername)
                        }
                        if (e.key === 'Escape') onCancelEditUsername()
                      }}
                    />
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-6 w-6"
                      onClick={onConfirmChangeUsername}
                      disabled={moderating === 'username' || !newUsername.trim()}
                      aria-label="Confirm username change"
                    >
                      <Check className="h-3 w-3" />
                    </Button>
                    <Button variant="ghost" size="icon" className="h-6 w-6" onClick={onCancelEditUsername} aria-label="Cancel username edit">
                      <X className="h-3 w-3" />
                    </Button>
                  </>
                ) : (
                  <>
                    <p className="font-medium">{detail.username}</p>
                    {!detail.is_super_admin && (
                      <Button variant="ghost" size="icon" className="h-6 w-6" onClick={onStartEditUsername} aria-label="Edit username">
                        <Pencil className="h-3 w-3" />
                      </Button>
                    )}
                  </>
                )}
              </div>
            </div>
            <div>
              <span className="text-muted-foreground">Email</span>
              <p className="font-medium flex items-center gap-1 text-xs"><Mail className="h-3 w-3" />{detail.email}</p>
            </div>
            <div>
              <span className="text-muted-foreground">Role</span>
              <div className="mt-0.5">
                {detail.is_super_admin ? (
                  <Badge className="gap-1 bg-gradient-to-r from-purple-600 to-pink-600 text-white"><Shield className="h-3 w-3" />Super Admin</Badge>
                ) : detail.is_admin ? (
                  <Badge variant="default" className="gap-1"><Shield className="h-3 w-3" />Admin</Badge>
                ) : (
                  <Badge variant="outline">User</Badge>
                )}
              </div>
            </div>
            <div>
              <span className="text-muted-foreground">Status</span>
              <div className="mt-0.5 flex flex-wrap gap-1">
                {detail.is_restricted && detail.restriction_type === 'permanent' ? (
                  <Badge variant="destructive" className="gap-1"><Ban className="h-3 w-3" />Permanently Restricted</Badge>
                ) : detail.is_restricted && detail.restriction_type === 'temporary' && !isRestrictionExpired ? (
                  <Badge variant="secondary" className="gap-1 bg-orange-500/15 text-orange-600 dark:text-orange-400">
                    <Clock className="h-3 w-3" />Restricted until {formatDateTime(detail.restriction_expires_at)}
                  </Badge>
                ) : (
                  <Badge variant={detail.is_approved ? 'default' : 'secondary'}>{detail.is_approved ? 'Active' : 'Pending'}</Badge>
                )}
              </div>
            </div>
            <div><span className="text-muted-foreground">Registered</span><p className="font-medium text-xs">{formatDateTime(detail.created_at)}</p></div>
            <div><span className="text-muted-foreground">Last Updated</span><p className="font-medium text-xs">{formatDateTime(detail.updated_at)}</p></div>
            <div>
              <span className="text-muted-foreground">ToS Accepted</span>
              <p className="font-medium text-xs">
                {detail.tos_accepted_at ? formatDateTime(detail.tos_accepted_at) : <span className="text-amber-500 flex items-center gap-1"><AlertTriangle className="h-3 w-3" /> Not accepted</span>}
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2"><ShieldCheck className="h-4 w-4" />Security</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground flex items-center gap-1.5"><Key className="h-3.5 w-3.5" />Two-Factor Auth (TOTP)</span>
            <div className="flex items-center gap-2">
              <Badge variant={detail.totp_enabled ? 'default' : 'outline'}>{detail.totp_enabled ? '✅ Enabled' : '❌ Disabled'}</Badge>
              {detail.totp_enabled && !detail.is_super_admin && !isCurrentUser && (
                <Button variant="ghost" size="sm" className="h-6 px-2 text-[10px] text-destructive hover:text-destructive" onClick={onAskReset2FA} disabled={moderating !== null}>
                  <RotateCcw className="h-3 w-3 mr-1" />Reset
                </Button>
              )}
            </div>
          </div>

          <Separator />

          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-sm text-muted-foreground flex items-center gap-1.5"><Fingerprint className="h-3.5 w-3.5" />Passkeys</span>
              <div className="flex items-center gap-2">
                <Badge variant="secondary">{detail.passkeys.length}</Badge>
                {detail.passkeys.length > 0 && !detail.is_super_admin && !isCurrentUser && (
                  <Button variant="ghost" size="sm" className="h-6 px-2 text-[10px] text-destructive hover:text-destructive" onClick={onAskResetPasskeys} disabled={moderating !== null}>
                    <Trash2 className="h-3 w-3 mr-1" />Remove all
                  </Button>
                )}
              </div>
            </div>
            {detail.passkeys.length > 0 ? (
              <div className="space-y-1.5">
                {detail.passkeys.map((pk) => (
                  <div key={pk.id} className="flex items-center justify-between bg-muted/50 rounded-md px-3 py-1.5 text-xs">
                    <span className="font-medium">{pk.name}</span>
                    <div className="flex items-center gap-2">
                      <Badge variant={pk.device_type === 'multiDevice' ? 'secondary' : 'outline'} className="text-[10px] px-1.5">
                        {pk.device_type === 'multiDevice' ? 'Synced' : 'Device-bound'}
                      </Badge>
                      <span className="text-muted-foreground">{pk.last_used_at ? `Used ${formatDateTime(pk.last_used_at)}` : 'Never used'}</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : <p className="text-xs text-muted-foreground">No passkeys registered</p>}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3"><CardTitle className="text-sm font-medium flex items-center gap-2"><Link2 className="h-4 w-4" />Linked Accounts</CardTitle></CardHeader>
        <CardContent>
          {detail.oauth_accounts.length > 0 ? (
            <div className="space-y-1.5">
              {detail.oauth_accounts.map((acc) => (
                <div key={acc.id} className="flex items-center justify-between bg-muted/50 rounded-md px-3 py-1.5 text-sm">
                  <span className="flex items-center gap-2">
                    {PROVIDER_ICONS[acc.provider as keyof typeof PROVIDER_ICONS] ?? <Link2 className="h-4 w-4" />}
                    <span className="font-medium capitalize">{acc.provider}</span>
                  </span>
                  <span className="text-xs text-muted-foreground">{acc.provider_email || 'No email'}</span>
                </div>
              ))}
            </div>
          ) : <p className="text-xs text-muted-foreground">No linked accounts</p>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-3"><CardTitle className="text-sm font-medium flex items-center gap-2"><Clock className="h-4 w-4" />Activity</CardTitle></CardHeader>
        <CardContent>
          <div className="grid grid-cols-3 gap-3 text-sm">
            <div className="bg-muted/50 rounded-md px-3 py-2"><span className="text-muted-foreground text-xs">Rules</span><p className="font-bold">{detail.stats.active_rules_count} / {detail.stats.rules_count}</p><span className="text-[10px] text-muted-foreground">active / total</span></div>
            <div className="bg-muted/50 rounded-md px-3 py-2"><span className="text-muted-foreground text-xs">Webhooks</span><p className="font-bold">{detail.stats.active_webhooks_count} / {detail.stats.webhooks_count}</p><span className="text-[10px] text-muted-foreground">active / total</span></div>
            <div className="bg-muted/50 rounded-md px-3 py-2"><span className="text-muted-foreground text-xs">Alerts</span><p className="font-bold">{detail.stats.alerts_count}</p><span className="text-[10px] text-muted-foreground">total received</span></div>
          </div>
        </CardContent>
      </Card>

    </div>
  )
}
