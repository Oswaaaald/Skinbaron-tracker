'use client'

import { useQuery } from '@tanstack/react-query'
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { Shield, Key, Link2, ShieldCheck, Fingerprint, Clock, Mail, User, AlertTriangle } from 'lucide-react'
import { apiClient, type AdminUserDetail } from '@/lib/api'

interface AdminUserDetailDialogProps {
  userId: number | null
  open: boolean
  onOpenChange: (open: boolean) => void
}

function formatDate(dateStr: string | null | undefined): string {
  if (!dateStr) return '—'
  return new Date(dateStr).toLocaleDateString('fr-FR', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function providerIcon(provider: string): string {
  switch (provider) {
    case 'google': return '🔵'
    case 'github': return '⚫'
    case 'discord': return '🟣'
    default: return '🔗'
  }
}

export function AdminUserDetailDialog({ userId, open, onOpenChange }: AdminUserDetailDialogProps) {
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

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <User className="h-5 w-5" />
            User Detail
          </DialogTitle>
          <DialogDescription>
            GDPR-audited — This access is logged.
          </DialogDescription>
        </DialogHeader>

        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <LoadingSpinner size="lg" />
          </div>
        ) : detail ? (
          <div className="space-y-4">
            {/* Identity */}
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <User className="h-4 w-4" />
                  Identity
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                  <div>
                    <span className="text-muted-foreground">Username</span>
                    <p className="font-medium">{detail.username}</p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Email</span>
                    <p className="font-medium flex items-center gap-1">
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
                    <div className="mt-0.5">
                      <Badge variant={detail.is_approved ? 'default' : 'secondary'}>
                        {detail.is_approved ? 'Approved' : 'Pending'}
                      </Badge>
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
                          <span>{providerIcon(acc.provider)}</span>
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
                <div className="grid grid-cols-2 gap-3 text-sm">
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
                </div>
              </CardContent>
            </Card>

            {/* GDPR Notice */}
            <p className="text-[10px] text-muted-foreground text-center">
              🔒 This data access has been logged in accordance with GDPR Art. 5(1)(f) — integrity & confidentiality.
            </p>
          </div>
        ) : null}
      </DialogContent>
    </Dialog>
  )
}
