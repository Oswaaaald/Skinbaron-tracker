'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { QUERY_KEYS } from '@/lib/constants'
import { apiClient } from '@/lib/api'
import { formatShortDate } from '@/lib/formatters'
import { useAuth } from '@/contexts/auth-context'
import { useApiMutation } from '@/hooks/use-api-mutation'
import { useToast } from '@/hooks/use-toast'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { Monitor, Smartphone, Tablet, Globe, LogOut, X } from 'lucide-react'

interface Session {
  id: number
  ip_address: string | null
  user_agent: string | null
  created_at: string
  expires_at: string
  is_current: boolean
}

function parseUserAgent(ua: string | null): { device: string; browser: string; icon: typeof Monitor } {
  if (!ua) return { device: 'Unknown Device', browser: 'Unknown', icon: Globe }

  // Detect browser
  let browser = 'Unknown Browser'
  if (ua.includes('Firefox/')) browser = 'Firefox'
  else if (ua.includes('Edg/')) browser = 'Edge'
  else if (ua.includes('OPR/') || ua.includes('Opera/')) browser = 'Opera'
  else if (ua.includes('Chrome/') && !ua.includes('Edg/')) browser = 'Chrome'
  else if (ua.includes('Safari/') && !ua.includes('Chrome/')) browser = 'Safari'
  else if (ua.includes('Brave')) browser = 'Brave'

  // Detect OS
  let os = ''
  if (ua.includes('Windows NT 10')) os = 'Windows 10'
  else if (ua.includes('Windows NT 11') || (ua.includes('Windows NT 10') && ua.includes('Win64'))) os = 'Windows'
  else if (ua.includes('Windows')) os = 'Windows'
  else if (ua.includes('Mac OS X')) os = 'macOS'
  else if (ua.includes('Android')) os = 'Android'
  else if (ua.includes('iPhone') || ua.includes('iPad')) os = 'iOS'
  else if (ua.includes('Linux')) os = 'Linux'
  else if (ua.includes('CrOS')) os = 'ChromeOS'

  // Detect device type
  let icon = Monitor
  if (ua.includes('Mobile') || ua.includes('Android') || ua.includes('iPhone')) {
    icon = Smartphone
  } else if (ua.includes('iPad') || ua.includes('Tablet')) {
    icon = Tablet
  }

  const device = os ? `${browser} on ${os}` : browser
  return { device, browser, icon }
}

export function SessionManager() {
  const { toast } = useToast()
  const { logout } = useAuth()
  const [revokeAllDialog, setRevokeAllDialog] = useState(false)
  const [revokeSessionId, setRevokeSessionId] = useState<number | null>(null)
  const [revokeCurrentDialog, setRevokeCurrentDialog] = useState(false)
  const { data: sessions, isLoading, error } = useQuery<Session[]>({
    queryKey: [QUERY_KEYS.SESSIONS],
    queryFn: async () => {
      const res = await apiClient.get<Session[]>('/api/user/sessions')
      if (!res.success) throw new Error(res.error || 'Failed to fetch sessions')
      return res.data ?? []
    },
  })

  const revokeSessionMutation = useApiMutation(
    (sessionId: number) => apiClient.delete<{ logged_out?: boolean }>(`/api/user/sessions/${sessionId}`),
    {
      invalidateKeys: [[QUERY_KEYS.SESSIONS], [QUERY_KEYS.USER_AUDIT_LOGS]],
      onSuccess: (data) => {
        setRevokeSessionId(null)
        setRevokeCurrentDialog(false)
        if (data?.data?.logged_out) {
          toast({ title: '✅ Session revoked', description: 'You have been logged out.' })
          void logout()
        } else {
          toast({ title: '✅ Session revoked', description: 'The session has been revoked.' })
        }
      },
      onError: () => {
        toast({ variant: 'destructive', title: '❌ Failed', description: 'Failed to revoke session' })
      },
    }
  )

  const revokeAllMutation = useApiMutation(
    () => apiClient.delete('/api/user/sessions'),
    {
      invalidateKeys: [[QUERY_KEYS.SESSIONS], [QUERY_KEYS.USER_AUDIT_LOGS]],
      onSuccess: () => {
        setRevokeAllDialog(false)
        toast({ title: '✅ Other sessions revoked', description: 'All other sessions have been revoked.' })
      },
      onError: () => {
        toast({ variant: 'destructive', title: '❌ Failed', description: 'Failed to revoke sessions' })
      },
    }
  )

  const otherSessions = sessions?.filter(s => !s.is_current) ?? []
  const currentSession = sessions?.find(s => s.is_current)

  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Monitor className="h-5 w-5" /> Active Sessions
          </CardTitle>
          <CardDescription>
            Manage your active sessions across devices and browsers
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {isLoading && (
            <div className="flex items-center justify-center py-6">
              <LoadingSpinner className="h-6 w-6" />
            </div>
          )}

          {error && (
            <p className="text-sm text-destructive">Failed to load sessions.</p>
          )}

          {sessions && sessions.length === 0 && (
            <p className="text-sm text-muted-foreground">No active sessions found.</p>
          )}

          {/* Current session */}
          {currentSession && (
            <SessionRow session={currentSession} onRevoke={() => setRevokeCurrentDialog(true)} />
          )}

          {/* Other sessions */}
          {otherSessions.length > 0 && (
            <div className="space-y-3">
              {currentSession && (
                <div className="border-t pt-3">
                  <p className="text-xs text-muted-foreground font-medium uppercase tracking-wide mb-3">Other sessions</p>
                </div>
              )}
              {otherSessions.map(session => (
                <SessionRow
                  key={session.id}
                  session={session}
                  onRevoke={() => setRevokeSessionId(session.id)}
                />
              ))}
            </div>
          )}

          {/* Revoke all other sessions */}
          {otherSessions.length > 0 && (
            <div className="border-t pt-4">
              <Button
                variant="outline"
                className="text-destructive hover:text-destructive"
                onClick={() => setRevokeAllDialog(true)}
              >
                <LogOut className="h-4 w-4 mr-2" />
                Revoke all other sessions
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Confirm revoke single session (non-current) */}
      <ConfirmDialog
        open={revokeSessionId !== null}
        onOpenChange={(open) => !open && setRevokeSessionId(null)}
        title="Revoke this session?"
        description="This device will be signed out immediately."
        confirmText="Revoke"
        variant="destructive"
        onConfirm={() => revokeSessionId !== null && revokeSessionMutation.mutate(revokeSessionId)}
      />

      {/* Confirm revoke current session */}
      <ConfirmDialog
        open={revokeCurrentDialog}
        onOpenChange={setRevokeCurrentDialog}
        title="Revoke current session?"
        description="You will be logged out of this device immediately and will need to log in again."
        confirmText="Log out"
        variant="destructive"
        onConfirm={() => currentSession && revokeSessionMutation.mutate(currentSession.id)}
      />

      {/* Confirm revoke all other sessions */}
      <ConfirmDialog
        open={revokeAllDialog}
        onOpenChange={setRevokeAllDialog}
        title="Revoke all other sessions?"
        description="All devices except the current one will be signed out. Your current session will remain active."
        confirmText="Revoke all"
        variant="destructive"
        onConfirm={() => revokeAllMutation.mutate(undefined)}
      />
    </>
  )
}

function SessionRow({ session, onRevoke }: { session: Session; onRevoke?: () => void }) {
  const { device, icon: Icon } = parseUserAgent(session.user_agent)

  return (
    <div className="flex items-center justify-between gap-4 rounded-lg border p-3">
      <div className="flex items-center gap-3 min-w-0">
        <div className="flex-shrink-0 rounded-full bg-muted p-2">
          <Icon className="h-4 w-4 text-muted-foreground" />
        </div>
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <p className="text-sm font-medium truncate">{device}</p>
            {session.is_current && (
              <Badge variant="secondary" className="text-xs shrink-0">Current</Badge>
            )}
          </div>
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            {session.ip_address && <span>{session.ip_address}</span>}
            {session.ip_address && <span>·</span>}
            <span>{formatShortDate(session.created_at)}</span>
          </div>
        </div>
      </div>
      {onRevoke && (
        <Button
          variant="ghost"
          size="icon"
          className="shrink-0 text-muted-foreground hover:text-destructive"
          onClick={onRevoke}
          title={session.is_current ? 'Log out' : 'Revoke session'}
        >
          {session.is_current ? <LogOut className="h-4 w-4" /> : <X className="h-4 w-4" />}
        </Button>
      )}
    </div>
  )
}
