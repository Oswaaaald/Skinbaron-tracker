'use client'

import { LogOut, Shield, ShieldOff, Trash2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'

interface AdminActionsCardProps {
  isAdmin: boolean
  isCurrentUser: boolean
  currentUserIsSuperAdmin?: boolean
  moderating: string | null
  onAskToggleAdmin: (action: 'grant' | 'revoke') => void
  onAskResetSessions: () => void
  onAskDeleteUser: () => void
}

export function AdminActionsCard({
  isAdmin,
  isCurrentUser,
  currentUserIsSuperAdmin,
  moderating,
  onAskToggleAdmin,
  onAskResetSessions,
  onAskDeleteUser,
}: AdminActionsCardProps) {
  return (
    <Card className="border-red-500/20">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-medium flex items-center gap-2 text-red-600 dark:text-red-400">
          <Shield className="h-4 w-4" />
          Admin Actions
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium">Admin privileges</p>
            <p className="text-xs text-muted-foreground">
              {isAdmin ? 'This user has admin access' : 'Grant admin access to this user'}
            </p>
          </div>
          {isAdmin ? (
            <Button
              size="sm"
              variant="outline"
              onClick={() => onAskToggleAdmin('revoke')}
              disabled={moderating !== null || !!isCurrentUser || !currentUserIsSuperAdmin}
              title={!currentUserIsSuperAdmin ? 'Only super admins can manage admin status' : isCurrentUser ? 'Cannot modify your own status' : undefined}
            >
              <ShieldOff className="h-3.5 w-3.5 mr-1.5" />Revoke Admin
            </Button>
          ) : (
            <Button
              size="sm"
              variant="outline"
              onClick={() => onAskToggleAdmin('grant')}
              disabled={moderating !== null || !currentUserIsSuperAdmin}
              title={!currentUserIsSuperAdmin ? 'Only super admins can grant admin status' : undefined}
            >
              <Shield className="h-3.5 w-3.5 mr-1.5" />Grant Admin
            </Button>
          )}
        </div>

        <Separator />

        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium">Revoke all sessions</p>
            <p className="text-xs text-muted-foreground">Force logout from all devices</p>
          </div>
          <Button
            size="sm"
            variant="outline"
            onClick={onAskResetSessions}
            disabled={moderating !== null}
            className="text-destructive hover:text-destructive"
          >
            <LogOut className="h-3.5 w-3.5 mr-1.5" />Revoke
          </Button>
        </div>

        <Separator />

        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm font-medium text-red-600 dark:text-red-400">Delete account</p>
            <p className="text-xs text-muted-foreground">Permanently delete this user and all their data</p>
          </div>
          <Button
            size="sm"
            variant="destructive"
            onClick={onAskDeleteUser}
            disabled={moderating !== null || !!isCurrentUser || !currentUserIsSuperAdmin}
            title={isCurrentUser ? 'Cannot delete your own account' : !currentUserIsSuperAdmin ? 'Only super admins can delete users' : undefined}
          >
            <Trash2 className="h-3.5 w-3.5 mr-1.5" />Delete
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
