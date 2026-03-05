'use client'

import type { FormEvent } from 'react'
import { AlertCircle, Fingerprint, Lock, Shield, ShieldCheck, Trash2 } from 'lucide-react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { PasskeyManager } from '@/components/profile/settings-passkeys'
import { SessionManager } from '@/components/profile/session-manager'

interface UserLike {
  has_password?: boolean
}

interface Feedback {
  success?: string
  error?: string
}

interface SecurityTabProps {
  user: UserLike | null
  passwordFeedback: Feedback
  currentPassword: string
  newPassword: string
  confirmPassword: string
  twoFactorEnabled?: boolean
  updatePasswordPending: boolean
  setPasswordPending: boolean
  onCurrentPasswordChange: (value: string) => void
  onNewPasswordChange: (value: string) => void
  onConfirmPasswordChange: (value: string) => void
  onSubmitPassword: (e: FormEvent) => void
  onOpenEnable2FA: () => void
  onOpenDisable2FA: () => void
  onOpenDeleteAccount: () => void
}

export function SecurityTab({
  user,
  passwordFeedback,
  currentPassword,
  newPassword,
  confirmPassword,
  twoFactorEnabled,
  updatePasswordPending,
  setPasswordPending,
  onCurrentPasswordChange,
  onNewPasswordChange,
  onConfirmPasswordChange,
  onSubmitPassword,
  onOpenEnable2FA,
  onOpenDisable2FA,
  onOpenDeleteAccount,
}: SecurityTabProps) {
  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Lock className="h-5 w-5" /> {user?.has_password ? 'Change Password' : 'Set Password'}
          </CardTitle>
          <CardDescription>
            {user?.has_password
              ? 'Update your password to keep your account secure'
              : 'Set a password to enable email/password login alongside your social accounts'}
          </CardDescription>
        </CardHeader>
        <CardContent>
          {passwordFeedback.success && (
            <Alert className="border-primary/50 bg-primary/10 mb-4">
              <AlertDescription className="text-primary">{passwordFeedback.success}</AlertDescription>
            </Alert>
          )}
          {passwordFeedback.error && (
            <Alert variant="destructive" className="mb-4">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>{passwordFeedback.error}</AlertDescription>
            </Alert>
          )}
          <form onSubmit={onSubmitPassword} className="space-y-4">
            {user?.has_password && (
              <div className="space-y-2">
                <Label htmlFor="current-password">Current Password</Label>
                <Input
                  id="current-password"
                  type="password"
                  value={currentPassword}
                  onChange={(e) => onCurrentPasswordChange(e.target.value)}
                  placeholder="Enter current password"
                />
              </div>
            )}
            <div className="space-y-2">
              <Label htmlFor="new-password">{user?.has_password ? 'New Password' : 'Password'}</Label>
              <Input
                id="new-password"
                type="password"
                value={newPassword}
                onChange={(e) => onNewPasswordChange(e.target.value)}
                placeholder="Enter new password (min 8 characters)"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="confirm-password">Confirm Password</Label>
              <Input
                id="confirm-password"
                type="password"
                value={confirmPassword}
                onChange={(e) => onConfirmPasswordChange(e.target.value)}
                placeholder="Confirm password"
              />
            </div>
            <Button type="submit" disabled={updatePasswordPending || setPasswordPending}>
              {(updatePasswordPending || setPasswordPending) ? (
                <>
                  <LoadingSpinner size="sm" className="mr-2" inline />
                  {user?.has_password ? 'Updating...' : 'Setting...'}
                </>
              ) : (
                user?.has_password ? 'Change Password' : 'Set Password'
              )}
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5" /> Authenticator App (TOTP)
          </CardTitle>
          <CardDescription>Use an authenticator app like Google Authenticator or Authy</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium">Status:</span>
            {twoFactorEnabled ? (
              <Badge variant="default" className="gap-1"><Shield className="h-3 w-3" /> Enabled</Badge>
            ) : (
              <Badge variant="outline">Disabled</Badge>
            )}
          </div>

          {twoFactorEnabled ? (
            <Alert>
              <Shield className="h-4 w-4" />
              <AlertDescription>
                You&apos;ll be asked for a verification code when logging in. Keep your authenticator app accessible.
              </AlertDescription>
            </Alert>
          ) : (
            <p className="text-sm text-muted-foreground">
              Add an extra layer of security by requiring a verification code when you log in.
            </p>
          )}

          {twoFactorEnabled ? (
            <Button variant="destructive" onClick={onOpenDisable2FA}>Disable 2FA</Button>
          ) : (
            <Button onClick={onOpenEnable2FA}>Enable 2FA</Button>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Fingerprint className="h-5 w-5" /> Passkeys &amp; Hardware Keys
          </CardTitle>
          <CardDescription>Sign in with biometrics, security keys, or device passkeys</CardDescription>
        </CardHeader>
        <CardContent>
          <PasskeyManager />
        </CardContent>
      </Card>

      <SessionManager />

      <Card className="border-destructive/50">
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-destructive">
            <Trash2 className="h-5 w-5" /> Delete Account
          </CardTitle>
          <CardDescription>Permanently delete your account and all associated data</CardDescription>
        </CardHeader>
        <CardContent className="mt-2 space-y-4">
          <Alert variant="destructive">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>
              This action cannot be undone. All your rules, alerts, and webhooks will be permanently deleted.
            </AlertDescription>
          </Alert>
          <Button variant="destructive" onClick={onOpenDeleteAccount}>
            <Trash2 className="h-4 w-4 mr-2" /> Delete Account
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
