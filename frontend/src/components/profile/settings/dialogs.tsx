'use client'

import type { Dispatch, FormEvent, ReactNode, SetStateAction } from 'react'
import { AlertCircle } from 'lucide-react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { LoadingSpinner } from '@/components/ui/loading-spinner'

interface UserLike {
  username?: string
  has_password?: boolean
}

interface StatsLike {
  rules_count?: number
  alerts_count?: number
  webhooks_count?: number
}

interface ProfileSettingsDialogsProps {
  user: UserLike | null
  stats?: StatsLike
  twoFactorEnabled?: boolean
  twoFactorError?: string

  confirmAvatarDelete: boolean
  setConfirmAvatarDelete: Dispatch<SetStateAction<boolean>>
  onConfirmAvatarDelete: () => void

  exportDialog: boolean
  setExportDialog: Dispatch<SetStateAction<boolean>>
  onConfirmExport: () => void

  disableTwoFactorDialog: boolean
  setDisableTwoFactorDialog: Dispatch<SetStateAction<boolean>>
  twoFactorPassword: string
  setTwoFactorPassword: Dispatch<SetStateAction<string>>
  disableTwoFactorPending: boolean
  onSubmitDisable2FA: (e: FormEvent) => void
  onResetTwoFactorForm: () => void

  deleteDialog: boolean
  setDeleteDialog: Dispatch<SetStateAction<boolean>>
  deleteConfirmText: string
  setDeleteConfirmText: Dispatch<SetStateAction<string>>
  deletePassword: string
  setDeletePassword: Dispatch<SetStateAction<string>>
  deleteError: string
  deleteAccountPending: boolean
  onConfirmDeleteAccount: () => void
  onResetDeleteForm: () => void

  twoFactorSetupElement: ReactNode
}

export function ProfileSettingsDialogs({
  user,
  stats,
  twoFactorEnabled,
  twoFactorError,
  confirmAvatarDelete,
  setConfirmAvatarDelete,
  onConfirmAvatarDelete,
  exportDialog,
  setExportDialog,
  onConfirmExport,
  disableTwoFactorDialog,
  setDisableTwoFactorDialog,
  twoFactorPassword,
  setTwoFactorPassword,
  disableTwoFactorPending,
  onSubmitDisable2FA,
  onResetTwoFactorForm,
  deleteDialog,
  setDeleteDialog,
  deleteConfirmText,
  setDeleteConfirmText,
  deletePassword,
  setDeletePassword,
  deleteError,
  deleteAccountPending,
  onConfirmDeleteAccount,
  onResetDeleteForm,
  twoFactorSetupElement,
}: ProfileSettingsDialogsProps) {
  return (
    <>
      <ConfirmDialog
        open={confirmAvatarDelete}
        onOpenChange={setConfirmAvatarDelete}
        title="Remove Avatar"
        description="Are you sure you want to remove your custom avatar? You can always upload a new one later."
        confirmText="Remove"
        variant="destructive"
        onConfirm={onConfirmAvatarDelete}
      />

      {twoFactorSetupElement}

      <ConfirmDialog
        open={exportDialog}
        onOpenChange={setExportDialog}
        title="Export My Data"
        description="This will download all your personal data (profile, rules, webhooks, alerts, audit logs) as a JSON file."
        confirmText="Export"
        onConfirm={onConfirmExport}
      />

      <Dialog open={disableTwoFactorDialog} onOpenChange={setDisableTwoFactorDialog}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Disable Two-Factor Authentication?</DialogTitle>
            <DialogDescription>
              {user?.has_password
                ? 'Enter your password to confirm disabling 2FA'
                : 'Enter a 2FA code from your authenticator app to confirm'}
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={onSubmitDisable2FA}>
            <div className="space-y-4">
              {twoFactorError && (
                <Alert variant="destructive">
                  <AlertCircle className="h-4 w-4" />
                  <AlertDescription>{twoFactorError}</AlertDescription>
                </Alert>
              )}
              <Alert variant="destructive">
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>
                  Your account will be less secure without 2FA protection.
                </AlertDescription>
              </Alert>
              <div className="space-y-2">
                <Label htmlFor="2fa-password">{user?.has_password ? 'Password' : '2FA Code'}</Label>
                <Input
                  id="2fa-password"
                  type={user?.has_password ? 'password' : 'text'}
                  inputMode={user?.has_password ? undefined : 'numeric'}
                  maxLength={user?.has_password ? undefined : 8}
                  value={twoFactorPassword}
                  onChange={(e) => setTwoFactorPassword(e.target.value)}
                  placeholder={user?.has_password ? 'Enter your password' : 'Enter 2FA or recovery code'}
                />
              </div>
            </div>
            <DialogFooter className="mt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setDisableTwoFactorDialog(false)
                  onResetTwoFactorForm()
                }}
              >
                Cancel
              </Button>
              <Button type="submit" variant="destructive" disabled={!twoFactorPassword || disableTwoFactorPending}>
                {disableTwoFactorPending ? (
                  <>
                    <LoadingSpinner size="sm" inline />
                    <span className="ml-2">Disabling...</span>
                  </>
                ) : (
                  'Disable 2FA'
                )}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <Dialog open={deleteDialog} onOpenChange={setDeleteDialog}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Are you absolutely sure?</DialogTitle>
            <DialogDescription>
              This will permanently delete your account and all associated data.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <Alert variant="destructive">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription>
                <strong>Warning:</strong> You will lose access to:
                <ul className="list-disc list-inside mt-2">
                  <li>{stats?.rules_count || 0} active rules</li>
                  <li>{stats?.alerts_count || 0} alert history</li>
                  <li>{stats?.webhooks_count || 0} webhook configurations</li>
                </ul>
              </AlertDescription>
            </Alert>

            <div className="space-y-2">
              <Label htmlFor="delete-confirm">
                Type your username to confirm: <strong>{user?.username}</strong>
              </Label>
              <Input
                id="delete-confirm"
                value={deleteConfirmText}
                onChange={(e) => setDeleteConfirmText(e.target.value)}
                placeholder={user?.username}
              />
            </div>

            {(user?.has_password || twoFactorEnabled) && (
              <div className="space-y-2">
                <Label htmlFor="delete-password">
                  {user?.has_password ? 'Enter your password' : 'Enter your 2FA code'}
                </Label>
                <Input
                  id="delete-password"
                  type={user?.has_password ? 'password' : 'text'}
                  inputMode={user?.has_password ? undefined : 'numeric'}
                  maxLength={user?.has_password ? undefined : 8}
                  value={deletePassword}
                  onChange={(e) => setDeletePassword(e.target.value)}
                  placeholder={user?.has_password ? 'Enter your password' : 'Enter 2FA or recovery code'}
                />
              </div>
            )}

            {deleteError && (
              <Alert variant="destructive">
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>{deleteError}</AlertDescription>
              </Alert>
            )}
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                setDeleteDialog(false)
                onResetDeleteForm()
              }}
            >
              Cancel
            </Button>
            <Button
              variant="destructive"
              onClick={onConfirmDeleteAccount}
              disabled={
                deleteConfirmText !== user?.username ||
                ((user?.has_password || twoFactorEnabled) && !deletePassword) ||
                deleteAccountPending
              }
            >
              {deleteAccountPending ? (
                <>
                  <LoadingSpinner size="sm" inline />
                  <span className="ml-2">Deleting...</span>
                </>
              ) : (
                'Delete My Account'
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
