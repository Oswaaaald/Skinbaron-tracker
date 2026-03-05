'use client'

import type { Dispatch, SetStateAction } from 'react'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'

interface SecurityDialogsProps {
  username?: string
  passkeysCount: number
  newUsername: string
  removingAvatar: boolean
  moderating: string | null
  confirmToggleAdmin: 'grant' | 'revoke' | null
  setConfirmToggleAdmin: Dispatch<SetStateAction<'grant' | 'revoke' | null>>
  lastToggleAdmin: 'grant' | 'revoke'
  confirmReset: '2fa' | 'passkeys' | 'sessions' | null
  setConfirmReset: Dispatch<SetStateAction<'2fa' | 'passkeys' | 'sessions' | null>>
  lastReset: '2fa' | 'passkeys' | 'sessions'
  confirmRemoveAvatar: boolean
  setConfirmRemoveAvatar: Dispatch<SetStateAction<boolean>>
  confirmChangeUsername: boolean
  setConfirmChangeUsername: Dispatch<SetStateAction<boolean>>
  onConfirmToggleAdmin: (grant: boolean) => void
  onConfirmReset: (target: '2fa' | 'passkeys' | 'sessions') => void
  onConfirmRemoveAvatar: () => void
  onConfirmChangeUsername: () => void
}

export function SecurityDialogs({
  username,
  passkeysCount,
  newUsername,
  removingAvatar,
  moderating,
  confirmToggleAdmin,
  setConfirmToggleAdmin,
  lastToggleAdmin,
  confirmReset,
  setConfirmReset,
  lastReset,
  confirmRemoveAvatar,
  setConfirmRemoveAvatar,
  confirmChangeUsername,
  setConfirmChangeUsername,
  onConfirmToggleAdmin,
  onConfirmReset,
  onConfirmRemoveAvatar,
  onConfirmChangeUsername,
}: SecurityDialogsProps) {
  return (
    <>
      <Dialog open={confirmToggleAdmin !== null} onOpenChange={(open) => { if (!open) setConfirmToggleAdmin(null) }}>
        <DialogContent className="sm:max-w-lg" onKeyDown={(e) => { if (e.key === 'Enter') e.preventDefault() }}>
          <DialogHeader>
            <DialogTitle>{lastToggleAdmin === 'grant' ? 'Grant Admin Access' : 'Revoke Admin Access'}</DialogTitle>
            <DialogDescription>
              Are you sure you want to {lastToggleAdmin === 'grant' ? 'grant admin privileges to' : 'revoke admin privileges from'} <strong>{username}</strong>?
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" disabled={moderating === 'admin'} onClick={() => setConfirmToggleAdmin(null)}>Cancel</Button>
            <Button onClick={() => onConfirmToggleAdmin(confirmToggleAdmin === 'grant')} disabled={moderating === 'admin'}>
              {moderating === 'admin' ? 'Updating...' : 'Confirm'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={confirmReset !== null} onOpenChange={(open) => { if (!open) setConfirmReset(null) }}>
        <DialogContent className="sm:max-w-lg" onKeyDown={(e) => { if (e.key === 'Enter') e.preventDefault() }}>
          <DialogHeader>
            <DialogTitle>
              {lastReset === '2fa' && 'Reset Two-Factor Authentication'}
              {lastReset === 'passkeys' && 'Remove All Passkeys'}
              {lastReset === 'sessions' && 'Revoke All Sessions'}
            </DialogTitle>
            <DialogDescription>
              {lastReset === '2fa' && <>Are you sure you want to reset 2FA for <strong>{username}</strong>? This will disable TOTP and delete all recovery codes. The user will need to set up 2FA again.</>}
              {lastReset === 'passkeys' && <>Are you sure you want to remove all passkeys ({passkeysCount}) for <strong>{username}</strong>? The user will lose all passwordless login methods.</>}
              {lastReset === 'sessions' && <>Are you sure you want to revoke all sessions for <strong>{username}</strong>? The user will be immediately logged out from all devices.</>}
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" disabled={moderating?.startsWith('reset-')} onClick={() => setConfirmReset(null)}>Cancel</Button>
            <Button variant="destructive" onClick={() => { if (confirmReset) onConfirmReset(confirmReset) }} disabled={moderating?.startsWith('reset-')}>
              {moderating?.startsWith('reset-') ? 'Processing...' : 'Confirm'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={confirmRemoveAvatar} onOpenChange={setConfirmRemoveAvatar}>
        <DialogContent className="sm:max-w-md" onKeyDown={(e) => { if (e.key === 'Enter') e.preventDefault() }}>
          <DialogHeader>
            <DialogTitle>Remove User Avatar</DialogTitle>
            <DialogDescription>Are you sure you want to remove this user&apos;s custom avatar? They will fall back to Gravatar or initials.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmRemoveAvatar(false)}>Cancel</Button>
            <Button variant="destructive" onClick={onConfirmRemoveAvatar} disabled={removingAvatar}>
              {removingAvatar ? 'Removing...' : 'Remove Avatar'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={confirmChangeUsername} onOpenChange={setConfirmChangeUsername}>
        <DialogContent className="sm:max-w-md" onKeyDown={(e) => { if (e.key === 'Enter') e.preventDefault() }}>
          <DialogHeader>
            <DialogTitle>Change Username</DialogTitle>
            <DialogDescription>
              Are you sure you want to change this user&apos;s username
              {username ? <> from <strong>{username}</strong> to <strong>{newUsername}</strong></> : ''}?
            </DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" onClick={() => setConfirmChangeUsername(false)}>Cancel</Button>
            <Button onClick={onConfirmChangeUsername} disabled={moderating === 'username'}>
              {moderating === 'username' ? 'Changing...' : 'Change Username'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  )
}
