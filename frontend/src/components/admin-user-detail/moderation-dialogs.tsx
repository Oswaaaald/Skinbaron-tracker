'use client'

import type { Dispatch, SetStateAction } from 'react'
import type { AdminUserDetail } from '@/lib/api'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { formatDuration } from '@/components/admin-user-detail/constants'

interface ModerationDialogsProps {
  detail?: AdminUserDetail
  moderating: string | null
  restrictionType: 'temporary' | 'permanent'
  durationHours: number
  restrictReason: string
  banEmail: boolean
  unrestrictReason: string
  confirmRestrict: boolean
  setConfirmRestrict: Dispatch<SetStateAction<boolean>>
  confirmUnrestrict: boolean
  setConfirmUnrestrict: Dispatch<SetStateAction<boolean>>
  confirmDelete: boolean
  setConfirmDelete: Dispatch<SetStateAction<boolean>>
  confirmDeleteSanction: number | null
  setConfirmDeleteSanction: Dispatch<SetStateAction<number | null>>
  lastDeleteSanction: number
  onConfirmRestrict: () => void
  onConfirmUnrestrict: () => void
  onConfirmDeleteUser: () => void
  onConfirmDeleteSanction: (id: number) => void
}

export function ModerationDialogs({
  detail,
  moderating,
  restrictionType,
  durationHours,
  restrictReason,
  banEmail,
  unrestrictReason,
  confirmRestrict,
  setConfirmRestrict,
  confirmUnrestrict,
  setConfirmUnrestrict,
  confirmDelete,
  setConfirmDelete,
  confirmDeleteSanction,
  setConfirmDeleteSanction,
  lastDeleteSanction,
  onConfirmRestrict,
  onConfirmUnrestrict,
  onConfirmDeleteUser,
  onConfirmDeleteSanction,
}: ModerationDialogsProps) {
  return (
    <>
      <Dialog open={confirmRestrict} onOpenChange={setConfirmRestrict}>
        <DialogContent className="sm:max-w-lg" onKeyDown={(e) => { if (e.key === 'Enter') e.preventDefault() }}>
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
            <Button variant="destructive" onClick={onConfirmRestrict} disabled={moderating === 'restrict'}>
              {moderating === 'restrict' ? 'Restricting...' : 'Confirm Restriction'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={confirmUnrestrict} onOpenChange={setConfirmUnrestrict}>
        <DialogContent className="sm:max-w-lg" onKeyDown={(e) => { if (e.key === 'Enter') e.preventDefault() }}>
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
            <Button onClick={onConfirmUnrestrict} disabled={moderating === 'unrestrict'}>
              {moderating === 'unrestrict' ? 'Unrestricting...' : 'Confirm Unrestriction'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={confirmDelete} onOpenChange={setConfirmDelete}>
        <DialogContent className="sm:max-w-lg" onKeyDown={(e) => { if (e.key === 'Enter') e.preventDefault() }}>
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
            <Button variant="destructive" onClick={onConfirmDeleteUser} disabled={moderating === 'delete'}>
              {moderating === 'delete' ? 'Deleting...' : 'Delete User'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={confirmDeleteSanction !== null} onOpenChange={(open) => { if (!open) setConfirmDeleteSanction(null) }}>
        <DialogContent className="sm:max-w-lg" onKeyDown={(e) => { if (e.key === 'Enter') e.preventDefault() }}>
          <DialogHeader>
            <DialogTitle>Delete Sanction</DialogTitle>
            <DialogDescription>
              Are you sure you want to delete this sanction from the history?
              {(() => {
                const sanction = detail?.sanctions.find((entry) => entry.id === lastDeleteSanction)
                if (!sanction) return null
                const isActive = sanction.action === 'restrict' && detail?.is_restricted && detail.sanctions.filter((x) => x.action === 'restrict')[0]?.id === sanction.id
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
              onClick={() => { if (confirmDeleteSanction) onConfirmDeleteSanction(confirmDeleteSanction) }}
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
