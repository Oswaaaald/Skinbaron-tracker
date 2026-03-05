'use client'

import { ConfirmDialog } from '@/components/ui/confirm-dialog'

interface PendingUserDialogState {
  open: boolean
  userId: number | null
  action: 'approve' | 'reject'
}

interface AdminPanelDialogsProps {
  pendingUserDialog: PendingUserDialogState
  setPendingUserDialog: (next: PendingUserDialogState) => void
  approvePending: boolean
  rejectPending: boolean
  onApprove: (userId: number) => void
  onReject: (userId: number) => void
  schedulerConfirmOpen: boolean
  setSchedulerConfirmOpen: (open: boolean) => void
  onConfirmScheduler: () => void
  sentryConfirmOpen: boolean
  setSentryConfirmOpen: (open: boolean) => void
  onConfirmSentry: () => void
}

export function AdminPanelDialogs({
  pendingUserDialog,
  setPendingUserDialog,
  approvePending,
  rejectPending,
  onApprove,
  onReject,
  schedulerConfirmOpen,
  setSchedulerConfirmOpen,
  onConfirmScheduler,
  sentryConfirmOpen,
  setSentryConfirmOpen,
  onConfirmSentry,
}: AdminPanelDialogsProps) {
  return (
    <>
      <ConfirmDialog
        open={pendingUserDialog.open}
        onOpenChange={(open) => setPendingUserDialog({ ...pendingUserDialog, open })}
        title={pendingUserDialog.action === 'approve' ? 'Approve User' : 'Reject User'}
        description={pendingUserDialog.action === 'approve'
          ? 'This user will be able to log in and use the application.'
          : 'This will permanently delete the user registration.'}
        confirmText={(approvePending || rejectPending) ? 'Processing...' : 'Confirm'}
        variant={pendingUserDialog.action === 'approve' ? 'default' : 'destructive'}
        onConfirm={() => {
          if (!pendingUserDialog.userId) return
          if (pendingUserDialog.action === 'approve') onApprove(pendingUserDialog.userId)
          else onReject(pendingUserDialog.userId)
        }}
      />

      <ConfirmDialog
        open={schedulerConfirmOpen}
        onOpenChange={setSchedulerConfirmOpen}
        title="Run Scheduler"
        description="Force the scheduler to run now? This will check all enabled rules immediately."
        confirmText="Run Now"
        variant="default"
        onConfirm={onConfirmScheduler}
      />

      <ConfirmDialog
        open={sentryConfirmOpen}
        onOpenChange={setSentryConfirmOpen}
        title="Test Sentry"
        description="Send a test error to Sentry? This will appear as a new issue in your Sentry dashboard."
        confirmText="Send Test"
        variant="default"
        onConfirm={onConfirmSentry}
      />
    </>
  )
}
