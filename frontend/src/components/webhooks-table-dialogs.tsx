'use client'

import type { Dispatch, FormEvent, SetStateAction } from 'react'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Button } from '@/components/ui/button'
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'
import type { Webhook } from '@/lib/api'
import type { WebhookFormData } from '@/components/webhooks-table.types'

interface WebhooksTableDialogsProps {
  isDialogOpen: boolean
  setIsDialogOpen: Dispatch<SetStateAction<boolean>>
  editingWebhook: Webhook | null
  formData: WebhookFormData
  setFormData: Dispatch<SetStateAction<WebhookFormData>>
  error: string
  onCreateDialogChange?: (open: boolean) => void
  onSubmit: (e: FormEvent) => void
  createPending: boolean
  updatePending: boolean

  deleteConfirmOpen: boolean
  onDeleteConfirmOpenChange: (open: boolean) => void
  deleteDialogName: string
  onConfirmDelete: () => void

  batchDeleteOpen: boolean
  onBatchDeleteOpenChange: (open: boolean) => void
  batchDeleteSize: number
  totalWebhooks: number
  onConfirmBatchDelete: () => void
}

export function WebhooksTableDialogs({
  isDialogOpen,
  setIsDialogOpen,
  editingWebhook,
  formData,
  setFormData,
  error,
  onCreateDialogChange,
  onSubmit,
  createPending,
  updatePending,
  deleteConfirmOpen,
  onDeleteConfirmOpenChange,
  deleteDialogName,
  onConfirmDelete,
  batchDeleteOpen,
  onBatchDeleteOpenChange,
  batchDeleteSize,
  totalWebhooks,
  onConfirmBatchDelete,
}: WebhooksTableDialogsProps) {
  return (
    <>
      <Dialog
        open={isDialogOpen}
        onOpenChange={(open) => {
          setIsDialogOpen(open)
          if (!open) onCreateDialogChange?.(false)
        }}
      >
        <DialogContent className="sm:max-w-md">
          <form onSubmit={onSubmit}>
            <DialogHeader>
              <DialogTitle>{editingWebhook ? 'Edit Webhook' : 'Create New Webhook'}</DialogTitle>
              <DialogDescription>
                {editingWebhook
                  ? 'Update your webhook configuration. URLs are encrypted for security.'
                  : 'Add a new webhook endpoint for receiving notifications. URLs are encrypted and stored securely.'}
              </DialogDescription>
            </DialogHeader>

            <div className="grid gap-4 py-4">
              <div className="space-y-2">
                <Label htmlFor="name">Name</Label>
                <Input
                  id="name"
                  value={formData.name}
                  onChange={(e) => setFormData((prev) => ({ ...prev, name: e.target.value }))}
                  placeholder="My Discord Webhook"
                  maxLength={50}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="webhook_url">
                  Webhook URL {editingWebhook ? '(optional - leave empty to keep current)' : ''}
                </Label>
                <Input
                  id="webhook_url"
                  type="url"
                  value={formData.webhook_url}
                  onChange={(e) => setFormData((prev) => ({ ...prev, webhook_url: e.target.value }))}
                  placeholder={editingWebhook ? 'Leave empty to keep current URL' : 'https://discord.com/api/webhooks/...'}
                  required={!editingWebhook}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="notification_style">Notification Style</Label>
                <Select
                  value={formData.notification_style}
                  onValueChange={(value: 'compact' | 'detailed') =>
                    setFormData((prev) => ({ ...prev, notification_style: value }))
                  }
                >
                  <SelectTrigger id="notification_style">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="compact">Compact</SelectItem>
                    <SelectItem value="detailed">Detailed</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="flex flex-row items-center justify-between rounded-lg border p-3">
                <div className="space-y-0.5">
                  <Label htmlFor="is_active" className="text-sm font-medium">
                    Enable Webhook
                  </Label>
                  <p className="text-[0.8rem] text-muted-foreground">
                    Webhook will send notifications about alerts
                  </p>
                </div>
                <Switch
                  id="is_active"
                  checked={formData.is_active}
                  onCheckedChange={(checked) => setFormData((prev) => ({ ...prev, is_active: checked }))}
                />
              </div>

              {error && (
                <Alert variant="destructive">
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setIsDialogOpen(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={createPending || updatePending}>
                {(createPending || updatePending) && <LoadingSpinner size="sm" inline />}
                <span className={createPending || updatePending ? 'ml-2' : ''}>
                  {editingWebhook ? 'Update' : 'Create'}
                </span>
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={deleteConfirmOpen}
        onOpenChange={onDeleteConfirmOpenChange}
        title="Delete Webhook"
        description={`Are you sure you want to delete "${deleteDialogName}"? This action cannot be undone.`}
        confirmText="Delete"
        variant="destructive"
        onConfirm={onConfirmDelete}
      />

      <ConfirmDialog
        open={batchDeleteOpen}
        onOpenChange={onBatchDeleteOpenChange}
        title="Delete Webhooks"
        description={
          batchDeleteSize > 0
            ? `Are you sure you want to delete ${batchDeleteSize} selected webhook(s)? This action cannot be undone.`
            : `Are you sure you want to delete ALL ${totalWebhooks} webhooks? This action cannot be undone and will permanently delete all your webhook configurations.`
        }
        confirmText="Delete"
        variant="destructive"
        onConfirm={onConfirmBatchDelete}
      />
    </>
  )
}
