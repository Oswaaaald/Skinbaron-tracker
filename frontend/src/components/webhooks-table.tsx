'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Button } from '@/components/ui/button'
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Edit, Trash2 } from 'lucide-react'
import { apiClient, type Webhook } from '@/lib/api'
import { useAuth } from '@/contexts/auth-context'
import { useApiMutation } from '@/hooks/use-api-mutation'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'

interface WebhookFormData {
  name: string
  webhook_url: string
  webhook_type: 'discord' | 'slack' | 'teams' | 'generic'
  is_active: boolean
}

const initialFormData: WebhookFormData = {
  name: '',
  webhook_url: '',
  webhook_type: 'discord',
  is_active: true,
}

export function WebhooksTable() {
  const [isDialogOpen, setIsDialogOpen] = useState(false)
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false)
  const [webhookToDelete, setWebhookToDelete] = useState<Webhook | null>(null)
  const [editingWebhook, setEditingWebhook] = useState<Webhook | null>(null)
  const [formData, setFormData] = useState<WebhookFormData>(initialFormData)
  const [error, setError] = useState('')
  const [selectedWebhooks, setSelectedWebhooks] = useState<Set<number>>(new Set())
  const [batchAction, setBatchAction] = useState<'enable' | 'disable' | 'delete' | null>(null)

  const { isReady, isAuthenticated } = useAuth()

  // Fetch webhooks
  const { data: webhooks, isLoading } = useQuery({
    queryKey: ['webhooks'],
    queryFn: async () => {
      const result = await apiClient.getWebhooks(false) // Don't decrypt for listing
      if (!result.success) throw new Error(result.error)
      return result.data || []
    },
    enabled: isReady && isAuthenticated, // Wait for auth to be ready and user to be authenticated
  })

  // Create webhook mutation
  const createWebhookMutation = useApiMutation(
    (data: WebhookFormData) => apiClient.createWebhook(data).then(result => {
      if (!result.success) throw new Error(result.error)
      return result.data
    }),
    {
      invalidateKeys: [['webhooks'], ['admin', 'stats']],
      successMessage: 'Webhook created successfully',
      onSuccess: () => {
        setIsDialogOpen(false)
        resetForm()
      },
      onError: (error: Error) => {
        setError(error.message)
      },
    }
  )

  // Update webhook mutation
  const updateWebhookMutation = useApiMutation(
    ({ id, data }: { id: number; data: Partial<WebhookFormData> }) => 
      apiClient.updateWebhook(id, data).then(result => {
        if (!result.success) throw new Error(result.error)
        return result.data
      }),
    {
      invalidateKeys: [['webhooks'], ['admin', 'stats']],
      successMessage: 'Webhook updated successfully',
      onSuccess: () => {
        setIsDialogOpen(false)
        resetForm()
      },
      onError: (error: Error) => {
        setError(error.message)
      },
    }
  )

  // Delete webhook mutation
  const deleteWebhookMutation = useApiMutation(
    (id: number) => apiClient.deleteWebhook(id).then(result => {
      if (!result.success) throw new Error(result.error)
      return result.data
    }),
    {
      invalidateKeys: [['webhooks']],
      successMessage: 'Webhook deleted successfully',
      errorMessage: 'Failed to delete webhook',
    }
  )

  const batchEnableMutation = useApiMutation(
    (webhookIds?: number[]) => apiClient.batchEnableWebhooks(webhookIds),
    {
      invalidateKeys: [['webhooks'], ['admin', 'stats']],
      successMessage: 'Webhooks enabled successfully',
    }
  )

  const batchDisableMutation = useApiMutation(
    (webhookIds?: number[]) => apiClient.batchDisableWebhooks(webhookIds),
    {
      invalidateKeys: [['webhooks'], ['admin', 'stats']],
      successMessage: 'Webhooks disabled successfully',
    }
  )

  const batchDeleteMutation = useApiMutation(
    ({ webhookIds, confirmAll }: { webhookIds?: number[]; confirmAll: boolean }) => 
      apiClient.batchDeleteWebhooks(webhookIds, confirmAll),
    {
      invalidateKeys: [['webhooks'], ['admin', 'stats']],
      onSuccess: () => {
        setBatchAction(null)
      },
      successMessage: 'Webhooks deleted successfully',
    }
  )

  const resetForm = () => {
    setFormData(initialFormData)
    setEditingWebhook(null)
    setError('')
  }

  const handleOpenDialog = (webhook?: Webhook) => {
    if (webhook) {
      setEditingWebhook(webhook)
      setFormData({
        name: webhook.name,
        webhook_url: '', // Don't pre-fill encrypted URL
        webhook_type: webhook.webhook_type,
        is_active: webhook.is_active,
      })
    } else {
      resetForm()
    }
    setIsDialogOpen(true)
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!formData.name || !formData.webhook_url) {
      setError('Name and webhook URL are required')
      return
    }

    if (editingWebhook) {
      // Only send fields that might have changed
      const updates: Partial<WebhookFormData> = {
        name: formData.name,
        webhook_type: formData.webhook_type,
        is_active: formData.is_active,
      }
      // Only include URL if it's provided (for updates)
      if (formData.webhook_url.trim()) {
        updates.webhook_url = formData.webhook_url
      }
      updateWebhookMutation.mutate({ id: editingWebhook.id!, data: updates })
    } else {
      createWebhookMutation.mutate(formData)
    }
  }

  const handleDelete = (webhook: Webhook) => {
    setWebhookToDelete(webhook)
    setDeleteConfirmOpen(true)
  }

  const confirmDelete = () => {
    if (webhookToDelete?.id) {
      deleteWebhookMutation.mutate(webhookToDelete.id)
    }
    setWebhookToDelete(null)
  }

  const handleSelectAll = () => {
    if (!webhooks) return
    if (selectedWebhooks.size === webhooks.length) {
      setSelectedWebhooks(new Set())
    } else {
      setSelectedWebhooks(new Set(webhooks.map(w => w.id!).filter(Boolean)))
    }
  }

  const handleSelectWebhook = (webhookId: number) => {
    const newSelection = new Set(selectedWebhooks)
    if (newSelection.has(webhookId)) {
      newSelection.delete(webhookId)
    } else {
      newSelection.add(webhookId)
    }
    setSelectedWebhooks(newSelection)
  }

  const handleBatchEnable = () => {
    const webhookIds = selectedWebhooks.size > 0 ? Array.from(selectedWebhooks) : undefined
    batchEnableMutation.mutate(webhookIds)
    setSelectedWebhooks(new Set())
  }

  const handleBatchDisable = () => {
    const webhookIds = selectedWebhooks.size > 0 ? Array.from(selectedWebhooks) : undefined
    batchDisableMutation.mutate(webhookIds)
    setSelectedWebhooks(new Set())
  }

  const handleBatchDelete = () => {
    setBatchAction('delete')
  }

  const confirmBatchDelete = () => {
    const webhookIds = selectedWebhooks.size > 0 ? Array.from(selectedWebhooks) : undefined
    const confirmAll = selectedWebhooks.size === 0
    batchDeleteMutation.mutate({ webhookIds, confirmAll })
    setSelectedWebhooks(new Set())
  }

  const getWebhookTypeColor = (type: string) => {
    switch (type) {
      case 'discord':
        return 'bg-blue-500'
      case 'slack':
        return 'bg-green-500'
      case 'teams':
        return 'bg-purple-500'
      default:
        return 'bg-gray-500'
    }
  }

  if (isLoading) {
    return <LoadingSpinner />
  }

  const hasWebhooks = webhooks && webhooks.length > 0

  if (!hasWebhooks) {
    return (
      <div className="space-y-4">
        <div className="flex justify-between items-center">
          <div>
            <h2 className="text-2xl font-bold tracking-tight">Webhooks</h2>
            <p className="text-muted-foreground">
              Manage your encrypted webhook endpoints for notifications
            </p>
          </div>
          <Button onClick={() => handleOpenDialog()}>
            Add Webhook
          </Button>
        </div>
        <Card>
          <CardHeader>
            <CardTitle>No Webhooks Found</CardTitle>
            <CardDescription>
              Create your first webhook to receive Discord notifications when alerts are triggered.
            </CardDescription>
          </CardHeader>
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Webhooks</h2>
          <p className="text-muted-foreground">
            Manage your encrypted webhook endpoints for notifications
          </p>
        </div>
          <Button onClick={() => handleOpenDialog()}>
            Add Webhook
          </Button>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">
                {selectedWebhooks.size > 0 ? `${selectedWebhooks.size} selected` : `${webhooks.length} total`}
              </span>
            </div>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={handleBatchEnable}
                disabled={batchEnableMutation.isPending}
              >
                {selectedWebhooks.size > 0 ? 'Enable Selected' : 'Enable All'}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={handleBatchDisable}
                disabled={batchDisableMutation.isPending}
              >
                {selectedWebhooks.size > 0 ? 'Disable Selected' : 'Disable All'}
              </Button>
              <Button
                variant="destructive"
                size="sm"
                onClick={handleBatchDelete}
                disabled={batchDeleteMutation.isPending}
              >
                {selectedWebhooks.size > 0 ? 'Delete Selected' : 'Delete All'}
              </Button>
            </div>
          </div>
        </CardHeader>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-12">
                <input
                  type="checkbox"
                  checked={!!webhooks && selectedWebhooks.size === webhooks.length && webhooks.length > 0}
                  onChange={handleSelectAll}
                  className="cursor-pointer"
                  aria-label="Select all webhooks"
                />
              </TableHead>
              <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {webhooks?.map((webhook) => (
                <TableRow key={webhook.id}>
                  <TableCell>
                    <input
                      type="checkbox"
                      checked={selectedWebhooks.has(webhook.id!)}
                      onChange={() => handleSelectWebhook(webhook.id!)}
                      className="cursor-pointer"
                      aria-label={`Select webhook ${webhook.name}`}
                    />
                  </TableCell>
                  <TableCell className="font-medium">{webhook.name}</TableCell>
                  <TableCell>
                    <Badge className={getWebhookTypeColor(webhook.webhook_type)}>
                      {webhook.webhook_type.toUpperCase()}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge variant={webhook.is_active ? 'default' : 'secondary'}>
                      {webhook.is_active ? 'Active' : 'Inactive'}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {webhook.created_at ? new Date(webhook.created_at).toLocaleDateString('en-GB') : '-'}
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleOpenDialog(webhook)}
                        aria-label="Edit webhook"
                      >
                        <Edit className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleDelete(webhook)}
                        className="text-red-600 hover:text-red-700"
                        aria-label="Delete webhook"
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
      </Card>

      {/* Webhook Dialog */}
      <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
        <DialogContent className="sm:max-w-md">
          <form onSubmit={handleSubmit}>
            <DialogHeader>
              <DialogTitle>
                {editingWebhook ? 'Edit Webhook' : 'Create New Webhook'}
              </DialogTitle>
              <DialogDescription>
                {editingWebhook 
                  ? 'Update your webhook configuration. URLs are encrypted for security.'
                  : 'Add a new webhook endpoint for receiving notifications. URLs are encrypted and stored securely.'
                }
              </DialogDescription>
            </DialogHeader>

            <div className="grid gap-4 py-4">
              <div className="space-y-2">
                <Label htmlFor="name">Name</Label>
                <Input
                  id="name"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  placeholder="My Discord Webhook"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="webhook_url">
                  Webhook URL {editingWebhook && '(leave empty to keep current)'}
                </Label>
                <Input
                  id="webhook_url"
                  type="url"
                  value={formData.webhook_url}
                  onChange={(e) => setFormData({ ...formData, webhook_url: e.target.value })}
                  placeholder="https://discord.com/api/webhooks/..."
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="webhook_type">Type</Label>
                <Select
                  value={formData.webhook_type}
                  onValueChange={(value: 'discord' | 'slack' | 'teams' | 'generic') =>
                    setFormData({ ...formData, webhook_type: value })
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="discord">Discord</SelectItem>
                    <SelectItem value="slack">Slack</SelectItem>
                    <SelectItem value="teams">Microsoft Teams</SelectItem>
                    <SelectItem value="generic">Generic</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="flex items-center space-x-2">
                <Switch
                  id="is_active"
                  checked={formData.is_active}
                  onCheckedChange={(checked) =>
                    setFormData({ ...formData, is_active: checked })
                  }
                />
                <Label htmlFor="is_active">Active</Label>
              </div>

              {error && (
                <Alert variant="destructive">
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}
            </div>

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => setIsDialogOpen(false)}
              >
                Cancel
              </Button>
              <Button
                type="submit"
                disabled={createWebhookMutation.isPending || updateWebhookMutation.isPending}
              >
                {(createWebhookMutation.isPending || updateWebhookMutation.isPending) && (
                  <LoadingSpinner className="mr-2 h-4 w-4" />
                )}
                {editingWebhook ? 'Update' : 'Create'}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={deleteConfirmOpen}
        onOpenChange={setDeleteConfirmOpen}
        title="Delete Webhook"
        description={`Are you sure you want to delete "${webhookToDelete?.name}"? This action cannot be undone.`}
        confirmText="Delete"
        variant="destructive"
        onConfirm={confirmDelete}
      />

      {/* Batch Delete Confirmation Dialog */}
      <ConfirmDialog
        open={batchAction === 'delete'}
        onOpenChange={(open) => !open && setBatchAction(null)}
        title="Delete Webhooks"
        description={
          selectedWebhooks.size > 0
            ? `Are you sure you want to delete ${selectedWebhooks.size} selected webhook(s)? This action cannot be undone.`
            : `Are you sure you want to delete ALL ${webhooks?.length || 0} webhooks? This action cannot be undone and will permanently delete all your webhook configurations.`
        }
        confirmText="Delete"
        variant="destructive"
        onConfirm={confirmBatchDelete}
      />
    </div>
  )
}