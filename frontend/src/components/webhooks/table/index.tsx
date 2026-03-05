'use client'

import { useCallback, useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Plus } from 'lucide-react'
import { apiClient, type Webhook } from '@/lib/api'
import { QUERY_KEYS } from '@/lib/constants'
import { useAuth } from '@/contexts/auth-context'
import { useSyncStats } from '@/hooks/use-sync-stats'
import { useToast } from '@/hooks/use-toast'
import { Button } from '@/components/ui/button'
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/card'
import { WebhooksTableSkeleton } from '@/components/ui/skeletons'
import { WebhooksTableBatchActions } from '@/components/webhooks/table/batch-actions'
import { WebhooksTableContent } from '@/components/webhooks/table/content'
import { WebhooksTableDialogs } from '@/components/webhooks/table/dialogs'
import { useWebhooksTableMutations } from '@/components/webhooks/table/mutations'
import { initialWebhookFormData, type WebhookFormData } from '@/components/webhooks/table/types'

interface WebhooksTableProps {
  onCreateWebhook?: () => void
  createDialogOpen?: boolean
  onCreateDialogChange?: (open: boolean) => void
}

export function WebhooksTable({ onCreateWebhook, createDialogOpen, onCreateDialogChange }: WebhooksTableProps) {
  const [isDialogOpen, setIsDialogOpen] = useState(false)
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false)
  const [webhookToDelete, setWebhookToDelete] = useState<Webhook | null>(null)
  const [deleteDialogName, setDeleteDialogName] = useState('')
  const [editingWebhook, setEditingWebhook] = useState<Webhook | null>(null)
  const [formData, setFormData] = useState<WebhookFormData>(initialWebhookFormData)
  const [error, setError] = useState('')
  const [selectedWebhooks, setSelectedWebhooks] = useState<Set<number>>(new Set())
  const [batchAction, setBatchAction] = useState<'enable' | 'disable' | 'delete' | null>(null)
  const [batchDeleteSize, setBatchDeleteSize] = useState(0)

  const { isReady, isAuthenticated } = useAuth()
  const { syncStats } = useSyncStats()
  const { toast } = useToast()

  const resetForm = () => {
    setFormData(initialWebhookFormData)
    setEditingWebhook(null)
    setError('')
  }

  useEffect(() => {
    if (createDialogOpen && !isDialogOpen) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- Syncing external dialog prop
      resetForm()
      setIsDialogOpen(true)
    }
    if (!createDialogOpen && isDialogOpen && !editingWebhook) {
      setIsDialogOpen(false)
    }
  }, [createDialogOpen]) // eslint-disable-line react-hooks/exhaustive-deps

  const { data: webhooks, isLoading } = useQuery({
    queryKey: [QUERY_KEYS.WEBHOOKS],
    queryFn: async () => {
      const result = await apiClient.getWebhooks(false)
      if (!result.success) throw new Error(result.error)
      return result.data || []
    },
    enabled: isReady && isAuthenticated,
  })

  const {
    createWebhookMutation,
    updateWebhookMutation,
    toggleActiveMutation,
    deleteWebhookMutation,
    batchEnableMutation,
    batchDisableMutation,
    batchDeleteMutation,
  } = useWebhooksTableMutations({
    syncStats,
    toast,
    setSelectedWebhooks,
    setBatchAction,
    setError,
    closeDialog: () => setIsDialogOpen(false),
    resetForm,
  })

  const handleOpenDialog = (webhook?: Webhook) => {
    if (webhook) {
      setEditingWebhook(webhook)
      setFormData({
        name: webhook.name,
        webhook_url: '',
        notification_style: webhook.notification_style || 'compact',
        is_active: webhook.is_active,
      })
    } else {
      resetForm()
    }
    setIsDialogOpen(true)
    onCreateDialogChange?.(true)
  }

  const handleToggleActive = (webhook: Webhook) => {
    if (webhook.id != null) {
      toggleActiveMutation.mutate({ id: webhook.id, is_active: !webhook.is_active })
    }
  }

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    if (editingWebhook) {
      if (!formData.name) {
        setError('Name is required')
        return
      }

      const updates: Partial<WebhookFormData> = {
        name: formData.name,
        notification_style: formData.notification_style,
        is_active: formData.is_active,
      }

      if (formData.webhook_url.trim()) {
        updates.webhook_url = formData.webhook_url
      }

      updateWebhookMutation.mutate({ id: editingWebhook.id as number, data: updates })
      return
    }

    if (!formData.name || !formData.webhook_url) {
      setError('Name and webhook URL are required')
      return
    }

    createWebhookMutation.mutate(formData)
  }

  const handleDelete = (webhook: Webhook) => {
    setWebhookToDelete(webhook)
    setDeleteDialogName(webhook.name)
    setDeleteConfirmOpen(true)
  }

  const confirmDelete = useCallback(() => {
    if (webhookToDelete?.id) {
      deleteWebhookMutation.mutate(webhookToDelete.id)
    }
    setWebhookToDelete(null)
  }, [webhookToDelete, deleteWebhookMutation])

  const handleSelectAll = () => {
    if (!webhooks) return
    if (selectedWebhooks.size === webhooks.length) {
      setSelectedWebhooks(new Set())
      return
    }
    setSelectedWebhooks(new Set(webhooks.map((webhook) => webhook.id).filter((id): id is number => id != null)))
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
  }

  const handleBatchDisable = () => {
    const webhookIds = selectedWebhooks.size > 0 ? Array.from(selectedWebhooks) : undefined
    batchDisableMutation.mutate(webhookIds)
  }

  const handleBatchDelete = () => {
    setBatchDeleteSize(selectedWebhooks.size)
    setBatchAction('delete')
  }

  const confirmBatchDelete = useCallback(() => {
    const webhookIds = selectedWebhooks.size > 0 ? Array.from(selectedWebhooks) : undefined
    const confirmAll = selectedWebhooks.size === 0
    batchDeleteMutation.mutate({ webhookIds, confirmAll })
    setSelectedWebhooks(new Set())
  }, [selectedWebhooks, batchDeleteMutation])

  if (isLoading) {
    return <WebhooksTableSkeleton />
  }

  const hasWebhooks = !!webhooks && webhooks.length > 0

  if (!hasWebhooks) {
    return (
      <>
        <Card className="border-dashed">
          <CardHeader className="items-center text-center py-10">
            <CardTitle className="text-base">No Webhooks Found</CardTitle>
            <CardDescription>
              Create your first webhook to receive Discord notifications when alerts are triggered.
            </CardDescription>
            {onCreateWebhook && (
              <Button onClick={onCreateWebhook} className="mt-4">
                <Plus className="h-4 w-4 mr-2" />
                Add Webhook
              </Button>
            )}
          </CardHeader>
        </Card>

        <WebhooksTableDialogs
          isDialogOpen={isDialogOpen}
          setIsDialogOpen={setIsDialogOpen}
          editingWebhook={editingWebhook}
          formData={formData}
          setFormData={setFormData}
          error={error}
          onCreateDialogChange={onCreateDialogChange}
          onSubmit={handleSubmit}
          createPending={createWebhookMutation.isPending}
          updatePending={updateWebhookMutation.isPending}
          deleteConfirmOpen={deleteConfirmOpen}
          onDeleteConfirmOpenChange={setDeleteConfirmOpen}
          deleteDialogName={deleteDialogName}
          onConfirmDelete={confirmDelete}
          batchDeleteOpen={batchAction === 'delete'}
          onBatchDeleteOpenChange={(open) => !open && setBatchAction(null)}
          batchDeleteSize={batchDeleteSize}
          totalWebhooks={webhooks?.length || 0}
          onConfirmBatchDelete={confirmBatchDelete}
        />
      </>
    )
  }

  return (
    <>
      <Card>
        <CardHeader className="pb-3">
          <WebhooksTableBatchActions
            selectedCount={selectedWebhooks.size}
            totalCount={webhooks.length}
            enablePending={batchEnableMutation.isPending}
            disablePending={batchDisableMutation.isPending}
            deletePending={batchDeleteMutation.isPending}
            onEnable={handleBatchEnable}
            onDisable={handleBatchDisable}
            onDelete={handleBatchDelete}
          />
        </CardHeader>
        <div className="md:overflow-x-auto">
          <WebhooksTableContent
            webhooks={webhooks}
            selectedWebhooks={selectedWebhooks}
            onSelectAll={handleSelectAll}
            onSelectWebhook={handleSelectWebhook}
            onEdit={handleOpenDialog}
            onToggleActive={handleToggleActive}
            onDelete={handleDelete}
          />
        </div>
      </Card>

      <WebhooksTableDialogs
        isDialogOpen={isDialogOpen}
        setIsDialogOpen={setIsDialogOpen}
        editingWebhook={editingWebhook}
        formData={formData}
        setFormData={setFormData}
        error={error}
        onCreateDialogChange={onCreateDialogChange}
        onSubmit={handleSubmit}
        createPending={createWebhookMutation.isPending}
        updatePending={updateWebhookMutation.isPending}
        deleteConfirmOpen={deleteConfirmOpen}
        onDeleteConfirmOpenChange={setDeleteConfirmOpen}
        deleteDialogName={deleteDialogName}
        onConfirmDelete={confirmDelete}
        batchDeleteOpen={batchAction === 'delete'}
        onBatchDeleteOpenChange={(open) => !open && setBatchAction(null)}
        batchDeleteSize={batchDeleteSize}
        totalWebhooks={webhooks.length}
        onConfirmBatchDelete={confirmBatchDelete}
      />
    </>
  )
}
