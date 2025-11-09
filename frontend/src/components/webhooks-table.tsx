'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Plus, Edit, Trash2, ExternalLink, Shield } from 'lucide-react'
import { toast } from 'sonner'
import { apiClient, type Webhook } from '@/lib/api'
import { useAuth } from '@/contexts/auth-context'

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
  const [editingWebhook, setEditingWebhook] = useState<Webhook | null>(null)
  const [formData, setFormData] = useState<WebhookFormData>(initialFormData)
  const [error, setError] = useState('')

  const queryClient = useQueryClient()
  const { isLoading: isAuthLoading } = useAuth()

  // Fetch webhooks
  const { data: webhooks, isLoading } = useQuery({
    queryKey: ['webhooks'],
    queryFn: async () => {
      const result = await apiClient.getWebhooks(false) // Don't decrypt for listing
      if (!result.success) throw new Error(result.error)
      return result.data || []
    },
    enabled: !isAuthLoading, // Wait for authentication to load
  })

  // Create webhook mutation
  const createWebhookMutation = useMutation({
    mutationFn: async (data: WebhookFormData) => {
      const result = await apiClient.createWebhook(data)
      if (!result.success) throw new Error(result.error)
      return result.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks'] })
      setIsDialogOpen(false)
      resetForm()
      toast.success('Webhook created successfully')
    },
    onError: (error: Error) => {
      setError(error.message)
    },
  })

  // Update webhook mutation
  const updateWebhookMutation = useMutation({
    mutationFn: async ({ id, data }: { id: number; data: Partial<WebhookFormData> }) => {
      const result = await apiClient.updateWebhook(id, data)
      if (!result.success) throw new Error(result.error)
      return result.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks'] })
      setIsDialogOpen(false)
      resetForm()
      toast.success('Webhook updated successfully')
    },
    onError: (error: Error) => {
      setError(error.message)
    },
  })

  // Delete webhook mutation
  const deleteWebhookMutation = useMutation({
    mutationFn: async (id: number) => {
      const result = await apiClient.deleteWebhook(id)
      if (!result.success) throw new Error(result.error)
      return result.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['webhooks'] })
      toast.success('Webhook deleted successfully')
    },
    onError: (error: Error) => {
      toast.error(`Failed to delete webhook: ${error.message}`)
    },
  })

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
    if (confirm(`Are you sure you want to delete "${webhook.name}"?`)) {
      deleteWebhookMutation.mutate(webhook.id!)
    }
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
    return (
      <div className="flex justify-center py-8">
        <LoadingSpinner />
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
          <Plus className="h-4 w-4 mr-2" />
          Add Webhook
        </Button>
      </div>

      {!webhooks?.length ? (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Shield className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold mb-2">No webhooks configured</h3>
            <p className="text-muted-foreground text-center mb-4">
              Create your first webhook to receive encrypted notifications
            </p>
            <Button onClick={() => handleOpenDialog()}>
              <Plus className="h-4 w-4 mr-2" />
              Add Your First Webhook
            </Button>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {webhooks.map((webhook) => (
                <TableRow key={webhook.id}>
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
                    {webhook.created_at ? new Date(webhook.created_at).toLocaleDateString() : '-'}
                  </TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleOpenDialog(webhook)}
                      >
                        <Edit className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleDelete(webhook)}
                        className="text-red-600 hover:text-red-700"
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
      )}

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
    </div>
  )
}