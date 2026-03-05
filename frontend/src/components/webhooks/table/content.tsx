'use client'

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Edit, MoreHorizontal, Pause, Play, Trash2 } from 'lucide-react'
import type { Webhook } from '@/lib/api'
import { formatDateOnly } from '@/lib/formatters'

interface WebhooksTableContentProps {
  webhooks: Webhook[]
  selectedWebhooks: Set<number>
  onSelectAll: () => void
  onSelectWebhook: (webhookId: number) => void
  onEdit: (webhook: Webhook) => void
  onToggleActive: (webhook: Webhook) => void
  onDelete: (webhook: Webhook) => void
}

function WebhookRow({
  webhook,
  selected,
  onSelect,
  onEdit,
  onToggleActive,
  onDelete,
}: {
  webhook: Webhook
  selected: boolean
  onSelect: () => void
  onEdit: () => void
  onToggleActive: () => void
  onDelete: () => void
}) {
  return (
    <TableRow>
      <TableCell>
        <input
          type="checkbox"
          checked={selected}
          onChange={onSelect}
          className="cursor-pointer"
          aria-label={`Select webhook ${webhook.name}`}
        />
      </TableCell>
      <TableCell className="font-medium max-w-[200px] truncate">{webhook.name}</TableCell>
      <TableCell>
        <Badge variant="outline">
          {webhook.notification_style === 'detailed' ? 'Detailed' : 'Compact'}
        </Badge>
      </TableCell>
      <TableCell>
        <Badge variant={webhook.is_active ? 'default' : 'secondary'}>
          {webhook.is_active ? 'Active' : 'Inactive'}
        </Badge>
      </TableCell>
      <TableCell className="text-muted-foreground">
        {webhook.created_at ? formatDateOnly(webhook.created_at) : '-'}
      </TableCell>
      <TableCell className="text-right">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" className="h-8 w-8 p-0" aria-label="Open webhook actions menu">
              <span className="sr-only">Open menu</span>
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuLabel>Actions</DropdownMenuLabel>
            <DropdownMenuItem onClick={onEdit}>
              <Edit className="mr-2 h-4 w-4" />
              Edit
            </DropdownMenuItem>
            <DropdownMenuItem onClick={onToggleActive}>
              {webhook.is_active ? (
                <>
                  <Pause className="mr-2 h-4 w-4" />
                  Disable
                </>
              ) : (
                <>
                  <Play className="mr-2 h-4 w-4" />
                  Enable
                </>
              )}
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={onDelete} className="text-destructive">
              <Trash2 className="mr-2 h-4 w-4" />
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </TableCell>
    </TableRow>
  )
}

function WebhookMobileCard({
  webhook,
  selected,
  onSelect,
  onEdit,
  onToggleActive,
  onDelete,
}: {
  webhook: Webhook
  selected: boolean
  onSelect: () => void
  onEdit: () => void
  onToggleActive: () => void
  onDelete: () => void
}) {
  return (
    <Card className="border-border/70 bg-card/85 py-0">
      <CardContent className="space-y-3 p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 space-y-1">
            <p className="truncate text-sm font-semibold">{webhook.name}</p>
            <p className="text-xs text-muted-foreground">
              {webhook.created_at ? formatDateOnly(webhook.created_at) : '-'}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              checked={selected}
              onChange={onSelect}
              className="cursor-pointer"
              aria-label={`Select webhook ${webhook.name}`}
            />
            <Badge variant={webhook.is_active ? 'default' : 'secondary'}>
              {webhook.is_active ? 'Active' : 'Inactive'}
            </Badge>
          </div>
        </div>

        <div className="rounded-lg border border-border/65 bg-background/60 p-3">
          <p className="text-xs text-muted-foreground">Notification style</p>
          <p className="mt-1 text-sm font-medium">
            {webhook.notification_style === 'detailed' ? 'Detailed' : 'Compact'}
          </p>
        </div>

        <div className="grid grid-cols-3 gap-2">
          <Button size="sm" variant="outline" onClick={onEdit}>Edit</Button>
          <Button size="sm" variant="outline" onClick={onToggleActive}>
            {webhook.is_active ? 'Disable' : 'Enable'}
          </Button>
          <Button size="sm" variant="destructive" onClick={onDelete}>Delete</Button>
        </div>
      </CardContent>
    </Card>
  )
}

export function WebhooksTableContent({
  webhooks,
  selectedWebhooks,
  onSelectAll,
  onSelectWebhook,
  onEdit,
  onToggleActive,
  onDelete,
}: WebhooksTableContentProps) {
  return (
    <>
      <div className="hidden md:block">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-12">
                <input
                  type="checkbox"
                  checked={selectedWebhooks.size === webhooks.length && webhooks.length > 0}
                  onChange={onSelectAll}
                  className="cursor-pointer"
                  aria-label="Select all webhooks"
                />
              </TableHead>
              <TableHead>Name</TableHead>
              <TableHead>Style</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Created</TableHead>
              <TableHead className="text-right">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {webhooks.map((webhook) => (
              <WebhookRow
                key={webhook.id}
                webhook={webhook}
                selected={webhook.id != null && selectedWebhooks.has(webhook.id)}
                onSelect={() => webhook.id != null && onSelectWebhook(webhook.id)}
                onEdit={() => onEdit(webhook)}
                onToggleActive={() => onToggleActive(webhook)}
                onDelete={() => onDelete(webhook)}
              />
            ))}
          </TableBody>
        </Table>
      </div>

      <div className="space-y-3 p-4 md:hidden">
        <div className="flex items-center justify-between rounded-lg border border-border/65 bg-background/60 px-3 py-2">
          <label className="flex items-center gap-2 text-xs text-muted-foreground">
            <input
              type="checkbox"
              checked={selectedWebhooks.size === webhooks.length && webhooks.length > 0}
              onChange={onSelectAll}
              className="cursor-pointer"
              aria-label="Select all webhooks"
            />
            Select all
          </label>
          <span className="text-xs text-muted-foreground">{selectedWebhooks.size}/{webhooks.length}</span>
        </div>

        {webhooks.map((webhook) => (
          <WebhookMobileCard
            key={webhook.id}
            webhook={webhook}
            selected={webhook.id != null && selectedWebhooks.has(webhook.id)}
            onSelect={() => webhook.id != null && onSelectWebhook(webhook.id)}
            onEdit={() => onEdit(webhook)}
            onToggleActive={() => onToggleActive(webhook)}
            onDelete={() => onDelete(webhook)}
          />
        ))}
      </div>
    </>
  )
}
