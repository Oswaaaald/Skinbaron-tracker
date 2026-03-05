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
  )
}
