'use client'

import type { ReactNode } from 'react'
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Edit, MoreHorizontal, Pause, Play, Trash2 } from 'lucide-react'
import type { Rule } from '@/lib/api'
import { formatDateOnly } from '@/lib/formatters'
import { formatWearPercentage } from '@/lib/wear-utils'

interface RulesTableTableProps {
  rules: Rule[]
  selectedRules: Set<number>
  onSelectAll: () => void
  onSelectRule: (ruleId: number) => void
  onEdit: (rule: Rule) => void
  onToggleEnabled: (rule: Rule) => void
  onDelete: (rule: Rule) => void
  renderWebhookDisplay: (rule: Rule) => ReactNode
}

function RuleConditions({ rule }: { rule: Rule }) {
  return (
    <div className="flex gap-1 flex-wrap items-center">
      {rule.min_wear !== undefined && rule.min_wear !== null && (
        <Badge variant="secondary" className="text-xs">
          Min Wear: {formatWearPercentage(rule.min_wear)}
        </Badge>
      )}
      {rule.max_wear !== undefined && rule.max_wear !== null && (
        <Badge variant="secondary" className="text-xs">
          Max Wear: {formatWearPercentage(rule.max_wear)}
        </Badge>
      )}
      {rule.stattrak_filter === 'only' && (
        <Badge variant="outline" className="text-xs">
          ⭐ StatTrak Only
        </Badge>
      )}
      {rule.stattrak_filter === 'exclude' && (
        <Badge variant="secondary" className="text-xs">
          🚫 No StatTrak
        </Badge>
      )}
      {rule.souvenir_filter === 'only' && (
        <Badge variant="outline" className="text-xs">
          🏆 Souvenir Only
        </Badge>
      )}
      {rule.souvenir_filter === 'exclude' && (
        <Badge variant="secondary" className="text-xs">
          🚫 No Souvenir
        </Badge>
      )}
      {rule.sticker_filter === 'only' && (
        <Badge variant="outline" className="text-xs">
          🏷️ Stickers Only
        </Badge>
      )}
      {rule.sticker_filter === 'exclude' && (
        <Badge variant="secondary" className="text-xs">
          🚫 No Stickers
        </Badge>
      )}
    </div>
  )
}

function RulePriceRange({ rule }: { rule: Rule }) {
  if (rule.max_price !== null && rule.max_price !== undefined) {
    return <span>{rule.min_price || 0}€ - {rule.max_price}€</span>
  }

  if (rule.min_price && rule.min_price > 0) {
    return <span>{rule.min_price}€+</span>
  }

  return <span className="text-muted-foreground">Any</span>
}

function RuleRow({
  rule,
  selected,
  onSelect,
  onEdit,
  onToggleEnabled,
  onDelete,
  renderWebhookDisplay,
}: {
  rule: Rule
  selected: boolean
  onSelect: () => void
  onEdit: () => void
  onToggleEnabled: () => void
  onDelete: () => void
  renderWebhookDisplay: (rule: Rule) => ReactNode
}) {
  return (
    <TableRow>
      <TableCell>
        <input
          type="checkbox"
          checked={selected}
          onChange={onSelect}
          className="cursor-pointer"
          aria-label={`Select rule ${rule.search_item}`}
        />
      </TableCell>
      <TableCell className="font-medium max-w-[200px] truncate">{rule.search_item}</TableCell>
      <TableCell>
        <RulePriceRange rule={rule} />
      </TableCell>
      <TableCell>
        <RuleConditions rule={rule} />
      </TableCell>
      <TableCell>{renderWebhookDisplay(rule)}</TableCell>
      <TableCell>
        <Badge variant={rule.enabled ? 'default' : 'secondary'}>
          {rule.enabled ? 'Enabled' : 'Disabled'}
        </Badge>
      </TableCell>
      <TableCell>{rule.created_at ? formatDateOnly(rule.created_at) : 'N/A'}</TableCell>
      <TableCell className="text-right">
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" className="h-8 w-8 p-0" aria-label="Open rule actions menu">
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
            <DropdownMenuItem onClick={onToggleEnabled}>
              {rule.enabled ? (
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

export function RulesTableTable({
  rules,
  selectedRules,
  onSelectAll,
  onSelectRule,
  onEdit,
  onToggleEnabled,
  onDelete,
  renderWebhookDisplay,
}: RulesTableTableProps) {
  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead className="w-12">
            <input
              type="checkbox"
              checked={selectedRules.size === rules.length && rules.length > 0}
              onChange={onSelectAll}
              className="cursor-pointer"
              aria-label="Select all rules"
            />
          </TableHead>
          <TableHead>Item</TableHead>
          <TableHead>Price Range</TableHead>
          <TableHead>Conditions</TableHead>
          <TableHead>Webhook</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>Created</TableHead>
          <TableHead className="text-right">Actions</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {rules.map((rule) => (
          <RuleRow
            key={rule.id}
            rule={rule}
            selected={rule.id != null && selectedRules.has(rule.id)}
            onSelect={() => rule.id != null && onSelectRule(rule.id)}
            onEdit={() => onEdit(rule)}
            onToggleEnabled={() => onToggleEnabled(rule)}
            onDelete={() => onDelete(rule)}
            renderWebhookDisplay={renderWebhookDisplay}
          />
        ))}
      </TableBody>
    </Table>
  )
}
