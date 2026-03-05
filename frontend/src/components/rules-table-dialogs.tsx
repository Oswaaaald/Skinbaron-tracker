'use client'

import type { Rule } from '@/lib/api'
import { RuleDialog } from '@/components/rule-dialog'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'

interface RulesTableDialogsProps {
  editingRule: Rule | null
  isEditDialogOpen: boolean
  onEditDialogChange: (open: boolean) => void
  clearEditingRule: () => void
  deleteConfirmOpen: boolean
  onDeleteConfirmOpenChange: (open: boolean) => void
  deleteDialogName: string
  onConfirmDelete: () => void
  batchDeleteOpen: boolean
  onBatchDeleteOpenChange: (open: boolean) => void
  batchDeleteSize: number
  totalRules: number
  onConfirmBatchDelete: () => void
}

export function RulesTableDialogs({
  editingRule,
  isEditDialogOpen,
  onEditDialogChange,
  clearEditingRule,
  deleteConfirmOpen,
  onDeleteConfirmOpenChange,
  deleteDialogName,
  onConfirmDelete,
  batchDeleteOpen,
  onBatchDeleteOpenChange,
  batchDeleteSize,
  totalRules,
  onConfirmBatchDelete,
}: RulesTableDialogsProps) {
  return (
    <>
      <RuleDialog
        open={isEditDialogOpen}
        onOpenChange={(open: boolean) => {
          onEditDialogChange(open)
          if (!open) setTimeout(clearEditingRule, 200)
        }}
        rule={editingRule}
      />

      <ConfirmDialog
        open={deleteConfirmOpen}
        onOpenChange={onDeleteConfirmOpenChange}
        title="Delete Rule"
        description={`Are you sure you want to delete the rule for "${deleteDialogName}"? This action cannot be undone.`}
        confirmText="Delete"
        cancelText="Cancel"
        variant="destructive"
        onConfirm={onConfirmDelete}
      />

      <ConfirmDialog
        open={batchDeleteOpen}
        onOpenChange={onBatchDeleteOpenChange}
        title="Delete Rules"
        description={
          batchDeleteSize > 0
            ? `Are you sure you want to delete ${batchDeleteSize} selected rule(s)? This action cannot be undone.`
            : `Are you sure you want to delete ALL ${totalRules} rules? This action cannot be undone and will permanently delete all your monitoring rules.`
        }
        confirmText="Delete"
        cancelText="Cancel"
        variant="destructive"
        onConfirm={onConfirmBatchDelete}
      />
    </>
  )
}
