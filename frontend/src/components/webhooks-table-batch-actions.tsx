'use client'

import { Button } from '@/components/ui/button'

interface WebhooksTableBatchActionsProps {
  selectedCount: number
  totalCount: number
  enablePending: boolean
  disablePending: boolean
  deletePending: boolean
  onEnable: () => void
  onDisable: () => void
  onDelete: () => void
}

export function WebhooksTableBatchActions({
  selectedCount,
  totalCount,
  enablePending,
  disablePending,
  deletePending,
  onEnable,
  onDisable,
  onDelete,
}: WebhooksTableBatchActionsProps) {
  return (
    <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
      <div className="flex items-center gap-2">
        <span className="text-sm text-muted-foreground" aria-live="polite" aria-atomic="true">
          {selectedCount > 0 ? `${selectedCount} selected` : `${totalCount} total`}
        </span>
      </div>
      <div className="flex flex-wrap gap-2 w-full sm:w-auto">
        <Button
          variant="outline"
          size="sm"
          onClick={onEnable}
          disabled={enablePending}
          className="flex-1 sm:flex-none"
        >
          <span className="hidden sm:inline">{selectedCount > 0 ? 'Enable Selected' : 'Enable All'}</span>
          <span className="sm:hidden">Enable</span>
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={onDisable}
          disabled={disablePending}
          className="flex-1 sm:flex-none"
        >
          <span className="hidden sm:inline">{selectedCount > 0 ? 'Disable Selected' : 'Disable All'}</span>
          <span className="sm:hidden">Disable</span>
        </Button>
        <Button
          variant="destructive"
          size="sm"
          onClick={onDelete}
          disabled={deletePending}
          className="flex-1 sm:flex-none"
        >
          <span className="hidden sm:inline">{selectedCount > 0 ? 'Delete Selected' : 'Delete All'}</span>
          <span className="sm:hidden">Delete</span>
        </Button>
      </div>
    </div>
  )
}
