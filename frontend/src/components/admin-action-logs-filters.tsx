import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { X, RefreshCw } from 'lucide-react'
import { ADMIN_ACTION_TYPES } from '@/lib/audit-icons'

type SearchAdmin = { id: number; username: string; email: string }

type AdminActionLogsFiltersProps = {
  actionType: string
  onActionTypeChange: (value: string) => void
  adminSearch: string
  selectedAdmin: SearchAdmin | null
  showSuggestions: boolean
  suggestions: SearchAdmin[]
  limit: number
  isFetching: boolean
  onAdminSearchChange: (value: string) => void
  onAdminInputClick: () => void
  onSelectAdmin: (admin: SearchAdmin) => void
  onClearAdminFilter: () => void
  onLimitChange: (value: number) => void
  onRefresh: () => void
  onClearFilters: () => void
}

export function AdminActionLogsFilters({
  actionType,
  onActionTypeChange,
  adminSearch,
  selectedAdmin,
  showSuggestions,
  suggestions,
  limit,
  isFetching,
  onAdminSearchChange,
  onAdminInputClick,
  onSelectAdmin,
  onClearAdminFilter,
  onLimitChange,
  onRefresh,
  onClearFilters,
}: AdminActionLogsFiltersProps) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
      <div className="space-y-2">
        <Label htmlFor="action-type">Action Type</Label>
        <Select value={actionType} onValueChange={onActionTypeChange}>
          <SelectTrigger id="action-type">
            <SelectValue placeholder="All Actions" />
          </SelectTrigger>
          <SelectContent>
            {ADMIN_ACTION_TYPES.map((type) => (
              <SelectItem key={type.value} value={type.value}>
                {type.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-2 relative">
        <Label htmlFor="admin-search">Search Admin</Label>
        <div className="relative">
          <Input
            id="admin-search"
            type="text"
            placeholder="Search by username or email..."
            value={adminSearch}
            onChange={(e) => onAdminSearchChange(e.target.value)}
            onClick={(e) => {
              e.stopPropagation()
              onAdminInputClick()
            }}
            className={selectedAdmin ? 'pr-8' : ''}
            autoComplete="off"
            data-form-type="other"
            data-lpignore="true"
            data-1p-ignore="true"
            name="admin-search-filter"
          />
          {selectedAdmin && (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation()
                onClearAdminFilter()
              }}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
              aria-label="Clear admin filter"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>

        {showSuggestions && suggestions.length > 0 && (
          <div className="absolute z-50 w-full mt-1 bg-popover border rounded-md shadow-lg max-h-60 overflow-auto">
            {suggestions.map((admin) => (
              <button
                key={admin.id}
                type="button"
                className="w-full px-3 py-2 text-left text-sm hover:bg-accent hover:text-accent-foreground cursor-pointer border-b last:border-b-0"
                onClick={(e) => {
                  e.stopPropagation()
                  onSelectAdmin(admin)
                }}
              >
                <div className="font-medium">{admin.username}</div>
                <div className="text-xs text-muted-foreground">{admin.email}</div>
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor="admin-log-limit">Limit</Label>
        <Select value={limit.toString()} onValueChange={(v) => onLimitChange(parseInt(v))}>
          <SelectTrigger id="admin-log-limit">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="50">50 events</SelectItem>
            <SelectItem value="100">100 events</SelectItem>
            <SelectItem value="250">250 events</SelectItem>
            <SelectItem value="500">500 events</SelectItem>
            <SelectItem value="1000">1000 events</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-2 flex flex-col">
        <Label className="invisible">Actions</Label>
        <div className="flex items-end gap-2">
          <Button onClick={onRefresh} variant="outline" className="flex-1" disabled={isFetching}>
            <RefreshCw className={`h-4 w-4 mr-2 ${isFetching ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
          <Button onClick={onClearFilters} variant="outline" className="flex-1">
            <X className="h-4 w-4 mr-2" />
            Clear Filters
          </Button>
        </div>
      </div>
    </div>
  )
}
