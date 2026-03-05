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
import { AUDIT_EVENT_TYPES } from '@/lib/audit-icons'

type SearchUser = { id: number; username: string; email: string }

type AdminAuditLogsFiltersProps = {
  eventType: string
  onEventTypeChange: (value: string) => void
  userSearch: string
  selectedUser: SearchUser | null
  showSuggestions: boolean
  suggestions: SearchUser[]
  limit: number
  isFetching: boolean
  onUserSearchChange: (value: string) => void
  onUserInputClick: () => void
  onSelectUser: (user: SearchUser) => void
  onClearUserFilter: () => void
  onLimitChange: (value: number) => void
  onRefresh: () => void
  onClearFilters: () => void
}

export function AdminAuditLogsFilters({
  eventType,
  onEventTypeChange,
  userSearch,
  selectedUser,
  showSuggestions,
  suggestions,
  limit,
  isFetching,
  onUserSearchChange,
  onUserInputClick,
  onSelectUser,
  onClearUserFilter,
  onLimitChange,
  onRefresh,
  onClearFilters,
}: AdminAuditLogsFiltersProps) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
      <div className="space-y-2">
        <Label htmlFor="event-type">Event Type</Label>
        <Select value={eventType} onValueChange={onEventTypeChange}>
          <SelectTrigger id="event-type">
            <SelectValue placeholder="All Events" />
          </SelectTrigger>
          <SelectContent>
            {AUDIT_EVENT_TYPES.map((type) => (
              <SelectItem key={type.value} value={type.value}>
                {type.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <div className="space-y-2 relative">
        <Label htmlFor="user-search">Search User</Label>
        <div className="relative">
          <Input
            id="user-search"
            type="text"
            placeholder="Search by username or email..."
            value={userSearch}
            onChange={(e) => onUserSearchChange(e.target.value)}
            onClick={(e) => {
              e.stopPropagation()
              onUserInputClick()
            }}
            className={selectedUser ? 'pr-8' : ''}
            autoComplete="off"
            data-form-type="other"
            data-lpignore="true"
            data-1p-ignore="true"
            name="user-search-filter"
          />
          {selectedUser && (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation()
                onClearUserFilter()
              }}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
              aria-label="Clear user filter"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>

        {showSuggestions && suggestions.length > 0 && (
          <div className="absolute z-50 w-full mt-1 bg-popover border rounded-md shadow-lg max-h-60 overflow-auto">
            {suggestions.map((user) => (
              <button
                key={user.id}
                type="button"
                className="w-full px-3 py-2 text-left text-sm hover:bg-accent hover:text-accent-foreground cursor-pointer border-b last:border-b-0"
                onClick={(e) => {
                  e.stopPropagation()
                  onSelectUser(user)
                }}
              >
                <div className="font-medium">{user.username}</div>
                <div className="text-xs text-muted-foreground">{user.email}</div>
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor="limit">Limit</Label>
        <Select value={limit.toString()} onValueChange={(v) => onLimitChange(parseInt(v))}>
          <SelectTrigger id="limit">
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
