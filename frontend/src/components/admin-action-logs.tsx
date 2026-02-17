"use client"

import { useState, useEffect } from "react"
import { useQuery } from "@tanstack/react-query"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Separator } from "@/components/ui/separator"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Button } from "@/components/ui/button"
import { 
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { 
  Shield, 
  X,
  RefreshCw,
  ArrowRight,
} from "lucide-react"
import { apiClient, type AdminActionLog } from "@/lib/api"
import { usePageVisible } from "@/hooks/use-page-visible"
import { LoadingState } from "@/components/ui/loading-state"
import { QUERY_KEYS, SLOW_POLL_INTERVAL, ADMIN_ACTION_TYPES, ADMIN_ACTION_CONFIG } from "@/lib/constants"
import { formatRelativeDate } from "@/lib/formatters"

export function AdminActionLogs() {
  const [actionType, setActionType] = useState<string>("all")
  const [adminSearch, setAdminSearch] = useState<string>("")
  const [selectedAdmin, setSelectedAdmin] = useState<{ id: number; username: string; email: string } | null>(null)
  const [showSuggestions, setShowSuggestions] = useState<boolean>(false)
  const [limit, setLimit] = useState<number>(100)
  const isVisible = usePageVisible()

  // Search admins with debounce
  const { data: searchResults } = useQuery({
    queryKey: [QUERY_KEYS.SEARCH_USERS, 'admins', adminSearch],
    queryFn: async () => {
      if (adminSearch.length < 2) return { success: true, data: [] }
      return apiClient.ensureSuccess(await apiClient.searchUsers(adminSearch, true), 'Failed to search admins')
    },
    enabled: adminSearch.length >= 2,
    staleTime: 30000,
  })

  // Hide suggestions when clicking outside
  useEffect(() => {
    if (!showSuggestions) return

    const handleClickOutside = () => setShowSuggestions(false)
    document.addEventListener('click', handleClickOutside)
    return () => document.removeEventListener('click', handleClickOutside)
  }, [showSuggestions])

  const { data, isLoading, isFetching, error, refetch } = useQuery({
    queryKey: [QUERY_KEYS.ADMIN_LOGS, actionType, selectedAdmin?.id, limit],
    queryFn: async () => {
      const result = apiClient.ensureSuccess(
        await apiClient.getAdminLogs({
          limit,
          action: actionType === "all" ? undefined : actionType,
          admin_id: selectedAdmin?.id,
        }),
        'Failed to load admin logs'
      )
      return result
    },
    refetchInterval: isVisible ? SLOW_POLL_INTERVAL : false,
    notifyOnChangeProps: ['data', 'error'],
    refetchOnMount: 'always',
    refetchOnWindowFocus: true,
    placeholderData: (prev) => prev,
    staleTime: 0,
    gcTime: 0,
  })

  const handleClearFilters = () => {
    setActionType("all")
    handleClearAdminFilter()
    setLimit(100)
  }

  const handleSelectAdmin = (admin: { id: number; username: string; email: string }) => {
    setSelectedAdmin(admin)
    setAdminSearch(`${admin.username} (${admin.email})`)
    setShowSuggestions(false)
  }

  const handleAdminSearchChange = (value: string) => {
    setAdminSearch(value)
    setShowSuggestions(true)
  }

  const handleClearAdminFilter = () => {
    setAdminSearch("")
    setSelectedAdmin(null)
    setShowSuggestions(false)
  }

  const initialLoading = isLoading && !data

  if (initialLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Admin Action Logs
          </CardTitle>
          <CardDescription>
            All administrative actions performed by admins
          </CardDescription>
        </CardHeader>
        <CardContent>
          <LoadingState variant="inline" />
        </CardContent>
      </Card>
    )
  }

  if (error || !data?.success) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Admin Action Logs
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-sm text-muted-foreground">
            Failed to load admin logs
          </p>
        </CardContent>
      </Card>
    )
  }

  const logs = data.data || []

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2">
          <Shield className="h-5 w-5" />
          Admin Action Logs
        </CardTitle>
        <CardDescription>
          {logs.length > 0
            ? `${logs.length} admin actions - Auto-deleted after 365 days`
            : "No admin actions recorded"}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {isFetching && (
          <div className="text-xs text-muted-foreground">Refreshing...</div>
        )}
        {/* Filters */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
          <div className="space-y-2">
            <Label htmlFor="action-type">Action Type</Label>
            <Select value={actionType} onValueChange={setActionType}>
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
                onChange={(e) => handleAdminSearchChange(e.target.value)}
                onClick={(e) => {
                  e.stopPropagation()
                  if (adminSearch.length >= 2) setShowSuggestions(true)
                }}
                className={selectedAdmin ? "pr-8" : ""}
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
                    handleClearAdminFilter()
                  }}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  <X className="h-4 w-4" />
                </button>
              )}
            </div>
            {showSuggestions && searchResults?.data && searchResults.data.length > 0 && (
              <div className="absolute z-50 w-full mt-1 bg-popover border rounded-md shadow-lg max-h-60 overflow-auto">
                {searchResults.data.map((admin) => (
                  <button
                    key={admin.id}
                    type="button"
                    className="w-full px-3 py-2 text-left text-sm hover:bg-accent hover:text-accent-foreground cursor-pointer border-b last:border-b-0"
                    onClick={(e) => {
                      e.stopPropagation()
                      handleSelectAdmin(admin)
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
            <Select value={limit.toString()} onValueChange={(v) => setLimit(parseInt(v))}>
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
              <Button onClick={() => void refetch()} variant="outline" className="flex-1" disabled={isFetching}>
                <RefreshCw className={`h-4 w-4 mr-2 ${isFetching ? 'animate-spin' : ''}`} />
                Refresh
              </Button>
              <Button onClick={handleClearFilters} variant="outline" className="flex-1">
                <X className="h-4 w-4 mr-2" />
                Clear Filters
              </Button>
            </div>
          </div>
        </div>

        <Separator />

        {/* Logs Display */}
        {logs.length === 0 ? (
          <p className="text-sm text-muted-foreground text-center py-8">
            No admin actions found
          </p>
        ) : (
          <ScrollArea className="h-[600px] pr-4">
            <div className="space-y-4">
              {logs.map((log: AdminActionLog, index: number) => {
                const config = ADMIN_ACTION_CONFIG[log.action] || {
                  icon: Shield,
                  label: log.action,
                  variant: "outline" as const,
                }

                const Icon = config.icon

                return (
                  <div key={log.id}>
                    <div className="flex items-start gap-4">
                      <div className="mt-0.5">
                        <Icon className="h-4 w-4 text-muted-foreground" />
                      </div>
                      <div className="flex-1 space-y-1">
                        <div className="flex items-center gap-2 flex-wrap">
                          <Badge variant={config.variant} className="font-medium">
                            {config.label}
                          </Badge>
                          <Badge variant="secondary" className="font-semibold">
                            {log.admin_username || `Admin #${log.admin_user_id}`}
                          </Badge>
                          {log.target_username && (
                            <>
                              <ArrowRight className="h-3 w-3 text-muted-foreground" />
                              <Badge variant="outline">
                                {log.target_username}
                              </Badge>
                            </>
                          )}
                          {log.target_user_id && !log.target_username && (
                            <>
                              <ArrowRight className="h-3 w-3 text-muted-foreground" />
                              <Badge variant="outline">
                                User #{log.target_user_id}
                              </Badge>
                            </>
                          )}
                          <span className="text-xs text-muted-foreground ml-auto">
                            {formatRelativeDate(log.created_at, 'fr')}
                          </span>
                        </div>
                        {log.details && (
                          <p className="text-sm text-muted-foreground">
                            {log.details}
                          </p>
                        )}
                      </div>
                    </div>
                    {index < logs.length - 1 && <Separator className="mt-4" />}
                  </div>
                )
              })}
            </div>
          </ScrollArea>
        )}
      </CardContent>
    </Card>
  )
}
