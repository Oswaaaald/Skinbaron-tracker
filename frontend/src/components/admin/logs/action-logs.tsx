"use client"

import { useState, useEffect, useMemo } from "react"
import { useQuery } from "@tanstack/react-query"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { 
  Shield, 
  ArrowRight,
} from "lucide-react"
import { apiClient, type AdminActionLog } from "@/lib/api"
import { usePageVisible } from "@/hooks/use-page-visible"
import { LogListSkeleton } from "@/components/ui/skeletons"
import { QUERY_KEYS, SLOW_POLL_INTERVAL } from "@/lib/constants"
import { ADMIN_ACTION_CONFIG } from "@/lib/audit-icons"
import { LogEntryRow, LogScrollArea } from "@/components/log-entry-list"
import { AdminActionLogsFilters } from "./action-logs-filters"

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
  const logs = useMemo(() => data?.data ?? [], [data])

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
          <LogListSkeleton withFilters />
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

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2">
          <Shield className="h-5 w-5" />
          Admin Action Logs
        </CardTitle>
        <CardDescription>
          {logs.length > 0
            ? `${logs.length} admin actions - Auto-deleted after ${process.env['NEXT_PUBLIC_AUDIT_RETENTION_DAYS'] || 365} days (GDPR)`
            : "No admin actions recorded"}
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {isFetching && (
          <div className="text-xs text-muted-foreground">Refreshing...</div>
        )}
        <AdminActionLogsFilters
          actionType={actionType}
          onActionTypeChange={setActionType}
          adminSearch={adminSearch}
          selectedAdmin={selectedAdmin}
          showSuggestions={showSuggestions}
          suggestions={searchResults?.data ?? []}
          limit={limit}
          isFetching={isFetching}
          onAdminSearchChange={handleAdminSearchChange}
          onAdminInputClick={() => {
            if (adminSearch.length >= 2) setShowSuggestions(true)
          }}
          onSelectAdmin={handleSelectAdmin}
          onClearAdminFilter={handleClearAdminFilter}
          onLimitChange={setLimit}
          onRefresh={() => { void refetch() }}
          onClearFilters={handleClearFilters}
        />

        <Separator />

        {/* Logs Display */}
        <LogScrollArea empty={logs.length === 0} emptyMessage="No admin actions found">
          {logs.map((log: AdminActionLog, index: number) => {
            const config = ADMIN_ACTION_CONFIG[log.action] || {
              icon: Shield,
              label: log.action,
              variant: "outline" as const,
            }

            return (
              <LogEntryRow
                key={log.id}
                icon={config.icon}
                badgeLabel={config.label}
                badgeVariant={config.variant}
                date={log.created_at}
                isLast={index === logs.length - 1}
                belowContent={
                  log.details ? (
                    <p className="text-sm text-muted-foreground">
                      {log.details}
                    </p>
                  ) : undefined
                }
              >
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
              </LogEntryRow>
            )
          })}
        </LogScrollArea>
      </CardContent>
    </Card>
  )
}
