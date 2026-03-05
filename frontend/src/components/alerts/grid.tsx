'use client'

import { useState, useMemo } from 'react'
import { useQuery, keepPreviousData } from '@tanstack/react-query'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { AlertsGridSkeleton } from '@/components/ui/skeletons'
import { apiClient } from '@/lib/api'
import { extractErrorMessage } from '@/lib/utils'
import { useApiMutation } from '@/hooks/use-api-mutation'
import { useSyncStats } from '@/hooks/use-sync-stats'
import { useAuth } from '@/contexts/auth-context'
import { usePageVisible } from '@/hooks/use-page-visible'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'
import { ALERTS_PAGE_SIZE, POLL_INTERVAL, QUERY_KEYS } from '@/lib/constants'
import { AlertsGridFilters } from './grid-filters'
import { AlertsGridEmptyState, AlertsGridList } from './grid-list'
import { filterAndSortAlerts, getAlertItemNames, type AlertSortBy } from './grid-helpers'

export function AlertsGrid() {
  const [page, setPage] = useState(0)
  const [itemNameFilter, setItemNameFilter] = useState<string>('')
  const [statTrakFilter, setStatTrakFilter] = useState<string>('all')
  const [souvenirFilter, setSouvenirFilter] = useState<string>('all')
  const [wearFilter, setWearFilter] = useState<string>('all')
  const [stickerFilter, setStickerFilter] = useState<string>('all')
  const [sortBy, setSortBy] = useState<AlertSortBy>('price_asc')
  const [clearConfirmOpen, setClearConfirmOpen] = useState(false)
  const { syncStats } = useSyncStats()
  const { isReady, isAuthenticated } = useAuth()
  const isVisible = usePageVisible()

  const clearAllMutation = useApiMutation(
    () => apiClient.clearAllAlerts(),
    {
      invalidateKeys: [[QUERY_KEYS.ALERTS]],
      successMessage: 'All alerts cleared successfully',
      errorMessage: 'Failed to clear alerts',
      onSuccess: () => { void syncStats() },
    },
  )

  const { data: alertsResponse, isLoading, error } = useQuery({
    queryKey: [QUERY_KEYS.ALERTS],
    queryFn: async () => apiClient.ensureSuccess(await apiClient.getAlerts({ limit: 0, offset: 0 }), 'Failed to load alerts'),
    enabled: isReady && isAuthenticated,
    staleTime: 0,
    placeholderData: keepPreviousData,
    refetchInterval: isVisible ? POLL_INTERVAL : false,
    refetchOnWindowFocus: true,
    refetchOnReconnect: true,
    notifyOnChangeProps: ['data', 'error'],
  })

  const allAlerts = useMemo(() => alertsResponse?.data ?? [], [alertsResponse?.data])
  const itemNames = useMemo(() => getAlertItemNames(allAlerts), [allAlerts])

  const filteredAlerts = useMemo(
    () => filterAndSortAlerts(allAlerts, {
      itemNameFilter,
      statTrakFilter,
      souvenirFilter,
      wearFilter,
      stickerFilter,
      sortBy,
    }),
    [allAlerts, itemNameFilter, statTrakFilter, souvenirFilter, wearFilter, stickerFilter, sortBy],
  )

  const startIndex = page * ALERTS_PAGE_SIZE
  const endIndex = startIndex + ALERTS_PAGE_SIZE
  const alerts = filteredAlerts.slice(startIndex, endIndex)
  const hasMorePages = endIndex < filteredAlerts.length

  if (isLoading) {
    return <AlertsGridSkeleton />
  }

  if (error) {
    return (
      <Card>
        <CardContent className="pt-6">
          <div className="text-center text-red-600" role="alert">
            Error loading alerts: {extractErrorMessage(error)}
          </div>
        </CardContent>
      </Card>
    )
  }

  if (allAlerts.length === 0) {
    return (
      <Card className="border-dashed">
        <CardHeader className="items-center text-center py-10">
          <CardTitle className="text-base">No Alerts Found</CardTitle>
          <CardDescription>
            No alerts have been triggered yet. Create some rules to start monitoring!
          </CardDescription>
        </CardHeader>
      </Card>
    )
  }

  return (
    <div className="space-y-5">
      <AlertsGridFilters
        filteredCount={filteredAlerts.length}
        itemNames={itemNames}
        itemNameFilter={itemNameFilter}
        wearFilter={wearFilter}
        stickerFilter={stickerFilter}
        statTrakFilter={statTrakFilter}
        souvenirFilter={souvenirFilter}
        sortBy={sortBy}
        clearPending={clearAllMutation.isPending}
        onItemNameFilterChange={(value) => {
          setItemNameFilter(value === 'all' ? '' : value)
          setPage(0)
        }}
        onWearFilterChange={(value) => {
          setWearFilter(value)
          setPage(0)
        }}
        onStickerFilterChange={(value) => {
          setStickerFilter(value)
          setPage(0)
        }}
        onStatTrakFilterChange={(value) => {
          setStatTrakFilter(value)
          setPage(0)
        }}
        onSouvenirFilterChange={(value) => {
          setSouvenirFilter(value)
          setPage(0)
        }}
        onSortByChange={(value) => {
          setSortBy(value)
          setPage(0)
        }}
        onClearAll={() => setClearConfirmOpen(true)}
      />

      {alerts.length === 0 ? (
        <AlertsGridEmptyState />
      ) : (
        <AlertsGridList
          alerts={alerts}
          page={page}
          hasMorePages={hasMorePages}
          onPageChange={setPage}
        />
      )}

      <ConfirmDialog
        open={clearConfirmOpen}
        onOpenChange={setClearConfirmOpen}
        title="Clear All Alerts"
        description="This will permanently delete all your alerts. This action cannot be undone."
        confirmText="Delete All"
        variant="destructive"
        onConfirm={() => clearAllMutation.mutate()}
      />
    </div>
  )
}
