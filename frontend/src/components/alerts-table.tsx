"use client"

import { useState, useEffect } from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { LoadingSpinner } from "@/components/ui/loading-spinner"
import { ExternalLink, Search, ChevronLeft, ChevronRight } from "lucide-react"
import { apiClient, type Alert } from "@/lib/api"
import { useSyncStats } from "@/hooks/use-sync-stats"
import { formatWearPercentage } from "@/lib/wear-utils"
import { useAuth } from "@/contexts/auth-context"

const ALERT_TYPE_LABELS = {
  match: 'Rule Match',
  best_deal: 'Best Deal',
  new_item: 'New Item'
} as const

const ALERT_TYPE_COLORS = {
  match: 'default',
  best_deal: 'destructive',
  new_item: 'secondary'
} as const

export function AlertsTable() {
  const [page, setPage] = useState(0)
  const [search, setSearch] = useState('')
  const [alertTypeFilter, setAlertTypeFilter] = useState<string>('')
  const [isClearingAll, setIsClearingAll] = useState(false)
  const limit = 20
  const queryClient = useQueryClient()
  const { syncStats } = useSyncStats()
  const { isLoading: isAuthLoading, isAuthenticated, token } = useAuth()

  const handleClearAllAlerts = async () => {
    if (isClearingAll) return
    
    if (!confirm('⚠️ Are you sure you want to delete ALL your alerts? This cannot be undone.')) {
      return
    }
    
    setIsClearingAll(true)
    try {
      const response = await apiClient.clearAllAlerts()
      if (response.success) {
        console.log('Alerts cleared, invalidating cache...')
        // Invalidate alerts and stats cache - let auto-refresh handle the rest
        queryClient.invalidateQueries({ queryKey: ['alerts'] })
        syncStats()
        
        alert(`✅ ${response.data?.message || 'All alerts cleared successfully'}`)
      }
    } catch (error) {
      console.error('Failed to clear all alerts:', error)
      alert('❌ Failed to clear alerts')
    } finally {
      setIsClearingAll(false)
    }
  }

  const { data: alertsResponse, isLoading, error } = useQuery({
    queryKey: ['alerts', page, search, alertTypeFilter],
    queryFn: () => apiClient.getAlerts({
      limit,
      offset: page * limit,
      alert_type: alertTypeFilter ? (alertTypeFilter as 'match' | 'best_deal' | 'new_item') : undefined,
    }),
    enabled: !isAuthLoading && !!token, // Wait for auth loading to finish and token to be present
    refetchInterval: 10000, // Refresh every 10 seconds
    refetchIntervalInBackground: true, // Continue refreshing when tab is not active
  })

  // Sync stats when alerts data changes
  useEffect(() => {
    if (alertsResponse) {
      console.log('Alerts data changed, syncing stats...')
      syncStats()
    }
  }, [alertsResponse, syncStats])

  if (isLoading) {
    return <LoadingSpinner />
  }

  if (error) {
    return (
      <Card>
        <CardContent className="pt-6">
          <div className="text-center text-red-600">
            Error loading alerts: {error instanceof Error ? error.message : 'Unknown error'}
          </div>
        </CardContent>
      </Card>
    )
  }

  const alerts = alertsResponse?.data || []
  const hasMorePages = alerts.length === limit

  const formatPrice = (price: number) => {
    return new Intl.NumberFormat('fr-FR', {
      style: 'currency',
      currency: 'EUR',
      minimumFractionDigits: 2,
    }).format(price)
  }

  const formatDate = (dateString?: string) => {
    if (!dateString) return 'N/A'
    return new Date(dateString).toLocaleString()
  }

  if (alerts.length === 0 && page === 0 && !search && !alertTypeFilter) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>No Alerts Found</CardTitle>
          <CardDescription>
            No alerts have been triggered yet. Create some rules to start monitoring!
          </CardDescription>
        </CardHeader>
      </Card>
    )
  }

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex gap-4 items-end">
        <div className="flex-1">
          <label htmlFor="search" className="text-sm font-medium mb-2 block">
            Search Items
          </label>
          <div className="relative">
            <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
            <Input
              id="search"
              placeholder="Search by item name..."
              value={search}
              onChange={(e) => {
                setSearch(e.target.value)
                setPage(0) // Reset to first page when searching
              }}
              className="pl-10"
            />
          </div>
        </div>
        <div>
          <label htmlFor="alert-type" className="text-sm font-medium mb-2 block">
            Alert Type
          </label>
          <Select
            value={alertTypeFilter}
            onValueChange={(value) => {
              setAlertTypeFilter(value === 'all' ? '' : value)
              setPage(0) // Reset to first page when filtering
            }}
          >
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="All types" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Types</SelectItem>
              <SelectItem value="match">Rule Match</SelectItem>
              <SelectItem value="best_deal">Best Deal</SelectItem>
              <SelectItem value="new_item">New Item</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div>
          <label className="text-sm font-medium mb-2 block">
            Actions
          </label>
          <Button
            variant="outline"
            onClick={handleClearAllAlerts}
            disabled={isClearingAll}
            className="w-[180px]"
          >
            {isClearingAll ? (
              <>
                <LoadingSpinner />
                Clearing...
              </>
            ) : (
              'Clear All Alerts'
            )}
          </Button>
        </div>
      </div>

      {/* Results */}
      <Card>
        <CardContent className="p-0">
          {alerts.length === 0 ? (
            <div className="p-8 text-center text-muted-foreground">
              No alerts found matching your criteria.
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Item</TableHead>
                  <TableHead>Price</TableHead>
                  <TableHead>Wear</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Features</TableHead>
                  <TableHead>Sent At</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {alerts.map((alert) => (
                  <TableRow key={alert.id}>
                    <TableCell className="font-medium max-w-[200px]">
                      <div className="truncate" title={alert.item_name}>
                        {alert.item_name}
                      </div>
                    </TableCell>
                    <TableCell className="font-mono">
                      {formatPrice(alert.price)}
                    </TableCell>
                    <TableCell>
                      {alert.wear_value !== undefined && alert.wear_value !== null ? (
                        <span className="text-sm">
                          {formatWearPercentage(alert.wear_value)}
                        </span>
                      ) : (
                        <span className="text-muted-foreground text-sm">N/A</span>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge variant={ALERT_TYPE_COLORS[alert.alert_type as keyof typeof ALERT_TYPE_COLORS] || 'default'}>
                        {ALERT_TYPE_LABELS[alert.alert_type as keyof typeof ALERT_TYPE_LABELS] || alert.alert_type}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex gap-1 flex-wrap">
                        {alert.stattrak && (
                          <Badge variant="outline" className="text-xs">
                            StatTrak
                          </Badge>
                        )}
                        {alert.souvenir && (
                          <Badge variant="outline" className="text-xs">
                            Souvenir
                          </Badge>
                        )}
                        {!alert.stattrak && !alert.souvenir && (
                          <span className="text-muted-foreground text-sm">Normal</span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className="text-sm">
                        {formatDate(alert.sent_at)}
                      </span>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="outline"
                        size="sm"
                        asChild
                      >
                        <a
                          href={alert.skin_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-center gap-2"
                        >
                          <ExternalLink className="h-3 w-3" />
                          View
                        </a>
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {/* Pagination */}
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          Page {page + 1}
          {alerts.length > 0 && (
            <> • Showing {alerts.length} alerts</>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setPage(Math.max(0, page - 1))}
            disabled={page === 0}
          >
            <ChevronLeft className="h-4 w-4" />
            Previous
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setPage(page + 1)}
            disabled={!hasMorePages}
          >
            Next
            <ChevronRight className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  )
}