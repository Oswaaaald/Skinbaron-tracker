"use client"

import Image from "next/image"
import { useState, useEffect, useRef, useCallback } from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { LoadingSpinner } from "@/components/ui/loading-spinner"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { ExternalLink, ChevronLeft, ChevronRight, Sparkles, TrendingDown, Bell } from "lucide-react"
import { apiClient } from "@/lib/api"
import { logger } from "@/lib/logger"
import { extractErrorMessage } from "@/lib/utils"
import { useToast } from "@/hooks/use-toast"
import { useSyncStats } from "@/hooks/use-sync-stats"
import { formatWearPercentage } from "@/lib/wear-utils"
import { formatPrice, formatShortDate } from "@/lib/formatters"
import { useAuth } from "@/contexts/auth-context"
import { usePageVisible } from "@/hooks/use-page-visible"
import { ConfirmDialog } from "@/components/ui/confirm-dialog"
import { ALERTS_PAGE_SIZE, POLL_INTERVAL, QUERY_KEYS } from "@/lib/constants"

const ALERT_TYPE_CONFIG = {
  match: {
    label: 'Rule Match',
    color: 'default' as const,
    icon: Bell,
    description: 'Matched your rule criteria'
  },
  best_deal: {
    label: 'Best Deal',
    color: 'destructive' as const,
    icon: TrendingDown,
    description: 'Exceptional price detected'
  },
  new_item: {
    label: 'New Item',
    color: 'secondary' as const,
    icon: Sparkles,
    description: 'Just listed on market'
  }
} as const

export function AlertsGrid() {
  const [page, setPage] = useState(0)
  const [alertTypeFilter, setAlertTypeFilter] = useState<string>('')
  const [isClearingAll, setIsClearingAll] = useState(false)
  const [clearConfirmOpen, setClearConfirmOpen] = useState(false)
  const { toast } = useToast()
  const queryClient = useQueryClient()
  const { syncStats } = useSyncStats()
  const { isReady, isAuthenticated } = useAuth()
  const isVisible = usePageVisible()

  const handleClearAllAlerts = useCallback(() => {
    setClearConfirmOpen(true)
  }, [])

  const confirmClear = useCallback(async () => {
    if (isClearingAll) return
    
    setIsClearingAll(true)
    try {
      const response = await apiClient.clearAllAlerts()
      if (response.success) {
        void queryClient.invalidateQueries({ queryKey: [QUERY_KEYS.ALERTS] })
        void syncStats()
        toast({
          title: "✅ Alerts cleared",
          description: response.data?.message || 'All alerts cleared successfully',
        })
      }
    } catch (error) {
      logger.error('Failed to clear all alerts:', error)
      toast({
        variant: "destructive",
        title: "❌ Failed to clear alerts",
        description: extractErrorMessage(error, "An error occurred while clearing alerts"),
      })
    } finally {
      setIsClearingAll(false)
    }
  }, [isClearingAll, queryClient, syncStats, toast])

  const { data: alertsResponse, isLoading, error } = useQuery({
    queryKey: [QUERY_KEYS.ALERTS, page, alertTypeFilter],
    queryFn: async () => apiClient.ensureSuccess(await apiClient.getAlerts({
      limit: ALERTS_PAGE_SIZE,
      offset: page * ALERTS_PAGE_SIZE,
      alert_type: alertTypeFilter ? (alertTypeFilter as 'match' | 'best_deal' | 'new_item') : undefined,
    }), 'Failed to load alerts'),
    enabled: isReady && isAuthenticated && isVisible,
    staleTime: 0, // Always consider alerts data stale to ensure fresh data
    refetchInterval: isVisible ? POLL_INTERVAL : false,
    refetchOnWindowFocus: true,
    refetchOnReconnect: true,
    notifyOnChangeProps: ['data', 'error'],
  })

  // Track previous alert count to detect changes
  const prevAlertIdsRef = useRef<Set<number>>(new Set())
  
  useEffect(() => {
    const alerts = alertsResponse?.data ?? []
    const currentIds = new Set(alerts.map(a => a.id).filter((id): id is number => id !== undefined))
    
    // Detect new alerts by finding IDs that weren't in previous set
    if (prevAlertIdsRef.current.size > 0 && page === 0) {
      const newAlerts = alerts.filter(a => a.id && !prevAlertIdsRef.current.has(a.id))
      
      if (newAlerts.length > 0) {
        toast({
          title: "🔔 New alerts",
          description: `${newAlerts.length} new alert${newAlerts.length > 1 ? 's' : ''} received`,
          duration: 3000,
        })
        // Invalidate stats when new alerts arrive
        void queryClient.invalidateQueries({ queryKey: [QUERY_KEYS.USER_STATS] })
      }
    }
    
    prevAlertIdsRef.current = currentIds
  }, [alertsResponse?.data, queryClient, page, toast])

  if (isLoading) {
    return (
      <div className="min-h-[400px] flex flex-col items-center justify-center">
        <LoadingSpinner size="lg" />
        <p className="text-muted-foreground mt-2">Loading...</p>
      </div>
    )
  }

  if (error) {
    return (
      <Card>
        <CardContent className="pt-6">
          <div className="text-center text-red-600">
            Error loading alerts: {extractErrorMessage(error)}
          </div>
        </CardContent>
      </Card>
    )
  }

  const alerts = alertsResponse?.data || []
  const hasMorePages = alerts.length === ALERTS_PAGE_SIZE

  const getSkinBaronUrl = (saleId: string, itemName?: string) => {
    if (itemName) {
      const productName = itemName.replace(/StatTrak™\s+/, '').replace(/Souvenir\s+/, '')
      const encodedProductName = encodeURIComponent(productName)
      return `https://skinbaron.de/offers/show?offerUuid=${saleId}&productName=${encodedProductName}`
    }
    return `https://skinbaron.de/offers/show?offerUuid=${saleId}`
  }

  if (alerts.length === 0 && page === 0 && !alertTypeFilter) {
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
    <div className="space-y-6">
      {/* Filters */}
      <div className="flex gap-4 items-end flex-wrap">
        <div>
          <label htmlFor="alert-type" className="text-sm font-medium mb-2 block">
            Alert Type
          </label>
          <Select
            value={alertTypeFilter}
            onValueChange={(value) => {
              setAlertTypeFilter(value === 'all' ? '' : value)
              setPage(0)
            }}
          >
            <SelectTrigger className="w-[180px]" aria-label="Filter alerts by type">
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
                <LoadingSpinner size="sm" className="mr-2" inline />
                Clearing...
              </>
            ) : (
              'Clear All Alerts'
            )}
          </Button>
        </div>
      </div>

      {/* Grid */}
      {alerts.length === 0 ? (
        <Card>
          <CardContent className="p-12 text-center text-muted-foreground">
            No alerts found matching your criteria.
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-x-4 gap-y-6">
            {alerts.map((alert, index) => {
              const config = ALERT_TYPE_CONFIG[alert.alert_type] || ALERT_TYPE_CONFIG.match
              const Icon = config.icon
              const isFirstImage = index === 0
              
              return (
                <Card
                  key={alert.id}
                  className="group relative overflow-hidden border border-border/70 bg-muted/60 shadow-sm hover:border-primary/50 transition-colors flex flex-col p-0 will-change-[border-color]"
                >
                  {/* Image Header */}
                  <div className="relative aspect-[4/3] overflow-hidden bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
                    {alert.skin_url ? (
                      <Image
                        src={alert.skin_url}
                        alt={alert.item_name}
                        fill
                        sizes="(max-width: 768px) 100vw, (max-width: 1024px) 50vw, (max-width: 1280px) 33vw, 25vw"
                        className="object-contain p-4 transition-transform duration-300 group-hover:scale-[1.03]"
                        priority={isFirstImage}
                        fetchPriority={isFirstImage ? "high" : undefined}
                      />
                    ) : (
                      <div className="w-full h-full flex items-center justify-center text-muted-foreground text-sm">
                        No Image
                      </div>
                    )}

                    {/* Type badge */}
                    <Badge variant={config.color} className="absolute top-2 right-2 shadow-sm">
                      <Icon className="h-3 w-3 mr-1" />
                      {config.label}
                    </Badge>

                    {/* Price pill */}
                    <div className="absolute bottom-3 right-3 bg-primary text-primary-foreground px-3 py-1 rounded-full shadow-lg text-sm font-semibold">
                      {formatPrice(alert.price)}
                    </div>
                  </div>

                  <CardHeader className="flex-1 flex flex-col justify-between pb-3 pt-2 space-y-2">
                    <div>
                      <CardTitle className="text-base leading-tight line-clamp-2 min-h-[2.5rem]">
                        {alert.item_name}
                      </CardTitle>
                      <CardDescription className="text-xs mt-0.5">
                        {formatShortDate(alert.sent_at)}
                      </CardDescription>
                    </div>

                    <div className="space-y-1">
                      {alert.wear_value !== undefined && alert.wear_value !== null && (
                        <div className="flex items-center justify-between text-sm">
                          <span className="text-muted-foreground">Wear</span>
                          <span className="font-medium">
                            {formatWearPercentage(alert.wear_value)}
                          </span>
                        </div>
                      )}

                      {(alert.stattrak || alert.souvenir) && (
                        <div className="flex gap-1 flex-wrap">
                          {alert.stattrak && (
                            <Badge variant="outline" className="text-[11px]">
                              StatTrak™
                            </Badge>
                          )}
                          {alert.souvenir && (
                            <Badge variant="outline" className="text-[11px]">
                              Souvenir
                            </Badge>
                          )}
                        </div>
                      )}
                    </div>

                    <div className="pt-2">
                      <Button asChild className="w-full" size="sm">
                        <a
                          href={getSkinBaronUrl(alert.sale_id, alert.item_name)}
                          target="_blank"
                          rel="noreferrer noopener"
                          aria-label={`View ${alert.item_name} at ${formatPrice(alert.price)} on SkinBaron`}
                        >
                          View on SkinBaron
                          <ExternalLink className="ml-2 h-3 w-3" />
                        </a>
                      </Button>
                    </div>
                  </CardHeader>
                </Card>
              )
            })}
          </div>

          {/* Pagination */}
          <div className="flex justify-between items-center">
            <div className="text-sm text-muted-foreground">
              Showing {page * ALERTS_PAGE_SIZE + 1} - {page * ALERTS_PAGE_SIZE + alerts.length} alerts
            </div>
            <div className="flex gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage(p => Math.max(0, p - 1))}
                disabled={page === 0}
              >
                <ChevronLeft className="h-4 w-4 mr-1" />
                Previous
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage(p => p + 1)}
                disabled={!hasMorePages}
              >
                Next
                <ChevronRight className="h-4 w-4 ml-1" />
              </Button>
            </div>
          </div>
        </>
      )}

      <ConfirmDialog
        open={clearConfirmOpen}
        onOpenChange={setClearConfirmOpen}
        title="Clear All Alerts"
        description="This will permanently delete all your alerts. This action cannot be undone."
        confirmText="Delete All"
        variant="destructive"
        onConfirm={() => void confirmClear()}
      />
    </div>
  )
}
