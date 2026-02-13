"use client"

import Image from "next/image"
import { useState, useCallback, useMemo } from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { LoadingState } from "@/components/ui/loading-state"
import { LoadingSpinner } from "@/components/ui/loading-spinner"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { ExternalLink, ChevronLeft, ChevronRight } from "lucide-react"
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

// Clean item name - remove StatTrak, Souvenir, and wear conditions
function cleanItemName(name: string): string {
  let cleaned = name
  cleaned = cleaned.replace(/^StatTrak™\s+/i, '')
  cleaned = cleaned.replace(/^Souvenir\s+/i, '')
  cleaned = cleaned.replace(/\s*\((Factory New|Minimal Wear|Field-Tested|Well-Worn|Battle-Scarred)\)\s*$/i, '')
  return cleaned.trim()
}

// Get wear condition from wear value
function getWearCondition(wearValue?: number): string | null {
  if (wearValue === undefined) return null
  if (wearValue < 0.07) return 'fn'
  if (wearValue < 0.15) return 'mw'
  if (wearValue < 0.38) return 'ft'
  if (wearValue < 0.45) return 'ww'
  return 'bs'
}

export function AlertsGrid() {
  const [page, setPage] = useState(0)
  const [itemNameFilter, setItemNameFilter] = useState<string>('')
  const [statTrakFilter, setStatTrakFilter] = useState<string>('all')
  const [souvenirFilter, setSouvenirFilter] = useState<string>('all')
  const [wearFilter, setWearFilter] = useState<string>('all')
  const [stickerFilter, setStickerFilter] = useState<string>('all')
  const [sortBy, setSortBy] = useState<'date' | 'price_asc' | 'price_desc' | 'wear_asc' | 'wear_desc'>('date')
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

  // Fetch ALL alerts without pagination (client-side filtering/sorting)
  const { data: alertsResponse, isLoading, error } = useQuery({
    queryKey: [QUERY_KEYS.ALERTS],
    queryFn: async () => apiClient.ensureSuccess(await apiClient.getAlerts({
      limit: 500, // Get all alerts (max 500)
      offset: 0,
    }), 'Failed to load alerts'),
    enabled: isReady && isAuthenticated,
    staleTime: 0,
    refetchInterval: isVisible ? POLL_INTERVAL : false,
    refetchOnWindowFocus: true,
    refetchOnReconnect: true,
    notifyOnChangeProps: ['data', 'error'],
  })

  const allAlerts = alertsResponse?.data || []

  // Get unique CLEANED item names from fetched alerts
  const itemNames = useMemo(
    () => Array.from(new Set(allAlerts.map(a => cleanItemName(a.item_name)))).sort(),
    [allAlerts]
  )

  // Client-side filtering and sorting (memoized)
  const filteredAlerts = useMemo(() => {
    let result = [...allAlerts]

    // Apply item name filter (compare cleaned names)
    if (itemNameFilter) {
      result = result.filter(alert => cleanItemName(alert.item_name) === itemNameFilter)
    }

    // Apply StatTrak filter
    if (statTrakFilter === 'only') {
      result = result.filter(alert => alert.stattrak)
    } else if (statTrakFilter === 'exclude') {
      result = result.filter(alert => !alert.stattrak)
    }

    // Apply Souvenir filter
    if (souvenirFilter === 'only') {
      result = result.filter(alert => alert.souvenir)
    } else if (souvenirFilter === 'exclude') {
      result = result.filter(alert => !alert.souvenir)
    }

    // Apply Wear condition filter
    if (wearFilter !== 'all') {
      if (wearFilter === 'no_wear') {
        result = result.filter(alert => alert.wear_value === undefined)
      } else {
        result = result.filter(alert => {
          const condition = getWearCondition(alert.wear_value)
          return condition === wearFilter
        })
      }
    }

    // Apply Sticker filter
    if (stickerFilter === 'only') {
      result = result.filter(alert => alert.has_stickers)
    } else if (stickerFilter === 'exclude') {
      result = result.filter(alert => !alert.has_stickers)
    }

    // Apply sorting
    result.sort((a, b) => {
      switch (sortBy) {
        case 'price_asc':
          return a.price - b.price
        case 'price_desc':
          return b.price - a.price
        case 'wear_asc':
          if (a.wear_value === undefined && b.wear_value === undefined) return 0
          if (a.wear_value === undefined) return 1
          if (b.wear_value === undefined) return -1
          return a.wear_value - b.wear_value
        case 'wear_desc':
          if (a.wear_value === undefined && b.wear_value === undefined) return 0
          if (a.wear_value === undefined) return 1
          if (b.wear_value === undefined) return -1
          return b.wear_value - a.wear_value
        case 'date':
        default:
          const dateA = a.sent_at ? new Date(a.sent_at).getTime() : 0
          const dateB = b.sent_at ? new Date(b.sent_at).getTime() : 0
          return dateB - dateA
      }
    })

    return result
  }, [allAlerts, itemNameFilter, statTrakFilter, souvenirFilter, wearFilter, stickerFilter, sortBy])

  // Client-side pagination
  const startIndex = page * ALERTS_PAGE_SIZE
  const endIndex = startIndex + ALERTS_PAGE_SIZE
  const alerts = filteredAlerts.slice(startIndex, endIndex)
  const hasMorePages = endIndex < filteredAlerts.length

  if (isLoading) {
    return <LoadingState variant="section" />
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

  const getSkinBaronUrl = (saleId: string, itemName?: string) => {
    if (itemName) {
      const productName = itemName.replace(/StatTrak™\s+/, '').replace(/Souvenir\s+/, '')
      const encodedProductName = encodeURIComponent(productName)
      return `https://skinbaron.de/offers/show?offerUuid=${saleId}&productName=${encodedProductName}`
    }
    return `https://skinbaron.de/offers/show?offerUuid=${saleId}`
  }

  if (allAlerts.length === 0) {
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
          <label htmlFor="item-filter" className="text-sm font-medium mb-2 block">
            Item
          </label>
          <Select
            value={itemNameFilter || 'all'}
            onValueChange={(value) => {
              setItemNameFilter(value === 'all' ? '' : value)
              setPage(0)
            }}
          >
            <SelectTrigger className="w-[220px]" aria-label="Filter alerts by item">
              <SelectValue placeholder="All items" />
            </SelectTrigger>
            <SelectContent className="max-h-[300px]">
              <SelectItem value="all">All Items</SelectItem>
              {itemNames.map((name) => (
                <SelectItem key={name} value={name}>
                  {name.length > 35 ? name.substring(0, 35) + '...' : name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div>
          <label htmlFor="wear-filter" className="text-sm font-medium mb-2 block">
            Wear
          </label>
          <Select
            value={wearFilter}
            onValueChange={(value) => {
              setWearFilter(value)
              setPage(0)
            }}
          >
            <SelectTrigger className="w-[160px]" aria-label="Filter by wear condition">
              <SelectValue placeholder="All" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Conditions</SelectItem>
              <SelectItem value="fn">Factory New</SelectItem>
              <SelectItem value="mw">Minimal Wear</SelectItem>
              <SelectItem value="ft">Field-Tested</SelectItem>
              <SelectItem value="ww">Well-Worn</SelectItem>
              <SelectItem value="bs">Battle-Scarred</SelectItem>
              <SelectItem value="no_wear">No Wear</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div>
          <label htmlFor="sticker-filter" className="text-sm font-medium mb-2 block">
            Stickers
          </label>
          <Select
            value={stickerFilter}
            onValueChange={(value) => {
              setStickerFilter(value)
              setPage(0)
            }}
          >
            <SelectTrigger className="w-[140px]" aria-label="Filter Sticker items">
              <SelectValue placeholder="All" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              <SelectItem value="only">Only Stickers</SelectItem>
              <SelectItem value="exclude">No Stickers</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div>
          <label htmlFor="stattrak-filter" className="text-sm font-medium mb-2 block">
            StatTrak™
          </label>
          <Select
            value={statTrakFilter}
            onValueChange={(value) => {
              setStatTrakFilter(value)
              setPage(0)
            }}
          >
            <SelectTrigger className="w-[140px]" aria-label="Filter StatTrak items">
              <SelectValue placeholder="All" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              <SelectItem value="only">Only StatTrak™</SelectItem>
              <SelectItem value="exclude">No StatTrak™</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div>
          <label htmlFor="souvenir-filter" className="text-sm font-medium mb-2 block">
            Souvenir
          </label>
          <Select
            value={souvenirFilter}
            onValueChange={(value) => {
              setSouvenirFilter(value)
              setPage(0)
            }}
          >
            <SelectTrigger className="w-[140px]" aria-label="Filter Souvenir items">
              <SelectValue placeholder="All" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              <SelectItem value="only">Only Souvenir</SelectItem>
              <SelectItem value="exclude">No Souvenir</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div>
          <label htmlFor="sort-by" className="text-sm font-medium mb-2 block">
            Sort By
          </label>
          <Select
            value={sortBy}
            onValueChange={(value) => {
              setSortBy(value as typeof sortBy)
              setPage(0)
            }}
          >
            <SelectTrigger className="w-[180px]" aria-label="Sort alerts">
              <SelectValue placeholder="Sort by" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="date">Date (Newest)</SelectItem>
              <SelectItem value="price_asc">Price (Low to High)</SelectItem>
              <SelectItem value="price_desc">Price (High to Low)</SelectItem>
              <SelectItem value="wear_asc">Wear (Low to High)</SelectItem>
              <SelectItem value="wear_desc">Wear (High to Low)</SelectItem>
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
          <CardContent className="p-12 text-center text-muted-foreground" role="status" aria-live="polite">
            No alerts found matching your criteria.
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-x-4 gap-y-6">
            {alerts.map((alert, index) => {
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

                    {/* Badges */}
                    {(alert.stattrak || alert.souvenir || alert.has_stickers) && (
                      <div className="absolute top-2 left-2 flex gap-1 flex-wrap">
                        {alert.stattrak && (
                          <Badge variant="outline" className="text-[11px] font-semibold bg-background/80 backdrop-blur-sm shadow-sm">
                            StatTrak™
                          </Badge>
                        )}
                        {alert.souvenir && (
                          <Badge variant="outline" className="text-[11px] font-semibold bg-background/80 backdrop-blur-sm shadow-sm">
                            Souvenir
                          </Badge>
                        )}
                        {alert.has_stickers && (
                          <Badge variant="outline" className="text-[11px] font-semibold bg-background/80 backdrop-blur-sm shadow-sm">
                            Stickers
                          </Badge>
                        )}
                      </div>
                    )}

                    {/* Date */}
                    <div className="absolute top-2 right-2 bg-background/80 backdrop-blur-sm text-foreground px-2 py-0.5 rounded-md shadow-sm text-[11px] font-semibold">
                      {formatShortDate(alert.sent_at)}
                    </div>

                    {/* Price pill */}
                    <div className="absolute bottom-3 left-3 bg-primary text-primary-foreground px-3 py-1 rounded-full shadow-lg text-sm font-semibold">
                      {formatPrice(alert.price)}
                    </div>

                    {/* Wear */}
                    {alert.wear_value !== undefined && alert.wear_value !== null && (
                      <div className="absolute bottom-3 right-3 bg-background/80 backdrop-blur-sm text-foreground px-2 py-0.5 rounded-md shadow-sm text-xs font-semibold">
                        {formatWearPercentage(alert.wear_value)}
                      </div>
                    )}
                  </div>

                  <div className="flex-1 flex flex-col justify-between px-3 pb-2.5 pt-2 gap-1.5">
                    <CardTitle className="text-sm leading-snug line-clamp-2">
                      {alert.item_name}
                    </CardTitle>

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
                </Card>
              )
            })}
          </div>

          {/* Pagination */}
          <div className="flex justify-between items-center">
            <div className="text-sm text-muted-foreground" aria-live="polite" aria-atomic="true">
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
