"use client"

import Image from "next/image"
import { useState, useCallback, useMemo } from "react"
import { useQuery, useQueryClient, keepPreviousData } from "@tanstack/react-query"
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
function getWearCondition(wearValue?: number | null): string | null {
  if (wearValue === undefined || wearValue === null) return null
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
  const [sortBy, setSortBy] = useState<'date' | 'price_asc' | 'price_desc' | 'wear_asc' | 'wear_desc'>('price_asc')
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
      limit: 0, // 0 = no limit — fetch ALL alerts
      offset: 0,
    }), 'Failed to load alerts'),
    enabled: isReady && isAuthenticated,
    staleTime: 0,
    placeholderData: keepPreviousData,
    refetchInterval: isVisible ? POLL_INTERVAL : false,
    refetchOnWindowFocus: true,
    refetchOnReconnect: true,
    notifyOnChangeProps: ['data', 'error'],
  })

  const allAlerts = useMemo(() => alertsResponse?.data ?? [], [alertsResponse?.data])

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
        result = result.filter(alert => alert.wear_value === undefined || alert.wear_value === null)
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
          if ((a.wear_value == null) && (b.wear_value == null)) return 0
          if (a.wear_value == null) return 1
          if (b.wear_value == null) return -1
          return a.wear_value - b.wear_value
        case 'wear_desc':
          if ((a.wear_value == null) && (b.wear_value == null)) return 0
          if (a.wear_value == null) return 1
          if (b.wear_value == null) return -1
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
    <div className="space-y-4">
      {/* Filters */}
      <Card>
        <CardContent className="p-4">
          <div className="flex items-center justify-between mb-3">
            <p className="text-xs text-muted-foreground">
              {filteredAlerts.length} result{filteredAlerts.length !== 1 ? 's' : ''}
            </p>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-8 gap-3">
            <div className="col-span-2 sm:col-span-1">
              <label htmlFor="item-filter" className="text-xs font-medium text-muted-foreground mb-1.5 block">
                Item
              </label>
              <Select
                value={itemNameFilter || 'all'}
                onValueChange={(value) => {
                  setItemNameFilter(value === 'all' ? '' : value)
                  setPage(0)
                }}
              >
                <SelectTrigger className="w-full" aria-label="Filter alerts by item">
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
              <label htmlFor="wear-filter" className="text-xs font-medium text-muted-foreground mb-1.5 block">
                Wear
              </label>
              <Select
                value={wearFilter}
                onValueChange={(value) => {
                  setWearFilter(value)
                  setPage(0)
                }}
              >
                <SelectTrigger className="w-full" aria-label="Filter by wear condition">
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
              <label htmlFor="sticker-filter" className="text-xs font-medium text-muted-foreground mb-1.5 block">
                Stickers
              </label>
              <Select
                value={stickerFilter}
                onValueChange={(value) => {
                  setStickerFilter(value)
                  setPage(0)
                }}
              >
                <SelectTrigger className="w-full" aria-label="Filter Sticker items">
                  <SelectValue placeholder="All" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All</SelectItem>
                  <SelectItem value="only">With Stickers</SelectItem>
                  <SelectItem value="exclude">No Stickers</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label htmlFor="stattrak-filter" className="text-xs font-medium text-muted-foreground mb-1.5 block">
                StatTrak™
              </label>
              <Select
                value={statTrakFilter}
                onValueChange={(value) => {
                  setStatTrakFilter(value)
                  setPage(0)
            }}
          >
            <SelectTrigger className="w-full" aria-label="Filter StatTrak items">
              <SelectValue placeholder="All" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              <SelectItem value="only">StatTrak™ Only</SelectItem>
              <SelectItem value="exclude">No StatTrak™</SelectItem>
            </SelectContent>
          </Select>
            </div>
            <div>
              <label htmlFor="souvenir-filter" className="text-xs font-medium text-muted-foreground mb-1.5 block">
                Souvenir
              </label>
              <Select
                value={souvenirFilter}
                onValueChange={(value) => {
                  setSouvenirFilter(value)
                  setPage(0)
                }}
              >
                <SelectTrigger className="w-full" aria-label="Filter Souvenir items">
                  <SelectValue placeholder="All" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All</SelectItem>
                  <SelectItem value="only">Souvenir Only</SelectItem>
                  <SelectItem value="exclude">No Souvenir</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label htmlFor="sort-by" className="text-xs font-medium text-muted-foreground mb-1.5 block">
                Sort By
              </label>
              <Select
                value={sortBy}
                onValueChange={(value) => {
                  setSortBy(value as typeof sortBy)
                  setPage(0)
                }}
              >
                <SelectTrigger className="w-full" aria-label="Sort alerts">
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
            <div className="flex items-end">
              <Button
                variant="outline"
                size="sm"
                onClick={handleClearAllAlerts}
                disabled={isClearingAll}
                className="h-9 w-full text-xs"
              >
                {isClearingAll ? (
                  <>
                    <LoadingSpinner size="sm" className="mr-1.5" inline />
                    Clearing...
                  </>
                ) : (
                  'Clear All Alerts'
                )}
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Grid */}
      {alerts.length === 0 ? (
        <Card className="border-dashed">
          <CardContent className="p-16 text-center" role="status" aria-live="polite">
            <p className="text-muted-foreground text-sm">No alerts found matching your criteria.</p>
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {alerts.map((alert, index) => {
              const isLCP = index === 0
              return (
                <Card
                  key={alert.id}
                  className="group relative overflow-hidden bg-card shadow-sm hover:shadow-md hover:border-border transition-all duration-200 flex flex-col p-0"
                >
                  {/* Image Header */}
                  <div className="relative aspect-[4/3] overflow-hidden bg-gradient-to-br from-slate-900/95 via-slate-800/95 to-slate-900/95">
                    {alert.skin_url ? (
                      <Image
                        src={alert.skin_url}
                        alt={alert.item_name}
                        fill
                        sizes="(max-width: 640px) 100vw, (max-width: 1024px) 50vw, (max-width: 1280px) 33vw, 25vw"
                        className="object-contain p-4 transition-transform duration-300 group-hover:scale-[1.03]"
                        priority={isLCP}
                        fetchPriority={isLCP ? "high" : "low"}
                        loading={isLCP ? "eager" : "lazy"}
                      />
                    ) : (
                      <div className="w-full h-full flex items-center justify-center text-slate-500 text-xs">
                        No Image
                      </div>
                    )}

                    {/* Badges */}
                    {(alert.stattrak || alert.souvenir || alert.has_stickers) && (
                      <div className="absolute top-2 left-2 flex gap-1 flex-wrap">
                        {alert.stattrak && (
                          <Badge className="text-[10px] font-medium bg-orange-500/90 text-white border-0 backdrop-blur-sm shadow-sm">
                            StatTrak™
                          </Badge>
                        )}
                        {alert.souvenir && (
                          <Badge className="text-[10px] font-medium bg-yellow-500/90 text-white border-0 backdrop-blur-sm shadow-sm">
                            Souvenir
                          </Badge>
                        )}
                        {alert.has_stickers && (
                          <Badge className="text-[10px] font-medium bg-sky-500/90 text-white border-0 backdrop-blur-sm shadow-sm">
                            Stickers
                          </Badge>
                        )}
                      </div>
                    )}

                    {/* Date */}
                    <div className="absolute top-2 right-2 bg-black/50 backdrop-blur-sm text-white/90 px-1.5 py-0.5 rounded text-[10px] font-medium">
                      {formatShortDate(alert.sent_at)}
                    </div>

                    {/* Price pill */}
                    <div className="absolute bottom-2.5 left-2.5 bg-primary text-primary-foreground px-2.5 py-1 rounded-full shadow-lg text-[13px] font-bold">
                      {formatPrice(alert.price)}
                    </div>

                    {/* Wear */}
                    {alert.wear_value !== undefined && alert.wear_value !== null ? (
                      <div className="absolute bottom-2.5 right-2.5 bg-black/50 backdrop-blur-sm text-white/90 px-1.5 py-0.5 rounded text-[11px] font-medium">
                        {formatWearPercentage(alert.wear_value)}
                      </div>
                    ) : (
                      <div className="absolute bottom-2.5 right-2.5 bg-black/30 backdrop-blur-sm text-white/60 px-1.5 py-0.5 rounded text-[11px] font-medium">
                        No Wear
                      </div>
                    )}
                  </div>

                  <div className="flex-1 flex flex-col justify-between px-3 pb-3 pt-2.5 gap-2">
                    <CardTitle className="text-[13px] leading-snug line-clamp-2 font-medium">
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
          <div className="flex flex-col sm:flex-row justify-between items-center gap-3 pt-2">
            <p className="text-xs text-muted-foreground order-2 sm:order-1" aria-live="polite" aria-atomic="true">
              Showing {page * ALERTS_PAGE_SIZE + 1}–{page * ALERTS_PAGE_SIZE + alerts.length} alerts
            </p>
            <div className="flex gap-2 order-1 sm:order-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage(p => Math.max(0, p - 1))}
                disabled={page === 0}
              >
                <ChevronLeft className="h-3.5 w-3.5 mr-1" />
                Previous
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setPage(p => p + 1)}
                disabled={!hasMorePages}
              >
                Next
                <ChevronRight className="h-3.5 w-3.5 ml-1" />
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
