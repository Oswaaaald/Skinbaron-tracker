"use client"

import { useState, useEffect } from "react"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { LoadingSpinner } from "@/components/ui/loading-spinner"
import { ExternalLink, Search, ChevronLeft, ChevronRight, Sparkles, TrendingDown, Bell } from "lucide-react"
import { apiClient, type Alert } from "@/lib/api"
import { useSyncStats } from "@/hooks/use-sync-stats"
import { formatWearPercentage } from "@/lib/wear-utils"
import { useAuth } from "@/contexts/auth-context"

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
  const [search, setSearch] = useState('')
  const [alertTypeFilter, setAlertTypeFilter] = useState<string>('')
  const [isClearingAll, setIsClearingAll] = useState(false)
  const limit = 12
  const queryClient = useQueryClient()
  const { syncStats } = useSyncStats()
  const { isReady, isAuthenticated } = useAuth()

  const handleClearAllAlerts = async () => {
    if (isClearingAll) return
    
    if (!confirm('⚠️ Are you sure you want to delete ALL your alerts? This cannot be undone.')) {
      return
    }
    
    setIsClearingAll(true)
    try {
      const response = await apiClient.clearAllAlerts()
      if (response.success) {
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
    enabled: isReady && isAuthenticated,
    refetchInterval: 10000,
    refetchIntervalInBackground: true,
  })

  useEffect(() => {
    if (alertsResponse) {
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
    const date = new Date(dateString)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffMins = Math.floor(diffMs / 60000)
    
    if (diffMins < 1) return 'Just now'
    if (diffMins < 60) return `${diffMins}m ago`
    if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`
    return date.toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric' })
  }

  const getSkinBaronUrl = (saleId: string, itemName?: string) => {
    if (itemName) {
      const productName = itemName.replace(/StatTrak™\s+/, '').replace(/Souvenir\s+/, '')
      const encodedProductName = encodeURIComponent(productName)
      return `https://skinbaron.de/offers/show?offerUuid=${saleId}&productName=${encodedProductName}`
    }
    return `https://skinbaron.de/offers/show?offerUuid=${saleId}`
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
    <div className="space-y-6">
      {/* Filters */}
      <div className="flex gap-4 items-end flex-wrap">
        <div className="flex-1 min-w-[250px]">
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
                setPage(0)
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
              setPage(0)
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

      {/* Grid */}
      {alerts.length === 0 ? (
        <Card>
          <CardContent className="p-12 text-center text-muted-foreground">
            No alerts found matching your criteria.
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {alerts.map((alert) => {
              const config = ALERT_TYPE_CONFIG[alert.alert_type as keyof typeof ALERT_TYPE_CONFIG] || ALERT_TYPE_CONFIG.match
              const Icon = config.icon
              
              return (
                <Card key={alert.id} className="overflow-hidden hover:shadow-xl transition-all duration-300 hover:scale-[1.02] flex flex-col group">
                  {/* Image Header with Gradient Overlay */}
                  <div className="relative h-56 bg-gradient-to-br from-background to-muted/50 overflow-hidden">
                    {alert.skin_url ? (
                      <>
                        <img 
                          src={alert.skin_url} 
                          alt={alert.item_name}
                          className="w-full h-full object-contain p-6 group-hover:scale-110 transition-transform duration-300"
                          onError={(e) => {
                            e.currentTarget.src = 'data:image/svg+xml,%3Csvg xmlns="http://www.w3.org/2000/svg" width="200" height="200"%3E%3Crect fill="%23ddd" width="200" height="200"/%3E%3Ctext fill="%23999" font-family="Arial" font-size="14" x="50%25" y="50%25" text-anchor="middle" dy=".3em"%3ENo Image%3C/text%3E%3C/svg%3E'
                          }}
                        />
                        {/* Subtle gradient overlay at bottom */}
                        <div className="absolute inset-x-0 bottom-0 h-20 bg-gradient-to-t from-background/80 to-transparent" />
                      </>
                    ) : (
                      <div className="w-full h-full flex items-center justify-center text-muted-foreground text-sm">
                        No Image Available
                      </div>
                    )}
                    {/* Type Badge - positioned elegantly */}
                    <div className="absolute top-3 right-3">
                      <Badge variant={config.color} className="shadow-lg backdrop-blur-sm">
                        <Icon className="h-3.5 w-3.5 mr-1.5" />
                        {config.label}
                      </Badge>
                    </div>
                    {/* Time Badge - bottom left */}
                    <div className="absolute bottom-3 left-3">
                      <Badge variant="secondary" className="shadow-lg backdrop-blur-sm">
                        {formatDate(alert.sent_at)}
                      </Badge>
                    </div>
                  </div>

                  <CardHeader className="pb-4">
                    <CardTitle className="text-base leading-tight line-clamp-2 min-h-[2.5rem]">
                      {alert.item_name}
                    </CardTitle>
                  </CardHeader>
                  
                  <CardContent className="space-y-4 flex-1 flex flex-col pt-0">
                    {/* Price and Wear - Clean grid layout */}
                    <div className="space-y-3">
                      <div className="flex items-center justify-between p-3 bg-muted/50 rounded-lg">
                        <span className="text-sm font-medium text-muted-foreground">Price</span>
                        <span className="text-xl font-bold">
                          {formatPrice(alert.price)}
                        </span>
                      </div>
                      <div className="flex items-center justify-between p-3 bg-muted/30 rounded-lg">
                        <span className="text-sm font-medium text-muted-foreground">Wear</span>
                        <span className="text-sm font-semibold">
                          {alert.wear_value !== undefined && alert.wear_value !== null ? (
                            formatWearPercentage(alert.wear_value)
                          ) : (
                            <span className="text-muted-foreground">N/A</span>
                          )}
                        </span>
                      </div>
                    </div>

                    {/* Features */}
                    {(alert.stattrak || alert.souvenir) && (
                      <div className="flex gap-2 flex-wrap">
                        {alert.stattrak && (
                          <Badge variant="outline" className="text-xs font-medium">
                            StatTrak™
                          </Badge>
                        )}
                        {alert.souvenir && (
                          <Badge variant="outline" className="text-xs font-medium">
                            Souvenir
                          </Badge>
                        )}
                      </div>
                    )}

                    {/* Action Button */}
                    <Button
                      className="w-full mt-auto group-hover:shadow-lg transition-shadow"
                      size="sm"
                      onClick={() => window.open(getSkinBaronUrl(alert.sale_id, alert.item_name), '_blank')}
                    >
                      View on SkinBaron
                      <ExternalLink className="ml-2 h-3.5 w-3.5" />
                    </Button>
                  </CardContent>
                </Card>
              )
            })}
          </div>

          {/* Pagination */}
          <div className="flex justify-between items-center">
            <div className="text-sm text-muted-foreground">
              Showing {page * limit + 1} - {page * limit + alerts.length} alerts
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
    </div>
  )
}
