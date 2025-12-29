"use client"

import { useState, useEffect } from "react"
import { useQuery } from "@tanstack/react-query"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { LoadingSpinner } from "@/components/ui/loading-spinner"
import {
  ExternalLink,
  Search,
  ChevronLeft,
  ChevronRight,
  Sparkles,
  TrendingDown,
  Bell
} from "lucide-react"
import { apiClient, type Alert } from "@/lib/api"
import { useSyncStats } from "@/hooks/use-sync-stats"
import { formatWearPercentage } from "@/lib/wear-utils"
import { useAuth } from "@/contexts/auth-context"

const ALERT_TYPE_CONFIG = {
  match: { label: "Rule Match", icon: Bell },
  best_deal: { label: "Best Deal", icon: TrendingDown },
  new_item: { label: "New Item", icon: Sparkles }
} as const

export function AlertsGrid() {
  const [page, setPage] = useState(0)
  const [search, setSearch] = useState("")
  const [alertTypeFilter, setAlertTypeFilter] = useState("")
  const limit = 12

  const { syncStats } = useSyncStats()
  const { isReady, isAuthenticated } = useAuth()

  const { data, isLoading, error } = useQuery({
    queryKey: ["alerts", page, search, alertTypeFilter],
    queryFn: () =>
      apiClient.getAlerts({
        limit,
        offset: page * limit,
        alert_type: alertTypeFilter
          ? (alertTypeFilter as "match" | "best_deal" | "new_item")
          : undefined
      }),
    enabled: isReady && isAuthenticated,
    refetchInterval: 10000,
    refetchIntervalInBackground: true
  })

  useEffect(() => {
    if (data) syncStats()
  }, [data, syncStats])

  if (isLoading) return <LoadingSpinner />

  if (error) {
    return (
      <Card>
        <CardContent className="pt-6 text-center text-red-600">
          Error loading alerts
        </CardContent>
      </Card>
    )
  }

  const alerts: Alert[] = data?.data || []
  const hasMorePages = alerts.length === limit

  const formatPrice = (price: number) =>
    new Intl.NumberFormat("fr-FR", {
      style: "currency",
      currency: "EUR"
    }).format(price)

  const formatDate = (date?: string) => {
    if (!date) return "N/A"
    const diff = Date.now() - new Date(date).getTime()
    const mins = Math.floor(diff / 60000)
    if (mins < 1) return "Just now"
    if (mins < 60) return `${mins}m ago`
    if (mins < 1440) return `${Math.floor(mins / 60)}h ago`
    return new Date(date).toLocaleDateString("en-GB")
  }

  const getSkinBaronUrl = (saleId: string, itemName?: string) => {
    if (!itemName) return `https://skinbaron.de/offers/show?offerUuid=${saleId}`
    const clean = itemName.replace(/StatTrak™\s+|Souvenir\s+/g, "")
    return `https://skinbaron.de/offers/show?offerUuid=${saleId}&productName=${encodeURIComponent(clean)}`
  }

  return (
    <div className="space-y-6">
      {/* Filters */}
      <div className="flex flex-wrap gap-4 items-end">
        <div className="flex-1 min-w-[240px]">
          <label className="text-sm font-medium mb-2 block">Search</label>
          <div className="relative">
            <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
            <Input
              value={search}
              onChange={(e) => {
                setSearch(e.target.value)
                setPage(0)
              }}
              className="pl-10"
              placeholder="Search by item name…"
            />
          </div>
        </div>

        <div>
          <label className="text-sm font-medium mb-2 block">Alert Type</label>
          <Select
            value={alertTypeFilter}
            onValueChange={(v) => {
              setAlertTypeFilter(v === "all" ? "" : v)
              setPage(0)
            }}
          >
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="All types" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All</SelectItem>
              <SelectItem value="match">Rule Match</SelectItem>
              <SelectItem value="best_deal">Best Deal</SelectItem>
              <SelectItem value="new_item">New Item</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {/* Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-x-4 gap-y-6">
        {alerts.map((alert) => {
          const config =
            ALERT_TYPE_CONFIG[alert.alert_type as keyof typeof ALERT_TYPE_CONFIG] ||
            ALERT_TYPE_CONFIG.match
          const Icon = config.icon

          return (
            <Card
              key={alert.id}
              className="
                group relative overflow-hidden
                rounded-2xl
                bg-gradient-to-b from-[#0b1220] to-[#070d18]
                border border-white/15
                shadow-[0_12px_35px_rgba(0,0,0,0.45)]
                hover:shadow-[0_30px_80px_rgba(0,0,0,0.65)]
                transition-all duration-300
                flex flex-col p-0
              "
            >
              {/* Image */}
              <div className="relative aspect-[4/3] overflow-hidden">
                <div className="absolute inset-0 bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900" />
                <div className="absolute inset-0 bg-black/30" />

                {alert.skin_url && (
                  <img
                    src={alert.skin_url}
                    alt={alert.item_name}
                    className="relative z-10 w-full h-full object-contain p-5 transition-transform duration-500 group-hover:scale-[1.06]"
                  />
                )}

                <Badge
                  className={`
                    absolute top-3 left-3
                    rounded-full px-2.5 py-1 text-[11px] font-medium
                    backdrop-blur-md shadow-sm
                    ${
                      alert.alert_type === "match"
                        ? "bg-blue-500/20 text-blue-300 border border-blue-400/30"
                        : alert.alert_type === "best_deal"
                        ? "bg-red-500/20 text-red-300 border border-red-400/30"
                        : "bg-purple-500/20 text-purple-300 border border-purple-400/30"
                    }
                  `}
                >
                  <Icon className="h-3 w-3 mr-1" />
                  {config.label}
                </Badge>

                <div className="absolute bottom-3 right-3 bg-white text-black text-sm font-semibold px-3 py-1 rounded-full shadow-lg">
                  {formatPrice(alert.price)}
                </div>
              </div>

              {/* Border separator */}
              <div className="h-px bg-white/10" />

              {/* Content */}
              <CardHeader className="px-4 py-4 space-y-3 flex-1">
                <div>
                  <CardTitle className="text-sm font-semibold leading-snug line-clamp-2">
                    {alert.item_name}
                  </CardTitle>
                  <CardDescription className="text-xs mt-1 opacity-70">
                    {formatDate(alert.sent_at)}
                  </CardDescription>
                </div>

                <div className="flex justify-between text-xs">
                  <span className="text-muted-foreground">Wear</span>
                  <span className="font-medium">
                    {alert.wear_value != null
                      ? formatWearPercentage(alert.wear_value)
                      : "—"}
                  </span>
                </div>

                {(alert.stattrak || alert.souvenir) && (
                  <div className="flex gap-1">
                    {alert.stattrak && (
                      <Badge className="text-[10px] rounded-full px-2 py-0.5">
                        StatTrak™
                      </Badge>
                    )}
                    {alert.souvenir && (
                      <Badge
                        variant="secondary"
                        className="text-[10px] rounded-full px-2 py-0.5"
                      >
                        Souvenir
                      </Badge>
                    )}
                  </div>
                )}

                <Button asChild size="sm" className="w-full rounded-full mt-2">
                  <a
                    href={getSkinBaronUrl(alert.sale_id, alert.item_name)}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    View on SkinBaron
                    <ExternalLink className="ml-2 h-3 w-3" />
                  </a>
                </Button>
              </CardHeader>
            </Card>
          )
        })}
      </div>

      {/* Pagination */}
      <div className="flex justify-between items-center">
        <span className="text-sm text-muted-foreground">
          Showing {page * limit + 1} – {page * limit + alerts.length}
        </span>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            disabled={page === 0}
            onClick={() => setPage((p) => Math.max(0, p - 1))}
          >
            <ChevronLeft className="h-4 w-4 mr-1" />
            Previous
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={!hasMorePages}
            onClick={() => setPage((p) => p + 1)}
          >
            Next
            <ChevronRight className="h-4 w-4 ml-1" />
          </Button>
        </div>
      </div>
    </div>
  )
}
