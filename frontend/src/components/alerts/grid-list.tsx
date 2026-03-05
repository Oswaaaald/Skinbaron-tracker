import Image from 'next/image'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardTitle } from '@/components/ui/card'
import { ExternalLink, ChevronLeft, ChevronRight } from 'lucide-react'
import { formatWearPercentage } from '@/lib/wear-utils'
import { formatPrice, formatShortDate } from '@/lib/formatters'
import type { Alert } from '@/lib/api'
import { ALERTS_PAGE_SIZE } from '@/lib/constants'
import { getSkinBaronUrl } from './grid-helpers'

export function AlertsGridList({
  alerts,
  page,
  hasMorePages,
  onPageChange,
}: {
  alerts: Alert[]
  page: number
  hasMorePages: boolean
  onPageChange: (nextPage: number) => void
}) {
  return (
    <>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4 animate-stagger">
        {alerts.map((alert, index) => {
          const isLCP = index === 0
          return (
            <Card
              key={alert.id}
              className="group relative overflow-hidden bg-card shadow-sm hover:shadow-md hover:border-border transition-all duration-200 flex flex-col p-0"
            >
              <div className="relative aspect-[4/3] overflow-hidden bg-gradient-to-br from-slate-900/95 via-slate-800/95 to-slate-900/95">
                {alert.skin_url ? (
                  <Image
                    src={alert.skin_url}
                    alt={alert.item_name}
                    fill
                    sizes="(max-width: 640px) 100vw, (max-width: 1024px) 50vw, (max-width: 1280px) 33vw, 25vw"
                    className="object-contain p-4 transition-transform duration-300 group-hover:scale-[1.03]"
                    priority={isLCP}
                    fetchPriority={isLCP ? 'high' : 'low'}
                    loading={isLCP ? 'eager' : 'lazy'}
                  />
                ) : (
                  <div className="w-full h-full flex items-center justify-center text-slate-500 text-xs">No Image</div>
                )}

                {(alert.stattrak || alert.souvenir || alert.has_stickers) && (
                  <div className="absolute top-2 left-2 flex gap-1 flex-wrap">
                    {alert.stattrak && (
                      <Badge className="text-[10px] font-medium bg-orange-500/90 text-white border-0 backdrop-blur-sm shadow-sm">StatTrak™</Badge>
                    )}
                    {alert.souvenir && (
                      <Badge className="text-[10px] font-medium bg-yellow-500/90 text-white border-0 backdrop-blur-sm shadow-sm">Souvenir</Badge>
                    )}
                    {alert.has_stickers && (
                      <Badge className="text-[10px] font-medium bg-sky-500/90 text-white border-0 backdrop-blur-sm shadow-sm">Stickers</Badge>
                    )}
                  </div>
                )}

                <div className="absolute top-2 right-2 bg-black/50 backdrop-blur-sm text-white/90 px-1.5 py-0.5 rounded text-[10px] font-medium">
                  {formatShortDate(alert.sent_at)}
                </div>

                <div className="absolute bottom-2.5 left-2.5 bg-primary text-primary-foreground px-2.5 py-1 rounded-full shadow-lg text-[13px] font-bold">
                  {formatPrice(alert.price)}
                </div>

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

      <div className="flex flex-col sm:flex-row justify-between items-center gap-3 pt-2">
        <p className="text-xs text-muted-foreground order-2 sm:order-1" aria-live="polite" aria-atomic="true">
          Showing {page * ALERTS_PAGE_SIZE + 1}–{page * ALERTS_PAGE_SIZE + alerts.length} alerts
        </p>
        <div className="flex gap-2 order-1 sm:order-2">
          <Button variant="outline" size="sm" onClick={() => onPageChange(Math.max(0, page - 1))} disabled={page === 0}>
            <ChevronLeft className="h-3.5 w-3.5 mr-1" />
            Previous
          </Button>
          <Button variant="outline" size="sm" onClick={() => onPageChange(page + 1)} disabled={!hasMorePages}>
            Next
            <ChevronRight className="h-3.5 w-3.5 ml-1" />
          </Button>
        </div>
      </div>
    </>
  )
}

export function AlertsGridEmptyState() {
  return (
    <Card className="border-dashed">
      <CardContent className="p-16 text-center" role="status" aria-live="polite">
        <p className="text-muted-foreground text-sm">No alerts found matching your criteria.</p>
      </CardContent>
    </Card>
  )
}
