import { useState } from 'react'
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
import { cn } from '@/lib/utils'

function AlertCardImage({
  src,
  alt,
  isLCP,
}: {
  src: string | null
  alt: string
  isLCP: boolean
}) {
  const [status, setStatus] = useState<'loading' | 'loaded' | 'error'>('loading')

  if (!src || status === 'error') {
    return (
      <div className="h-full w-full flex items-center justify-center text-slate-500 text-xs">
        No Image
      </div>
    )
  }

  return (
    <>
      <div
        className={cn(
          'absolute inset-0 animate-pulse bg-slate-700/30 transition-opacity duration-300',
          status === 'loaded' && 'opacity-0',
        )}
      />
      <Image
        src={src}
        alt={alt}
        fill
        sizes="(max-width: 640px) 100vw, (max-width: 1024px) 50vw, (max-width: 1280px) 33vw, 25vw"
        className={cn(
          'object-contain p-4 transition-opacity duration-500',
          status === 'loaded' ? 'opacity-100' : 'opacity-0',
        )}
        priority={isLCP}
        fetchPriority={isLCP ? 'high' : 'low'}
        loading={isLCP ? 'eager' : 'lazy'}
        onLoad={() => setStatus('loaded')}
        onError={() => setStatus('error')}
      />
    </>
  )
}

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
              className="relative flex flex-col overflow-hidden border-border/70 bg-card/92 p-0 shadow-sm transition-[box-shadow,border-color] duration-200 hover:shadow-md"
            >
              <div className="relative aspect-[4/3] overflow-hidden bg-gradient-to-br from-slate-900/95 via-slate-800/95 to-slate-900/95">
                <AlertCardImage
                  key={`${alert.id}-${alert.skin_url ?? 'none'}`}
                  src={alert.skin_url}
                  alt={alert.item_name}
                  isLCP={isLCP}
                />

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

              <div className="flex flex-1 flex-col justify-between gap-2.5 px-3.5 pb-3.5 pt-3">
                <CardTitle className="line-clamp-2 text-[13px] font-medium leading-snug">
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
