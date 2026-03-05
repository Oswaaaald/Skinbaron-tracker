import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import type { AlertSortBy } from './grid-helpers'

type AlertsGridFiltersProps = {
  filteredCount: number
  itemNames: string[]
  itemNameFilter: string
  wearFilter: string
  stickerFilter: string
  statTrakFilter: string
  souvenirFilter: string
  sortBy: AlertSortBy
  clearPending: boolean
  onItemNameFilterChange: (value: string) => void
  onWearFilterChange: (value: string) => void
  onStickerFilterChange: (value: string) => void
  onStatTrakFilterChange: (value: string) => void
  onSouvenirFilterChange: (value: string) => void
  onSortByChange: (value: AlertSortBy) => void
  onClearAll: () => void
}

export function AlertsGridFilters({
  filteredCount,
  itemNames,
  itemNameFilter,
  wearFilter,
  stickerFilter,
  statTrakFilter,
  souvenirFilter,
  sortBy,
  clearPending,
  onItemNameFilterChange,
  onWearFilterChange,
  onStickerFilterChange,
  onStatTrakFilterChange,
  onSouvenirFilterChange,
  onSortByChange,
  onClearAll,
}: AlertsGridFiltersProps) {
  return (
    <Card className="border-border/70 bg-card/90 py-0">
      <CardContent className="space-y-4 p-4 sm:p-5">
        <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <p className="text-xs font-medium uppercase tracking-[0.09em] text-muted-foreground">
            {filteredCount} result{filteredCount !== 1 ? 's' : ''}
          </p>
          <Button
            variant="outline"
            size="sm"
            onClick={onClearAll}
            disabled={clearPending}
            className="h-9 w-full text-xs sm:w-auto"
          >
            {clearPending ? (
              <>
                <LoadingSpinner size="sm" className="mr-1.5" inline />
                Clearing...
              </>
            ) : (
              'Clear All Alerts'
            )}
          </Button>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-6">
          <div className="sm:col-span-2 lg:col-span-1 xl:col-span-2">
            <label className="mb-1.5 block text-xs font-medium text-muted-foreground">Item</label>
            <Select value={itemNameFilter || 'all'} onValueChange={onItemNameFilterChange}>
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
            <label className="mb-1.5 block text-xs font-medium text-muted-foreground">Wear</label>
            <Select value={wearFilter} onValueChange={onWearFilterChange}>
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
            <label className="mb-1.5 block text-xs font-medium text-muted-foreground">Stickers</label>
            <Select value={stickerFilter} onValueChange={onStickerFilterChange}>
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
            <label className="mb-1.5 block text-xs font-medium text-muted-foreground">StatTrak™</label>
            <Select value={statTrakFilter} onValueChange={onStatTrakFilterChange}>
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
            <label className="mb-1.5 block text-xs font-medium text-muted-foreground">Souvenir</label>
            <Select value={souvenirFilter} onValueChange={onSouvenirFilterChange}>
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
            <label className="mb-1.5 block text-xs font-medium text-muted-foreground">Sort By</label>
            <Select value={sortBy} onValueChange={(value) => onSortByChange(value as AlertSortBy)}>
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
        </div>
      </CardContent>
    </Card>
  )
}
