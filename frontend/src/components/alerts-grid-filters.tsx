import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import type { AlertSortBy } from './alerts-grid-helpers'

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
    <Card>
      <CardContent className="p-4">
        <div className="flex items-center justify-between mb-3">
          <p className="text-xs text-muted-foreground">
            {filteredCount} result{filteredCount !== 1 ? 's' : ''}
          </p>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-8 gap-3">
          <div className="col-span-2 sm:col-span-1">
            <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Item</label>
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
            <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Wear</label>
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
            <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Stickers</label>
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
            <label className="text-xs font-medium text-muted-foreground mb-1.5 block">StatTrak™</label>
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
            <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Souvenir</label>
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
            <label className="text-xs font-medium text-muted-foreground mb-1.5 block">Sort By</label>
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

          <div className="flex items-end">
            <Button variant="outline" size="sm" onClick={onClearAll} disabled={clearPending} className="h-9 w-full text-xs">
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
        </div>
      </CardContent>
    </Card>
  )
}
