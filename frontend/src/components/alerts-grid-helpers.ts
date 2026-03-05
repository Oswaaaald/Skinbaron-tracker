import type { Alert } from '@/lib/api'

export type AlertSortBy = 'date' | 'price_asc' | 'price_desc' | 'wear_asc' | 'wear_desc'

export type AlertFilters = {
  itemNameFilter: string
  statTrakFilter: string
  souvenirFilter: string
  wearFilter: string
  stickerFilter: string
  sortBy: AlertSortBy
}

export function cleanItemName(name: string): string {
  let cleaned = name
  cleaned = cleaned.replace(/^StatTrak™\s+/i, '')
  cleaned = cleaned.replace(/^Souvenir\s+/i, '')
  cleaned = cleaned.replace(/\s*\((Factory New|Minimal Wear|Field-Tested|Well-Worn|Battle-Scarred)\)\s*$/i, '')
  return cleaned.trim()
}

export function getWearCondition(wearValue?: number | null): string | null {
  if (wearValue === undefined || wearValue === null) return null
  if (wearValue < 0.07) return 'fn'
  if (wearValue < 0.15) return 'mw'
  if (wearValue < 0.38) return 'ft'
  if (wearValue < 0.45) return 'ww'
  return 'bs'
}

export function getSkinBaronUrl(saleId: string, itemName?: string) {
  if (itemName) {
    const productName = itemName.replace(/StatTrak™\s+/, '').replace(/Souvenir\s+/, '')
    const encodedProductName = encodeURIComponent(productName)
    return `https://skinbaron.de/offers/show?offerUuid=${saleId}&productName=${encodedProductName}`
  }
  return `https://skinbaron.de/offers/show?offerUuid=${saleId}`
}

export function getAlertItemNames(allAlerts: Alert[]): string[] {
  return Array.from(new Set(allAlerts.map(a => cleanItemName(a.item_name)))).sort()
}

export function filterAndSortAlerts(allAlerts: Alert[], filters: AlertFilters): Alert[] {
  const {
    itemNameFilter,
    statTrakFilter,
    souvenirFilter,
    wearFilter,
    stickerFilter,
    sortBy,
  } = filters

  let result = [...allAlerts]

  if (itemNameFilter) {
    result = result.filter(alert => cleanItemName(alert.item_name) === itemNameFilter)
  }

  if (statTrakFilter === 'only') {
    result = result.filter(alert => alert.stattrak)
  } else if (statTrakFilter === 'exclude') {
    result = result.filter(alert => !alert.stattrak)
  }

  if (souvenirFilter === 'only') {
    result = result.filter(alert => alert.souvenir)
  } else if (souvenirFilter === 'exclude') {
    result = result.filter(alert => !alert.souvenir)
  }

  if (wearFilter !== 'all') {
    if (wearFilter === 'no_wear') {
      result = result.filter(alert => alert.wear_value === undefined || alert.wear_value === null)
    } else {
      result = result.filter(alert => getWearCondition(alert.wear_value) === wearFilter)
    }
  }

  if (stickerFilter === 'only') {
    result = result.filter(alert => alert.has_stickers)
  } else if (stickerFilter === 'exclude') {
    result = result.filter(alert => !alert.has_stickers)
  }

  result.sort((a, b) => {
    switch (sortBy) {
      case 'price_asc':
        return a.price - b.price
      case 'price_desc':
        return b.price - a.price
      case 'wear_asc':
        if (a.wear_value == null && b.wear_value == null) return 0
        if (a.wear_value == null) return 1
        if (b.wear_value == null) return -1
        return a.wear_value - b.wear_value
      case 'wear_desc':
        if (a.wear_value == null && b.wear_value == null) return 0
        if (a.wear_value == null) return 1
        if (b.wear_value == null) return -1
        return b.wear_value - a.wear_value
      case 'date':
      default:
        return (b.sent_at ? new Date(b.sent_at).getTime() : 0) - (a.sent_at ? new Date(a.sent_at).getTime() : 0)
    }
  })

  return result
}
