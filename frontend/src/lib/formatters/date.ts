import { LOCALE, normalizeUtcDateString } from './common'

export function formatRelativeDate(dateString: string): string {
  const date = new Date(normalizeUtcDateString(dateString))
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()

  if (diffMs < 0) {
    const absoluteDate = date.toLocaleDateString(LOCALE, {
      day: 'numeric',
      month: 'long',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    })
    return `Just now • ${absoluteDate}`
  }

  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMs / 3600000)
  const diffDays = Math.floor(diffMs / 86400000)

  let relative = ''
  if (diffMins < 1) relative = 'Just now'
  else if (diffMins < 60) relative = `${diffMins} minute${diffMins > 1 ? 's' : ''} ago`
  else if (diffHours < 24) relative = `${diffHours} hour${diffHours > 1 ? 's' : ''} ago`
  else if (diffDays < 7) relative = `${diffDays} day${diffDays > 1 ? 's' : ''} ago`
  else {
    relative = date.toLocaleDateString(LOCALE, {
      day: 'numeric',
      month: 'long',
      year: 'numeric',
    })
  }

  const fullDate = date.toLocaleString(LOCALE, {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  })

  return `${relative} • ${fullDate}`
}

export function formatShortDate(dateString?: string | null): string {
  if (!dateString) return 'N/A'

  const date = new Date(normalizeUtcDateString(dateString))
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)

  if (diffMins < 1) return 'Just now'
  if (diffMins < 60) return `${diffMins}m ago`
  if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`
  return date.toLocaleDateString(LOCALE, { day: 'numeric', month: 'long', year: 'numeric' })
}

export function formatSystemDate(dateString?: Date | string | null): string {
  if (!dateString) return 'Never'

  const date = dateString instanceof Date
    ? dateString
    : new Date(normalizeUtcDateString(dateString))

  return date.toLocaleString(LOCALE, {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  })
}

export function formatDateTime(dateString?: string | null): string {
  if (!dateString) return '—'

  const date = new Date(normalizeUtcDateString(dateString))
  return date.toLocaleString(LOCALE, {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  })
}

export function formatDateOnly(dateString?: string | null): string {
  if (!dateString) return '—'

  const date = new Date(normalizeUtcDateString(dateString))
  return date.toLocaleDateString(LOCALE, {
    day: 'numeric',
    month: 'long',
    year: 'numeric',
  })
}
