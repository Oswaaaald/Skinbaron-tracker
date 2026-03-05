/**
 * Centralized formatting utilities
 *
 * Convention:
 * - Locale: 'en-GB' everywhere (DD/MM/YYYY, 24h)
 * - Timezone: browser local TZ for display
 * - DB stores UTC internally
 */

export { capitalize } from './formatters/common'

export {
  formatRelativeDate,
  formatShortDate,
  formatSystemDate,
  formatDateTime,
  formatDateOnly,
} from './formatters/date'

export { formatPrice, formatUptime } from './formatters/misc'
export { formatEventData } from './formatters/event-data'
