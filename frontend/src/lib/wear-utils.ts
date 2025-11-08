// Utility functions for wear value conversion

/**
 * Convert wear value from 0-1 format to percentage (0-100)
 */
export function wearToPercentage(wear: number): number {
  return Math.round(wear * 100)
}

/**
 * Convert percentage (0-100) to wear value (0-1)
 */
export function percentageToWear(percentage: number): number {
  return percentage / 100
}

/**
 * Format wear value for display as percentage
 */
export function formatWearPercentage(wear: number): string {
  return `${wearToPercentage(wear)}%`
}