// Utility functions for wear value conversion

/**
 * Convert wear value from 0-1 format to percentage (0-100)
 */
export function wearToPercentage(wear: number): number {
  return Math.round(wear * 100 * 100) / 100
}

/**
 * Convert percentage (0-100) to wear value (0-1)
 */
export function percentageToWear(percentage: number): number {
  return Math.round(percentage * 100) / 10000
}

/**
 * Format wear value as percentage for display
 */
export function formatWearPercentage(wear: number): string {
  return `${wearToPercentage(wear).toFixed(2)}%`;
}