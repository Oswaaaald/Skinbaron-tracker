export const DURATION_PRESETS = [
  { label: '1h', hours: 1 },
  { label: '6h', hours: 6 },
  { label: '12h', hours: 12 },
  { label: '24h', hours: 24 },
  { label: '3d', hours: 72 },
  { label: '7d', hours: 168 },
  { label: '14d', hours: 336 },
  { label: '30d', hours: 720 },
] as const

export function formatDuration(hours: number): string {
  if (hours < 24) return `${hours}h`
  const days = Math.floor(hours / 24)
  const rem = hours % 24
  return rem > 0 ? `${days}d ${rem}h` : `${days}d`
}
