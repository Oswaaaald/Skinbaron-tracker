export function formatPrice(price: number): string {
  return new Intl.NumberFormat('de-DE', {
    style: 'currency',
    currency: 'EUR',
    minimumFractionDigits: 2,
  }).format(price)
}

export function formatUptime(uptimeSeconds?: number): string {
  if (!uptimeSeconds) return 'N/A'
  const hours = Math.floor(uptimeSeconds / 3600)
  const minutes = Math.floor((uptimeSeconds % 3600) / 60)
  return `${hours}h ${minutes}m`
}
