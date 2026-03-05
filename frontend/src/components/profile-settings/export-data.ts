import { apiClient } from '@/lib/api'
import { extractErrorMessage } from '@/lib/utils'

interface ToastFn {
  (params: { title?: string; description?: string; variant?: 'default' | 'destructive' }): void
}

export async function exportUserData(toast: ToastFn) {
  try {
    const response = await apiClient.get('/api/user/data-export')
    if (!response.success || !response.data) return

    const blob = new Blob([JSON.stringify(response.data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `skinbaron-tracker-export-${new Date().toISOString().split('T')[0]}.json`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    setTimeout(() => URL.revokeObjectURL(url), 1000)
    toast({ title: '✅ Data exported', description: 'Your data has been downloaded' })
  } catch (error) {
    toast({ variant: 'destructive', title: '❌ Export failed', description: extractErrorMessage(error, 'Failed to export data') })
  }
}
