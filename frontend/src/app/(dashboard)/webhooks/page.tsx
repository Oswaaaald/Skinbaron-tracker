"use client"

import { WebhooksTable } from "@/components/webhooks-table"
import { useAuth } from "@/contexts/auth-context"
import { LoadingSpinner } from "@/components/ui/loading-spinner"

export default function WebhooksPage() {
  const { isReady } = useAuth()

  if (!isReady) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center">
        <LoadingSpinner size="lg" />
        <p className="text-muted-foreground mt-2">Loading...</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <WebhooksTable />
    </div>
  )
}
