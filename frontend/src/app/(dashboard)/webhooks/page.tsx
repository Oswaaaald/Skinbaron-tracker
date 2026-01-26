"use client"

import { WebhooksTable } from "@/components/webhooks-table"
import { useAuth } from "@/contexts/auth-context"
import { LoadingSpinner } from "@/components/ui/loading-spinner"

export default function WebhooksPage() {
  const { isReady } = useAuth()

  if (!isReady) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <WebhooksTable />
    </div>
  )
}
