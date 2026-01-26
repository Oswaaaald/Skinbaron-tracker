"use client"

import { WebhooksTable } from "@/components/webhooks-table"
import { useAuth } from "@/contexts/auth-context"

export default function WebhooksPage() {
  const { isReady } = useAuth()

  if (!isReady) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary mx-auto mb-4"></div>
          <p className="text-muted-foreground">Loading...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <WebhooksTable />
    </div>
  )
}
