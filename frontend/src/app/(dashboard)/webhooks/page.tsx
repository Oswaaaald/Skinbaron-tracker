"use client"

import { Suspense, lazy } from "react"
import { LoadingSpinner } from "@/components/ui/loading-spinner"

const WebhooksTable = lazy(() => import("@/components/webhooks-table").then(m => ({ default: m.WebhooksTable })))

export default function WebhooksPage() {
  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Webhooks</h2>
        <p className="text-muted-foreground">
          Manage your encrypted webhook endpoints for notifications
        </p>
      </div>
      <Suspense fallback={<LoadingSpinner />}>
        <WebhooksTable />
      </Suspense>
    </div>
  )
}
