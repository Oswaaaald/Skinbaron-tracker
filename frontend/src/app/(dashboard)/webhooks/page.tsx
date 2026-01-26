"use client"

import { Suspense, lazy } from "react"
import { LoadingSpinner } from "@/components/ui/loading-spinner"

const WebhooksTable = lazy(() => import("@/components/webhooks-table").then(m => ({ default: m.WebhooksTable })))

export default function WebhooksPage() {
  return (
    <div className="space-y-4">
      <Suspense fallback={<LoadingSpinner />}>
        <WebhooksTable />
      </Suspense>
    </div>
  )
}
