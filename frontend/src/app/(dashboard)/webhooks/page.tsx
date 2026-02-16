"use client"

import { WebhooksTable } from "@/components/webhooks-table"
import { useAuth } from "@/contexts/auth-context"
import { LoadingState } from "@/components/ui/loading-state"

export default function WebhooksPage() {
  const { isReady } = useAuth()

  if (!isReady) {
    return <LoadingState variant="page" />
  }

  return <WebhooksTable />
}
