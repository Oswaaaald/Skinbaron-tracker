"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { WebhooksTable } from "@/components/webhooks-table"
import { useAuth } from "@/contexts/auth-context"
import { LoadingState } from "@/components/ui/loading-state"

export default function WebhooksPage() {
  const [isDialogOpen, setIsDialogOpen] = useState(false)
  const { isReady } = useAuth()

  if (!isReady) {
    return <LoadingState variant="page" />
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Webhooks</h2>
          <p className="text-sm text-muted-foreground mt-1">
            Manage your encrypted webhook endpoints for notifications
          </p>
        </div>
        <Button onClick={() => setIsDialogOpen(true)} className="w-full sm:w-auto">
          Add Webhook
        </Button>
      </div>
      <WebhooksTable
        onCreateWebhook={() => setIsDialogOpen(true)}
        createDialogOpen={isDialogOpen}
        onCreateDialogChange={setIsDialogOpen}
      />
    </div>
  )
}
