"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { WebhooksTable } from "@/components/webhooks/table"
import { useAuth } from "@/contexts/auth-context"
import { WebhooksTableSkeleton } from "@/components/ui/skeletons"
import { PageHeader } from "@/components/page-header"
import { Webhook } from "lucide-react"

export default function WebhooksPage() {
  const [isDialogOpen, setIsDialogOpen] = useState(false)
  const { isReady } = useAuth()

  if (!isReady) {
    return <WebhooksTableSkeleton />
  }

  return (
    <div className="space-y-6 md:space-y-7">
      <PageHeader
        icon={Webhook}
        eyebrow="Dashboard"
        title="Webhooks"
        description="Configure delivery endpoints, notification style, and active state for outgoing alerts."
        actions={
          <Button onClick={() => setIsDialogOpen(true)} className="w-full sm:w-auto">
            Add Webhook
          </Button>
        }
      />
      <WebhooksTable
        onCreateWebhook={() => setIsDialogOpen(true)}
        createDialogOpen={isDialogOpen}
        onCreateDialogChange={setIsDialogOpen}
      />
    </div>
  )
}
