"use client"

import { useAuth } from "@/contexts/auth-context"
import { SystemStats } from "@/components/system/stats"
import { SystemStatsSkeleton } from "@/components/ui/skeletons"
import { PageHeader } from "@/components/page-header"
import { Activity } from "lucide-react"

export default function AdminSystemPage() {
  const { isReady } = useAuth()

  if (!isReady) {
    return <SystemStatsSkeleton />
  }

  return (
    <div className="space-y-5">
      <PageHeader
        icon={Activity}
        eyebrow="Administration"
        title="System Status"
        description="Live health metrics and service-level signals for backend operations."
      />
      <SystemStats enabled={true} />
    </div>
  )
}
