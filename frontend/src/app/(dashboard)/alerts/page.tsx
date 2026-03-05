"use client"

import { AlertsGrid } from "@/components/alerts/grid"
import { useAuth } from "@/contexts/auth-context"
import { AlertsGridSkeleton } from "@/components/ui/skeletons"
import { PageHeader } from "@/components/page-header"
import { Bell } from "lucide-react"

export default function AlertsPage() {
  const { isReady } = useAuth()

  if (!isReady) {
    return <AlertsGridSkeleton />
  }

  return (
    <div className="space-y-6 md:space-y-7">
      <PageHeader
        icon={Bell}
        eyebrow="Dashboard"
        title="Alert History"
        description="All listing matches detected by your active rules, with filters and quick review actions."
      />
      <AlertsGrid />
    </div>
  )
}
