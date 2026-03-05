"use client"

import { useAuth } from "@/contexts/auth-context"
import { AdminPanel } from "@/components/admin/panel"
import { AdminPanelSkeleton } from "@/components/ui/skeletons"
import { PageHeader } from "@/components/page-header"
import { Shield } from "lucide-react"

export default function AdminPage() {
  const { isReady } = useAuth()

  if (!isReady) {
    return <AdminPanelSkeleton />
  }

  return (
    <div className="space-y-6 md:space-y-7">
      <PageHeader
        icon={Shield}
        eyebrow="Administration"
        title="Admin Panel"
        description="User moderation, access controls, and operational tools for platform management."
      />
      <AdminPanel />
    </div>
  )
}
