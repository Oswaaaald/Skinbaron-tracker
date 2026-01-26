'use client'

import { DashboardNav } from "@/components/dashboard-nav"
import { UserNav } from "@/components/user-nav"
import { ThemeToggle } from "@/components/theme-toggle"
import { useAuth } from "@/contexts/auth-context"

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const { isAuthenticated, isLoading, isReady } = useAuth()

  // Don't show navigation during loading to prevent flash
  if (isLoading || !isReady || !isAuthenticated) {
    return children
  }

  return (
    <div className="container mx-auto p-4">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-3xl font-bold">SkinBaron Tracker</h1>
        <div className="flex items-center gap-4">
          <ThemeToggle />
          <UserNav />
        </div>
      </div>
      
      <div className="mb-6">
        <DashboardNav />
      </div>
      
      {children}
    </div>
  )
}
