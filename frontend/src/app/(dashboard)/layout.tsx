'use client'

import { DashboardNav, MobileNavTrigger } from "@/components/dashboard-nav"
import { UserNav } from "@/components/user-nav"
import { ThemeToggle } from "@/components/theme-toggle"
import { useAuth } from "@/contexts/auth-context"
import { useAlertNotifier } from "@/hooks/use-alert-notifier"
import { flushQueuedToasts } from "@/hooks/use-toast"
import { useEffect, useState } from "react"
import { Skeleton } from "@/components/ui/skeleton"

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode
}) {
  const { isAuthenticated, isLoading, isReady } = useAuth()
  const [hasBeenAuthenticated, setHasBeenAuthenticated] = useState(false)

  // Track if user has been authenticated at least once
  useEffect(() => {
    if (isAuthenticated) {
      setHasBeenAuthenticated(true)
    }
  }, [isAuthenticated])

  // Flush any toasts queued before a hard navigation (e.g. post-login redirect)
  useEffect(() => {
    flushQueuedToasts()
  }, [])

  // Show a toast whenever new alerts arrive (works on every page)
  useAlertNotifier()

  // Show navigation if:
  // 1. User is currently authenticated, OR
  // 2. User was authenticated before (during page transitions/reloads)
  const shouldShowNav = isAuthenticated || (hasBeenAuthenticated && isLoading)

  // For initial load, render the layout shell with skeleton nav to prevent layout shift
  if (!isReady && !hasBeenAuthenticated) {
    return (
      <div className="min-h-[calc(100vh-56px)]">
        <header className="sticky top-0 z-40 border-b border-border/40 bg-background/80 backdrop-blur-lg supports-[backdrop-filter]:bg-background/60">
          <div className="container mx-auto px-4 sm:px-6">
            <div className="flex h-14 items-center justify-between gap-4">
              <div className="flex items-center gap-6">
                <h1 className="text-base sm:text-lg font-semibold tracking-tight whitespace-nowrap">SkinBaron Tracker</h1>
                <nav className="hidden md:flex items-center gap-1.5">
                  {Array.from({ length: 4 }).map((_, i) => (
                    <Skeleton key={i} className="h-7 w-20 rounded-md" />
                  ))}
                </nav>
              </div>
              <div className="flex items-center gap-1.5 sm:gap-2">
                <Skeleton className="h-8 w-8 rounded-md" />
                <Skeleton className="hidden sm:block h-4 w-20" />
                <Skeleton className="h-8 w-8 rounded-full" />
              </div>
            </div>
          </div>
        </header>
        <div className="container mx-auto px-4 sm:px-6 py-4 sm:py-6">
          {children}
        </div>
      </div>
    )
  }

  // If user is not authenticated and has never been, show children without nav
  if (!shouldShowNav) {
    return children
  }

  return (
    <div className="min-h-[calc(100vh-56px)]">
      {/* Top bar */}
      <header className="sticky top-0 z-40 border-b border-border/40 bg-background/80 backdrop-blur-lg supports-[backdrop-filter]:bg-background/60">
        <div className="container mx-auto px-4 sm:px-6">
          <div className="flex h-14 items-center justify-between gap-4">
            <div className="flex items-center gap-6">
              <h1 className="text-base sm:text-lg font-semibold tracking-tight whitespace-nowrap">SkinBaron Tracker</h1>
              <DashboardNav />
            </div>
            <div className="flex items-center gap-1.5 sm:gap-2">
              <ThemeToggle />
              <UserNav />
              <MobileNavTrigger />
            </div>
          </div>
        </div>
      </header>
      
      {/* Page content */}
      <div className="container mx-auto px-4 sm:px-6 py-4 sm:py-6">
        {children}
      </div>
    </div>
  )
}
