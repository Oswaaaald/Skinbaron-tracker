"use client"

import { Suspense, lazy } from "react"
import { LoadingSpinner } from "@/components/ui/loading-spinner"
import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Activity } from "lucide-react"
import { usePathname } from "next/navigation"

const AdminPanel = lazy(() => import("@/components/admin-panel").then(m => ({ default: m.AdminPanel })))

export default function AdminPage() {
  const pathname = usePathname()
  
  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Admin Panel</h2>
          <p className="text-muted-foreground">
            Manage users and system settings
          </p>
        </div>
        <nav className="flex gap-2">
          <Link href="/admin">
            <Button 
              variant={pathname === '/admin' ? 'default' : 'outline'}
              size="sm"
            >
              Users
            </Button>
          </Link>
          <Link href="/admin/system">
            <Button 
              variant={pathname === '/admin/system' ? 'default' : 'outline'}
              size="sm"
            >
              <Activity className="mr-2 h-4 w-4" />
              System
            </Button>
          </Link>
        </nav>
      </div>
      <Suspense fallback={<LoadingSpinner />}>
        <AdminPanel />
      </Suspense>
    </div>
  )
}
