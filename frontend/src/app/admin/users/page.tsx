"use client"

import Link from "next/link"
import { Button } from "@/components/ui/button"
import { ArrowLeft } from "lucide-react"

export default function AdminUsersPage() {
  return (
    <div className="container mx-auto p-4 space-y-4">
      <div className="flex items-center gap-4">
        <Link href="/admin">
          <Button variant="outline" size="icon">
            <ArrowLeft className="h-4 w-4" />
          </Button>
        </Link>
        <div>
          <h2 className="text-2xl font-bold tracking-tight">User Management</h2>
          <p className="text-muted-foreground">
            View and manage user accounts
          </p>
        </div>
      </div>
      <p className="text-muted-foreground">Users management is available in the Admin Panel</p>
      <Link href="/admin">
        <Button>Go to Admin Panel</Button>
      </Link>
    </div>
  )
}
