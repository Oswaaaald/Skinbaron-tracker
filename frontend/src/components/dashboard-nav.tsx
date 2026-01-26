"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { useAuth } from "@/contexts/auth-context"
import { cn } from "@/lib/utils"
import { 
  LayoutDashboard,
  ListFilter,
  Bell,
  Webhook,
  Settings,
  Shield,
  Activity,
  Menu
} from "lucide-react"
import { useState } from "react"
import { Sheet, SheetContent, SheetTrigger } from "@/components/ui/sheet"
import { Button } from "@/components/ui/button"

const navItems = [
  { href: "/", label: "Home", icon: LayoutDashboard },
  { href: "/rules", label: "Rules", icon: ListFilter },
  { href: "/alerts", label: "Alerts", icon: Bell },
  { href: "/webhooks", label: "Webhooks", icon: Webhook },
  { href: "/settings", label: "Settings", icon: Settings },
]

const adminNavItems = [
  { href: "/admin", label: "Admin", icon: Shield },
  { href: "/admin/system", label: "System", icon: Activity },
]

export function DashboardNav() {
  const pathname = usePathname()
  const { user } = useAuth()
  
  const isActive = (href: string) => {
    if (href === "/") return pathname === "/"
    if (href === "/admin") return pathname === "/admin"
    return pathname.startsWith(href)
  }

  const NavLinks = () => (
    <>
      {navItems.map((item) => {
        const Icon = item.icon
        return (
          <Link
            key={item.href}
            href={item.href}
            className={cn(
              "flex items-center gap-2 px-3 py-2 text-sm font-medium rounded-md transition-colors",
              isActive(item.href)
                ? "bg-primary text-primary-foreground"
                : "text-muted-foreground hover:bg-muted hover:text-foreground"
            )}
          >
            <Icon className="h-4 w-4" />
            {item.label}
          </Link>
        )
      })}
      
      {user?.is_admin && (
        <>
          <div className="w-px h-6 bg-border mx-2" />
          {adminNavItems.map((item) => {
            const Icon = item.icon
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "flex items-center gap-2 px-3 py-2 text-sm font-medium rounded-md transition-colors",
                  isActive(item.href)
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:bg-muted hover:text-foreground"
                )}
              >
                <Icon className="h-4 w-4" />
                {item.label}
              </Link>
            )
          })}
        </>
      )}
    </>
  )

  return (
    <>
      {/* Desktop Navigation */}
      <nav className="hidden md:flex items-center gap-1">
        <NavLinks />
      </nav>
    </>
  )
}

export function MobileNavTrigger() {
  const pathname = usePathname()
  const { user } = useAuth()
  const [open, setOpen] = useState(false)
  
  const isActive = (href: string) => {
    if (href === "/") return pathname === "/"
    if (href === "/admin") return pathname === "/admin"
    return pathname.startsWith(href)
  }

  const NavLinks = ({ mobile = false }: { mobile?: boolean }) => (
    <>
      {navItems.map((item) => {
        const Icon = item.icon
        return (
          <Link
            key={item.href}
            href={item.href}
            onClick={() => mobile && setOpen(false)}
            className={cn(
              "flex items-center gap-2 px-3 py-2 text-sm font-medium rounded-md transition-colors",
              isActive(item.href)
                ? "bg-primary text-primary-foreground"
                : "text-muted-foreground hover:bg-muted hover:text-foreground",
              mobile && "w-full"
            )}
          >
            <Icon className="h-4 w-4" />
            {item.label}
          </Link>
        )
      })}
      
      {user?.is_admin && (
        <>
          <div className={cn("bg-border", mobile ? "h-px w-full my-2" : "w-px h-6 mx-2")} />
          {adminNavItems.map((item) => {
            const Icon = item.icon
            return (
              <Link
                key={item.href}
                href={item.href}
                onClick={() => mobile && setOpen(false)}
                className={cn(
                  "flex items-center gap-2 px-3 py-2 text-sm font-medium rounded-md transition-colors",
                  isActive(item.href)
                    ? "bg-primary text-primary-foreground"
                    : "text-muted-foreground hover:bg-muted hover:text-foreground",
                  mobile && "w-full"
                )}
              >
                <Icon className="h-4 w-4" />
                {item.label}
              </Link>
            )
          })}
        </>
      )}
    </>
  )

  return (
    <div className="md:hidden">
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetTrigger asChild>
          <Button variant="outline" size="icon">
            <Menu className="h-5 w-5" />
          </Button>
        </SheetTrigger>
        <SheetContent side="right" className="w-64">
          <nav className="flex flex-col gap-1 mt-8">
            <NavLinks mobile />
          </nav>
        </SheetContent>
      </Sheet>
    </div>
  )
}
