"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { useAuth } from "@/contexts/auth-context"
import { cn } from "@/lib/utils"
import { 
  ListFilter,
  Bell,
  Webhook,
  Settings,
  Shield,
  Menu
} from "lucide-react"
import { useState } from "react"
import { Sheet, SheetContent, SheetTrigger, SheetTitle, SheetDescription } from "@/components/ui/sheet"
import { Button } from "@/components/ui/button"

const navItems = [
  { href: "/", label: "Alerts", icon: Bell },
  { href: "/rules", label: "Rules", icon: ListFilter },
  { href: "/webhooks", label: "Webhooks", icon: Webhook },
  { href: "/settings", label: "Settings", icon: Settings },
]

const adminNavItems = [
  { href: "/admin", label: "Admin", icon: Shield },
]

function useIsActive() {
  const pathname = usePathname()
  return (href: string) => {
    if (href === "/") return pathname === "/"
    if (href === "/admin") return pathname === "/admin"
    return pathname.startsWith(href)
  }
}

/** Shared navigation links rendered for both desktop and mobile layouts. */
function NavLinks({ mobile = false, onNavigate }: { mobile?: boolean; onNavigate?: () => void }) {
  const { user } = useAuth()
  const isActive = useIsActive()

  const linkCls = (active: boolean) =>
    cn(
      "flex items-center text-sm font-medium rounded-md transition-all duration-150",
      mobile ? "gap-2.5 px-3 py-2.5 rounded-lg" : "gap-1.5 px-3 py-1.5",
      active
        ? "bg-primary text-primary-foreground shadow-sm"
        : "text-muted-foreground hover:text-foreground hover:bg-accent",
      mobile && "w-full",
    )

  const iconCls = mobile ? "h-4 w-4" : "h-3.5 w-3.5"

  return (
    <>
      {navItems.map((item) => {
        const Icon = item.icon
        return (
          <Link key={item.href} href={item.href} onClick={onNavigate} className={linkCls(isActive(item.href))}>
            <Icon className={iconCls} />
            {item.label}
          </Link>
        )
      })}

      {user?.is_admin && (
        <>
          <div className={cn("bg-border", mobile ? "h-px w-full my-2" : "w-px h-5 mx-1")} />
          {adminNavItems.map((item) => {
            const Icon = item.icon
            return (
              <Link key={item.href} href={item.href} onClick={onNavigate} className={linkCls(isActive(item.href))}>
                <Icon className={iconCls} />
                {item.label}
              </Link>
            )
          })}
        </>
      )}
    </>
  )
}

export function DashboardNav() {
  return (
    <nav className="hidden md:flex items-center gap-0.5">
      <NavLinks />
    </nav>
  )
}

export function MobileNavTrigger() {
  const [open, setOpen] = useState(false)

  return (
    <div className="md:hidden">
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetTrigger asChild>
          <Button variant="outline" size="icon" aria-label="Open navigation menu">
            <Menu className="h-5 w-5" />
          </Button>
        </SheetTrigger>
        <SheetContent side="right" className="w-64">
          <SheetTitle className="sr-only">Navigation Menu</SheetTitle>
          <SheetDescription className="sr-only">Navigate through the application</SheetDescription>
          <nav className="flex flex-col gap-1 mt-8">
            <NavLinks mobile onNavigate={() => setOpen(false)} />
          </nav>
        </SheetContent>
      </Sheet>
    </div>
  )
}
