'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { Github } from 'lucide-react'

const HIDDEN_FOOTER_ROUTES = new Set(['/login', '/register'])

export function AppFooter() {
  const pathname = usePathname()

  if (HIDDEN_FOOTER_ROUTES.has(pathname)) {
    return null
  }

  return (
    <footer className="border-t border-border/65 bg-background/70 backdrop-blur">
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-3 px-4 py-4 text-[13px] text-muted-foreground sm:flex-row sm:items-center sm:justify-between sm:px-6">
        <span>© 2026 SkinBaron Tracker</span>
        <div className="flex items-center gap-5">
          <Link className="hover:text-foreground transition-colors" href="/tos">Terms</Link>
          <Link className="hover:text-foreground transition-colors" href="/privacy">Privacy</Link>
          <a
            href="https://github.com/Oswaaaald"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-foreground transition-colors flex items-center gap-1.5"
          >
            <Github className="h-3.5 w-3.5" />
            GitHub
          </a>
        </div>
      </div>
    </footer>
  )
}
