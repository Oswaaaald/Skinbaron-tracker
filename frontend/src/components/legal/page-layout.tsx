import type { ReactNode } from 'react'
import Link from 'next/link'
import { ArrowLeft } from 'lucide-react'
import { Button } from '@/components/ui/button'

interface LegalPageLayoutProps {
  title: string
  subtitle: string
  updatedAt: string
  children: ReactNode
}

export function LegalPageLayout({ title, subtitle, updatedAt, children }: LegalPageLayoutProps) {
  return (
    <div className="mx-auto w-full max-w-5xl px-4 py-10 sm:px-6 sm:py-12">
      <div className="mb-7 flex items-center justify-between gap-3">
        <Button variant="outline" size="sm" asChild>
          <Link href="/">
            <ArrowLeft className="h-4 w-4" />
            Back
          </Link>
        </Button>
        <p className="text-xs text-muted-foreground">Last updated: {updatedAt}</p>
      </div>

      <div className="mb-8 space-y-3 rounded-2xl border border-border/70 bg-card/90 p-6 sm:p-8">
        <h1 className="text-3xl font-semibold tracking-tight sm:text-4xl">{title}</h1>
        <p className="text-sm leading-relaxed text-muted-foreground sm:text-base">{subtitle}</p>
      </div>

      <div className="space-y-4">{children}</div>
    </div>
  )
}

export function LegalSection({ title, children }: { title: string; children: ReactNode }) {
  return (
    <section className="space-y-2 rounded-xl border border-border/70 bg-card/90 p-5 sm:p-6">
      <h2 className="text-xl font-semibold tracking-tight">{title}</h2>
      <div className="space-y-2 text-sm leading-relaxed text-muted-foreground sm:text-[15px]">{children}</div>
    </section>
  )
}
