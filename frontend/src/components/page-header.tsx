import type { ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'

interface PageHeaderProps {
  title: string
  description: string
  actions?: ReactNode
  icon?: LucideIcon
  eyebrow?: string
}

export function PageHeader({ title, description, actions, icon: Icon, eyebrow }: PageHeaderProps) {
  return (
    <header className="rounded-2xl border border-border/70 bg-card/92 px-4 py-4 shadow-[0_1px_2px_rgba(15,23,42,0.06)] sm:px-5 sm:py-5">
      <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
        <div className="space-y-2.5">
          {eyebrow ? (
            <p className="text-xs font-medium uppercase tracking-[0.11em] text-muted-foreground">{eyebrow}</p>
          ) : null}
          <div className="flex items-start gap-3">
            {Icon ? (
              <span className="mt-0.5 inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border border-border/70 bg-background/85 text-muted-foreground">
                <Icon className="h-4 w-4" />
              </span>
            ) : null}
            <div className="space-y-1.5">
              <h2 className="text-2xl font-semibold tracking-tight sm:text-[1.72rem]">{title}</h2>
              <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground sm:text-[15px]">{description}</p>
            </div>
          </div>
        </div>
        {actions ? <div className="w-full sm:w-auto">{actions}</div> : null}
      </div>
    </header>
  )
}
