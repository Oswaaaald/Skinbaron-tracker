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
    <div className="flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
      <div className="space-y-2">
        {eyebrow ? (
          <p className="text-xs font-medium uppercase tracking-[0.1em] text-muted-foreground">{eyebrow}</p>
        ) : null}
        <div className="flex items-center gap-3">
          {Icon ? (
            <span className="inline-flex h-9 w-9 items-center justify-center rounded-lg border border-border/70 bg-card text-muted-foreground">
              <Icon className="h-4 w-4" />
            </span>
          ) : null}
          <h2 className="text-2xl font-semibold tracking-tight sm:text-[1.7rem]">{title}</h2>
        </div>
        <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground">{description}</p>
      </div>
      {actions ? <div className="w-full sm:w-auto">{actions}</div> : null}
    </div>
  )
}
