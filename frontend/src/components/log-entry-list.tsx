"use client"

import { useState, memo, useCallback, type ReactNode } from "react"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { ScrollArea } from "@/components/ui/scroll-area"
import { ChevronDown, ChevronUp } from "lucide-react"
import { formatRelativeDate } from "@/lib/formatters"
import type { LucideIcon } from "lucide-react"

/** Manages a set of expanded row IDs for log entry lists. */
export function useExpandableRows() {
  const [expandedIds, setExpandedIds] = useState<Set<number>>(new Set())

  const toggle = useCallback((id: number) => {
    setExpandedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  return { expandedIds, toggle } as const
}

// ---------------------------------------------------------------------------
// LogEntryRow
// ---------------------------------------------------------------------------

interface LogEntryRowProps {
  icon: LucideIcon
  badgeLabel: string
  badgeVariant: "default" | "secondary" | "destructive" | "outline"
  date: string
  /** IP address shown in expandable details. */
  ipAddress?: string | null
  /** User-agent shown in expandable details. */
  userAgent?: string | null
  expanded?: boolean
  onToggleExpand?: () => void
  /** When true the bottom separator is hidden (last item). */
  isLast: boolean
  /** Custom badges / detail nodes inserted after the event badge. */
  children?: ReactNode
  /** Extra content rendered below the badge row (e.g. details paragraph). */
  belowContent?: ReactNode
}

export const LogEntryRow = memo(function LogEntryRow({
  icon: Icon,
  badgeLabel,
  badgeVariant,
  date,
  ipAddress,
  userAgent,
  expanded = false,
  onToggleExpand,
  isLast,
  children,
  belowContent,
}: LogEntryRowProps) {
  const expandable = !!(ipAddress || userAgent)

  return (
    <div>
      <div
        className={`flex items-start gap-4 ${expandable ? "cursor-pointer hover:bg-muted/50 -mx-2 px-2 py-1 rounded-md transition-colors" : ""}`}
        onClick={expandable ? onToggleExpand : undefined}
      >
        <div className="mt-0.5">
          <Icon className="h-4 w-4 text-muted-foreground" />
        </div>
        <div className="flex-1 space-y-1">
          <div className="flex items-center gap-2 flex-wrap">
            <Badge variant={badgeVariant} className="font-medium">
              {badgeLabel}
            </Badge>
            {children}
            <span className="text-xs text-muted-foreground ml-auto">
              {formatRelativeDate(date, "fr")}
            </span>
            {expandable && (
              <div className="h-6 px-2 ml-2 flex items-center">
                {expanded ? (
                  <ChevronUp className="h-3 w-3" />
                ) : (
                  <ChevronDown className="h-3 w-3" />
                )}
              </div>
            )}
          </div>
          {expanded && expandable && (
            <div className="flex flex-col gap-1 pt-1 text-xs text-muted-foreground/60">
              {ipAddress && <span className="font-mono">IP: {ipAddress}</span>}
              {userAgent && (
                <span className="font-mono break-all">{userAgent}</span>
              )}
            </div>
          )}
          {belowContent}
        </div>
      </div>
      {!isLast && <Separator className="mt-4" />}
    </div>
  )
})

// ---------------------------------------------------------------------------
// LogScrollArea
// ---------------------------------------------------------------------------

interface LogScrollAreaProps {
  empty: boolean
  emptyMessage?: string
  children: ReactNode
}

/** Wraps log entries in a fixed-height scrollable area with an empty state. */
export function LogScrollArea({
  empty,
  emptyMessage = "No events found",
  children,
}: LogScrollAreaProps) {
  if (empty) {
    return (
      <p className="text-sm text-muted-foreground text-center py-8">
        {emptyMessage}
      </p>
    )
  }

  return (
    <ScrollArea className="h-[600px] pr-4">
      <div className="space-y-4">{children}</div>
    </ScrollArea>
  )
}
