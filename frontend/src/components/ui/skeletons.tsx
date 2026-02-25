import { Card, CardContent, CardHeader } from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"
import { Skeleton } from "@/components/ui/skeleton"

/** Skeleton for a table with header and N rows. */
export function TableSkeleton({ rows = 5, columns = 4 }: { rows?: number; columns?: number }) {
  return (
    <div className="space-y-3">
      {/* Header row */}
      <div className="flex gap-4 px-4 py-2">
        {Array.from({ length: columns }).map((_, i) => (
          <Skeleton key={i} className="h-4 flex-1" />
        ))}
      </div>
      {/* Data rows */}
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex gap-4 px-4 py-3 border-t">
          {Array.from({ length: columns }).map((_, j) => (
            <Skeleton key={j} className="h-4 flex-1" />
          ))}
        </div>
      ))}
    </div>
  )
}

/** Skeleton for the rules table page. */
export function RulesTableSkeleton() {
  return (
    <Card>
      <CardContent className="pt-4">
        <TableSkeleton rows={5} columns={5} />
      </CardContent>
    </Card>
  )
}

/** Skeleton for the webhooks table page. */
export function WebhooksTableSkeleton() {
  return (
    <Card>
      <CardContent className="pt-4">
        <TableSkeleton rows={4} columns={4} />
      </CardContent>
    </Card>
  )
}

/** Skeleton for the alerts page — approximates the filter bar + card grid to avoid CLS. */
export function AlertsGridSkeleton() {
  return (
    <div className="space-y-4">
      {/* Filter bar skeleton */}
      <Card>
        <CardContent className="p-4">
          <Skeleton className="h-3 w-20 mb-3" />
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-8 gap-3">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="space-y-1.5">
                <Skeleton className="h-3 w-12" />
                <Skeleton className="h-9 w-full rounded-md" />
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
      {/* Card grid skeleton */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {Array.from({ length: 8 }).map((_, i) => (
          <Card key={i} className="overflow-hidden p-0">
            <Skeleton className="aspect-[4/3] w-full rounded-none" />
            <div className="px-3 pb-3 pt-2.5 space-y-2">
              <Skeleton className="h-4 w-3/4" />
              <Skeleton className="h-9 w-full rounded-md" />
            </div>
          </Card>
        ))}
      </div>
    </div>
  )
}

/** Skeleton for the profile settings page (card with tabs). */
export function ProfileSkeleton() {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-3">
          <Skeleton className="h-12 w-12 rounded-full" />
          <div className="space-y-2">
            <Skeleton className="h-5 w-40" />
            <Skeleton className="h-4 w-56" />
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Tab bar */}
        <div className="flex gap-2">
          {Array.from({ length: 4 }).map((_, i) => (
            <Skeleton key={i} className="h-8 w-24 rounded-md" />
          ))}
        </div>
        {/* Form fields */}
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="space-y-2">
            <Skeleton className="h-4 w-24" />
            <Skeleton className="h-9 w-full" />
          </div>
        ))}
        <Skeleton className="h-9 w-32" />
      </CardContent>
    </Card>
  )
}

/** Skeleton for the admin panel dashboard. */
export function AdminPanelSkeleton() {
  return (
    <div className="space-y-6">
      {/* Stats cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {Array.from({ length: 4 }).map((_, i) => (
          <Card key={i}>
            <CardContent className="pt-4 space-y-2">
              <Skeleton className="h-4 w-20" />
              <Skeleton className="h-8 w-16" />
            </CardContent>
          </Card>
        ))}
      </div>
      {/* Tab bar */}
      <div className="flex gap-2">
        {Array.from({ length: 3 }).map((_, i) => (
          <Skeleton key={i} className="h-8 w-28 rounded-md" />
        ))}
      </div>
      {/* Table */}
      <Card>
        <CardContent className="pt-4">
          <TableSkeleton rows={6} columns={5} />
        </CardContent>
      </Card>
    </div>
  )
}

/** Skeleton for log list views (audit logs, action logs, security history). */
export function LogListSkeleton({ withFilters = false, rows = 6 }: { withFilters?: boolean; rows?: number }) {
  return (
    <div className="space-y-3">
      {withFilters && (
        <div className="flex gap-3 flex-wrap">
          <Skeleton className="h-9 w-64" />
          <Skeleton className="h-9 w-32" />
          <Skeleton className="h-9 w-28" />
        </div>
      )}
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-start gap-3 py-3 border-b last:border-b-0">
          <Skeleton className="h-8 w-8 rounded-full shrink-0 mt-0.5" />
          <div className="flex-1 space-y-2">
            <div className="flex items-center gap-2">
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-5 w-16 rounded-full" />
            </div>
            <Skeleton className="h-3 w-3/4" />
            <Skeleton className="h-3 w-32" />
          </div>
        </div>
      ))}
    </div>
  )
}

/** Skeleton for the system stats page (2-column card grid). */
export function SystemStatsSkeleton() {
  return (
    <div className="grid gap-6 md:grid-cols-2">
      {/* System Health card */}
      <Card>
        <CardHeader>
          <Skeleton className="h-5 w-32" />
          <Skeleton className="h-4 w-56" />
        </CardHeader>
        <CardContent className="space-y-4">
          {Array.from({ length: 3 }).map((_, i) => (
            <div key={i} className="flex items-center justify-between">
              <Skeleton className="h-4 w-20" />
              <Skeleton className="h-5 w-16 rounded-full" />
            </div>
          ))}
          <Separator />
          <Skeleton className="h-4 w-28" />
          <div className="space-y-2">
            {Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="flex items-center justify-between">
                <Skeleton className="h-4 w-24" />
                <Skeleton className="h-5 w-14 rounded-full" />
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
      {/* Alert Monitoring card */}
      <Card>
        <CardHeader>
          <Skeleton className="h-5 w-36" />
          <Skeleton className="h-4 w-64" />
        </CardHeader>
        <CardContent className="space-y-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="flex items-center justify-between">
              <Skeleton className="h-4 w-28" />
              <Skeleton className="h-4 w-16" />
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  )
}

/** Skeleton for the passkeys list. */
export function PasskeyListSkeleton({ rows = 3 }: { rows?: number }) {
  return (
    <div className="space-y-2">
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center justify-between rounded-lg border p-3">
          <div className="flex items-center gap-3">
            <Skeleton className="h-9 w-9 rounded-md" />
            <div className="space-y-1.5">
              <div className="flex items-center gap-2">
                <Skeleton className="h-4 w-28" />
                <Skeleton className="h-5 w-14 rounded-full" />
              </div>
              <Skeleton className="h-3 w-40" />
            </div>
          </div>
          <div className="flex gap-1">
            <Skeleton className="h-8 w-8 rounded-md" />
            <Skeleton className="h-8 w-8 rounded-md" />
          </div>
        </div>
      ))}
    </div>
  )
}

/** Skeleton for the admin user detail dialog content. */
export function UserDetailSkeleton() {
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {/* Identity card */}
      <Card>
        <CardHeader className="pb-3">
          <Skeleton className="h-4 w-20" />
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-center gap-4">
            <Skeleton className="h-16 w-16 rounded-full" />
            <div className="space-y-2">
              <Skeleton className="h-5 w-32" />
              <Skeleton className="h-4 w-44" />
            </div>
          </div>
          <Separator />
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="flex items-center justify-between">
              <Skeleton className="h-4 w-20" />
              <Skeleton className="h-4 w-28" />
            </div>
          ))}
        </CardContent>
      </Card>
      {/* Security card */}
      <Card>
        <CardHeader className="pb-3">
          <Skeleton className="h-4 w-20" />
        </CardHeader>
        <CardContent className="space-y-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="flex items-center justify-between">
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-5 w-16 rounded-full" />
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  )
}

/** Skeleton for the linked OAuth accounts card. */
export function LinkedAccountsSkeleton({ rows = 3 }: { rows?: number }) {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <Skeleton className="h-5 w-5 rounded" />
          <Skeleton className="h-5 w-32" />
        </div>
        <Skeleton className="h-4 w-56" />
      </CardHeader>
      <CardContent className="mt-2 space-y-2">
        {Array.from({ length: rows }).map((_, i) => (
          <div key={i} className="flex items-center justify-between rounded-lg border p-3">
            <div className="flex items-center gap-3">
              <Skeleton className="h-9 w-9 rounded-md" />
              <div className="space-y-1.5">
                <Skeleton className="h-4 w-20" />
                <Skeleton className="h-3 w-32" />
              </div>
            </div>
            <Skeleton className="h-8 w-16 rounded-md" />
          </div>
        ))}
      </CardContent>
    </Card>
  )
}

/** Skeleton for the login / register auth form. */
export function AuthFormSkeleton() {
  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-background p-4" style={{ minHeight: '100vh', paddingTop: '4rem', paddingBottom: '4rem' }}>
      <Card className="w-full max-w-md border-border/50 shadow-lg">
        <CardHeader className="space-y-1.5 text-center pb-2">
          <Skeleton className="h-7 w-40 mx-auto" />
          <Skeleton className="h-4 w-64 mx-auto" />
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Email field */}
          <div className="space-y-2">
            <Skeleton className="h-4 w-12" />
            <Skeleton className="h-10 w-full rounded-md" />
          </div>
          {/* Password field */}
          <div className="space-y-2">
            <Skeleton className="h-4 w-16" />
            <Skeleton className="h-10 w-full rounded-md" />
          </div>
          {/* Submit button */}
          <Skeleton className="h-10 w-full rounded-md" />
          {/* Divider */}
          <div className="flex items-center gap-3 py-1">
            <Separator className="flex-1" />
            <Skeleton className="h-3 w-20" />
            <Separator className="flex-1" />
          </div>
          {/* OAuth buttons */}
          <div className="flex flex-col gap-2">
            <Skeleton className="h-10 w-full rounded-md" />
            <Skeleton className="h-10 w-full rounded-md" />
          </div>
          {/* Toggle mode link */}
          <div className="flex justify-center pt-2">
            <Skeleton className="h-4 w-48" />
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
