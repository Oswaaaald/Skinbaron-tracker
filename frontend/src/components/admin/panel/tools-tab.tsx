'use client'

import { Bug, Shield } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'

interface AdminPanelToolsTabProps {
  sentryEnabled?: boolean
  forceSchedulerPending: boolean
  testSentryPending: boolean
  onForceScheduler: () => void
  onOpenSentryConfirm: () => void
}

export function AdminPanelToolsTab({
  sentryEnabled,
  forceSchedulerPending,
  testSentryPending,
  onForceScheduler,
  onOpenSentryConfirm,
}: AdminPanelToolsTabProps) {
  return (
    <div className="space-y-4">
      <Card className="border-purple-500 border-2">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-purple-500" />
            Super Admin Actions
          </CardTitle>
          <CardDescription>Advanced system controls</CardDescription>
        </CardHeader>
        <CardContent className="mt-2">
          <Button onClick={onForceScheduler} disabled={forceSchedulerPending} variant="outline">
            {forceSchedulerPending ? 'Running...' : 'Force Scheduler Run'}
          </Button>
          <p className="text-sm text-muted-foreground mt-2">
            Bypass the cron schedule and run the scheduler immediately
          </p>
        </CardContent>
      </Card>

      {sentryEnabled && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Bug className="h-5 w-5 text-orange-500" />
              Test Sentry
            </CardTitle>
            <CardDescription>Verify that Sentry error tracking is working</CardDescription>
          </CardHeader>
          <CardContent className="mt-2">
            <Button onClick={onOpenSentryConfirm} disabled={testSentryPending} variant="outline">
              {testSentryPending ? 'Sending...' : 'Send Test Error'}
            </Button>
            <p className="text-sm text-muted-foreground mt-2">
              Sends a fake error to Sentry — check your dashboard to confirm it arrives
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
