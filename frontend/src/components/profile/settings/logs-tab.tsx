'use client'

import { Download } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { SecurityHistory } from '@/components/profile/security-history'

export function LogsTab({ onOpenExport }: { onOpenExport: () => void }) {
  return (
    <div className="space-y-4">
      <SecurityHistory />

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Download className="h-5 w-5" /> Export My Data
          </CardTitle>
          <CardDescription>
            Download all your personal data (GDPR Art. 20 — Right to data portability)
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm text-muted-foreground">
            Export all your data (profile, rules, webhooks, alerts, audit logs) as a JSON file.
          </p>
          <Button variant="outline" onClick={onOpenExport}>
            <Download className="h-4 w-4 mr-2" /> Export My Data
          </Button>
        </CardContent>
      </Card>
    </div>
  )
}
