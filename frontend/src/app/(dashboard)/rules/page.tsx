"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { RulesTable } from "@/components/rules-table"
import { RuleDialog } from "@/components/rule-dialog"
import { useAuth } from "@/contexts/auth-context"
import { LoadingSpinner } from "@/components/ui/loading-spinner"

export default function RulesPage() {
  const [isRuleDialogOpen, setIsRuleDialogOpen] = useState(false)
  const { isReady } = useAuth()

  if (!isReady) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center">
        <LoadingSpinner size="lg" />
        <p className="text-muted-foreground mt-2">Loading...</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Alert Rules</h2>
          <p className="text-muted-foreground">
            Manage your custom skin monitoring rules
          </p>
        </div>
        <Button onClick={() => setIsRuleDialogOpen(true)}>
          Create Rule
        </Button>
      </div>
      <RulesTable />
      
      <RuleDialog
        open={isRuleDialogOpen}
        onOpenChange={setIsRuleDialogOpen}
      />
    </div>
  )
}
