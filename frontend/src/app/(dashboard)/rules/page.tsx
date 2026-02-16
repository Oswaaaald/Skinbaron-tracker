"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { RulesTable } from "@/components/rules-table"
import { RuleDialog } from "@/components/rule-dialog"
import { useAuth } from "@/contexts/auth-context"
import { LoadingState } from "@/components/ui/loading-state"

export default function RulesPage() {
  const [isRuleDialogOpen, setIsRuleDialogOpen] = useState(false)
  const { isReady } = useAuth()

  if (!isReady) {
    return <LoadingState variant="page" />
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Alert Rules</h2>
          <p className="text-sm text-muted-foreground mt-1">
            Manage your custom skin monitoring rules
          </p>
        </div>
        <Button onClick={() => setIsRuleDialogOpen(true)} className="w-full sm:w-auto">
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
