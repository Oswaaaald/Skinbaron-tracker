"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { RulesTable } from "@/components/rules/table"
import { RuleDialog } from "@/components/rules/dialog"
import { useAuth } from "@/contexts/auth-context"
import { RulesTableSkeleton } from "@/components/ui/skeletons"
import { PageHeader } from "@/components/page-header"
import { SlidersHorizontal } from "lucide-react"

export default function RulesPage() {
  const [isRuleDialogOpen, setIsRuleDialogOpen] = useState(false)
  const { isReady } = useAuth()

  if (!isReady) {
    return <RulesTableSkeleton />
  }

  return (
    <div className="space-y-6 md:space-y-7">
      <PageHeader
        icon={SlidersHorizontal}
        eyebrow="Dashboard"
        title="Alert Rules"
        description="Define, edit, and batch-manage the rule set that powers your monitoring strategy."
        actions={
          <Button onClick={() => setIsRuleDialogOpen(true)} className="w-full sm:w-auto">
            Create Rule
          </Button>
        }
      />
      <RulesTable onCreateRule={() => setIsRuleDialogOpen(true)} />
      
      <RuleDialog
        open={isRuleDialogOpen}
        onOpenChange={setIsRuleDialogOpen}
      />
    </div>
  )
}
