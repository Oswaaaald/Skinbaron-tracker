'use client'

import { useCallback, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Plus } from 'lucide-react'
import { apiClient, type Rule } from '@/lib/api'
import { QUERY_KEYS } from '@/lib/constants'
import { extractErrorMessage } from '@/lib/utils'
import { useAuth } from '@/contexts/auth-context'
import { useSyncStats } from '@/hooks/use-sync-stats'
import { useToast } from '@/hooks/use-toast'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { RulesTableSkeleton } from '@/components/ui/skeletons'
import { RulesTableBatchActions } from '@/components/rules-table-batch-actions'
import { RulesTableTable } from '@/components/rules-table-table'
import { RulesTableDialogs } from '@/components/rules-table-dialogs'
import { useRulesTableMutations } from '@/components/rules-table-mutations'

export function RulesTable({ onCreateRule }: { onCreateRule?: () => void }) {
  const [editingRule, setEditingRule] = useState<Rule | null>(null)
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false)
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false)
  const [ruleToDelete, setRuleToDelete] = useState<Rule | null>(null)
  const [deleteDialogName, setDeleteDialogName] = useState('')
  const [selectedRules, setSelectedRules] = useState<Set<number>>(new Set())
  const [batchAction, setBatchAction] = useState<'enable' | 'disable' | 'delete' | null>(null)
  const [batchDeleteSize, setBatchDeleteSize] = useState(0)

  const { isReady, isAuthenticated } = useAuth()
  const { syncStats } = useSyncStats()
  const { toast } = useToast()

  const { data: rulesResponse, isLoading, error } = useQuery({
    queryKey: [QUERY_KEYS.RULES],
    queryFn: async () => apiClient.ensureSuccess(await apiClient.getRules(), 'Failed to load rules'),
    enabled: isReady && isAuthenticated,
  })

  const { data: webhooksResponse } = useQuery({
    queryKey: [QUERY_KEYS.WEBHOOKS],
    queryFn: async () => {
      const result = await apiClient.getWebhooks(false)
      if (!result.success) throw new Error(result.error)
      return result.data || []
    },
    enabled: isReady && isAuthenticated,
  })

  const rules = rulesResponse?.data ?? []
  const webhooks = useMemo(() => webhooksResponse || [], [webhooksResponse])

  const getWebhookDisplay = useCallback((rule: Rule) => {
    if (rule.webhook_ids && rule.webhook_ids.length > 0 && webhooks) {
      const webhookNames = rule.webhook_ids
        .map((id) => {
          const webhook = webhooks.find((w) => w.id === id)
          return webhook?.name
        })
        .filter(Boolean)

      if (webhookNames.length > 0) {
        return (
          <div className="flex gap-1 flex-wrap">
            {webhookNames.map((name, index) => (
              <Badge key={`${name}-${index}`} variant="outline" className="text-xs">
                {name}
              </Badge>
            ))}
          </div>
        )
      }
    }

    return (
      <Badge variant="secondary" className="text-xs">
        No webhook
      </Badge>
    )
  }, [webhooks])

  const {
    toggleRuleMutation,
    deleteRuleMutation,
    batchEnableMutation,
    batchDisableMutation,
    batchDeleteMutation,
  } = useRulesTableMutations({ syncStats, toast, setSelectedRules })

  const handleEdit = (rule: Rule) => {
    setEditingRule(rule)
    setIsEditDialogOpen(true)
  }

  const handleToggleEnabled = (rule: Rule) => {
    if (rule.id) {
      toggleRuleMutation.mutate({ rule, enabled: !rule.enabled })
    }
  }

  const handleDelete = (rule: Rule) => {
    setRuleToDelete(rule)
    setDeleteDialogName(rule.search_item)
    setDeleteConfirmOpen(true)
  }

  const confirmDelete = useCallback(() => {
    if (ruleToDelete?.id) {
      deleteRuleMutation.mutate(ruleToDelete.id)
    }
    setRuleToDelete(null)
  }, [ruleToDelete, deleteRuleMutation])

  const handleSelectAll = () => {
    if (selectedRules.size === rules.length) {
      setSelectedRules(new Set())
      return
    }
    setSelectedRules(new Set(rules.map((rule) => rule.id).filter((id): id is number => id != null)))
  }

  const handleSelectRule = (ruleId: number) => {
    const newSelection = new Set(selectedRules)
    if (newSelection.has(ruleId)) {
      newSelection.delete(ruleId)
    } else {
      newSelection.add(ruleId)
    }
    setSelectedRules(newSelection)
  }

  const handleBatchEnable = () => {
    const ruleIds = selectedRules.size > 0 ? Array.from(selectedRules) : undefined
    batchEnableMutation.mutate(ruleIds)
  }

  const handleBatchDisable = () => {
    const ruleIds = selectedRules.size > 0 ? Array.from(selectedRules) : undefined
    batchDisableMutation.mutate(ruleIds)
  }

  const handleBatchDelete = () => {
    setBatchDeleteSize(selectedRules.size)
    setBatchAction('delete')
  }

  const confirmBatchDelete = useCallback(() => {
    const ruleIds = selectedRules.size > 0 ? Array.from(selectedRules) : undefined
    const confirmAll = selectedRules.size === 0
    batchDeleteMutation.mutate({ ruleIds, confirmAll })
    setBatchAction(null)
  }, [selectedRules, batchDeleteMutation])

  if (isLoading) {
    return <RulesTableSkeleton />
  }

  if (error) {
    return (
      <Card>
        <CardContent className="pt-6">
          <div className="text-center text-destructive text-sm" role="alert">
            Error loading rules: {extractErrorMessage(error)}
          </div>
        </CardContent>
      </Card>
    )
  }

  if (rules.length === 0) {
    return (
      <Card className="border-dashed">
        <CardHeader className="items-center text-center py-10">
          <CardTitle className="text-base">No Rules Found</CardTitle>
          <CardDescription>
            Create your first rule to start monitoring SkinBaron for CS2 skins.
          </CardDescription>
          {onCreateRule && (
            <Button onClick={onCreateRule} className="mt-4">
              <Plus className="h-4 w-4 mr-2" />
              Create Rule
            </Button>
          )}
        </CardHeader>
      </Card>
    )
  }

  return (
    <>
      <Card>
        <CardHeader className="pb-3">
          <RulesTableBatchActions
            selectedCount={selectedRules.size}
            totalCount={rules.length}
            enablePending={batchEnableMutation.isPending}
            disablePending={batchDisableMutation.isPending}
            deletePending={batchDeleteMutation.isPending}
            onEnable={handleBatchEnable}
            onDisable={handleBatchDisable}
            onDelete={handleBatchDelete}
          />
        </CardHeader>
        <CardContent className="p-0 overflow-x-auto">
          <RulesTableTable
            rules={rules}
            selectedRules={selectedRules}
            onSelectAll={handleSelectAll}
            onSelectRule={handleSelectRule}
            onEdit={handleEdit}
            onToggleEnabled={handleToggleEnabled}
            onDelete={handleDelete}
            renderWebhookDisplay={getWebhookDisplay}
          />
        </CardContent>
      </Card>

      <RulesTableDialogs
        editingRule={editingRule}
        isEditDialogOpen={isEditDialogOpen}
        onEditDialogChange={setIsEditDialogOpen}
        clearEditingRule={() => setEditingRule(null)}
        deleteConfirmOpen={deleteConfirmOpen}
        onDeleteConfirmOpenChange={setDeleteConfirmOpen}
        deleteDialogName={deleteDialogName}
        onConfirmDelete={confirmDelete}
        batchDeleteOpen={batchAction === 'delete'}
        onBatchDeleteOpenChange={(open) => !open && setBatchAction(null)}
        batchDeleteSize={batchDeleteSize}
        totalRules={rules.length}
        onConfirmBatchDelete={confirmBatchDelete}
      />
    </>
  )
}
