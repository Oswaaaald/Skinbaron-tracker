"use client"

import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { Button } from "@/components/ui/button"
import { LoadingSpinner } from "@/components/ui/loading-spinner"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { MoreHorizontal, Edit, Trash2, Play, Pause } from "lucide-react"
import { apiClient, type Rule } from "@/lib/api"
import { RuleDialog } from "@/components/rule-dialog"
import { formatWearPercentage } from "@/lib/wear-utils"
import { useAuth } from "@/contexts/auth-context"
import { useSyncStats } from "@/hooks/use-sync-stats"
import { useApiMutation } from "@/hooks/use-api-mutation"
import { useToast } from "@/hooks/use-toast"
import { ConfirmDialog } from "@/components/ui/confirm-dialog"

export function RulesTable() {
  const [editingRule, setEditingRule] = useState<Rule | null>(null)
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false)
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false)
  const [ruleToDelete, setRuleToDelete] = useState<Rule | null>(null)
  const [selectedRules, setSelectedRules] = useState<Set<number>>(new Set())
  const [batchAction, setBatchAction] = useState<'enable' | 'disable' | 'delete' | null>(null)
  const { isReady, isAuthenticated } = useAuth()
  const { syncStats } = useSyncStats()
  const { toast } = useToast()

  const { data: rulesResponse, isLoading, error } = useQuery({
    queryKey: ['rules'],
    queryFn: async () => apiClient.ensureSuccess(await apiClient.getRules(), 'Failed to load rules'),
    enabled: isReady && isAuthenticated, // Wait for auth to be ready and user to be authenticated
  })

    // Fetch user's webhooks to display webhook names in rules table
  const { data: webhooksResponse } = useQuery({
    queryKey: ['webhooks'],
    queryFn: async () => {
      const result = await apiClient.getWebhooks(false) // Don't decrypt for listing
      if (!result.success) throw new Error(result.error)
      return result.data || []
    },
    enabled: isReady && isAuthenticated, // Wait for auth to be ready and user to be authenticated
  })

  // webhooksResponse is directly an array since queryFn returns result.data || []
  const webhooks = webhooksResponse || []

  // Helper function to get webhook display text
  const getWebhookDisplay = (rule: Rule) => {
    
    if (rule.webhook_ids && rule.webhook_ids.length > 0 && webhooks) {
      const webhookNames = rule.webhook_ids
        .map(id => {
          const webhook = webhooks.find(w => w.id === id)
          return webhook?.name
        })
        .filter(Boolean)
      
      if (webhookNames.length > 0) {
        return (
          <div className="flex gap-1 flex-wrap">
            {webhookNames.map((name, index) => (
              <Badge key={index} variant="outline" className="text-xs">
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
  }

  const toggleRuleMutation = useApiMutation(
    ({ rule, enabled }: { rule: Rule; enabled: boolean }) => {
      // Ensure rule.id exists
      if (!rule.id) {
        throw new Error('Rule ID is required');
      }
      
      // Note: webhook_ids can now be empty - rules without webhooks are allowed
      
      // Send complete rule data with updated enabled status, ensuring all fields are properly set
      const updateData = {
        search_item: rule.search_item,
        min_price: rule.min_price ?? undefined,
        max_price: rule.max_price ?? undefined,
        min_wear: rule.min_wear ?? undefined,
        max_wear: rule.max_wear ?? undefined,
        stattrak_filter: rule.stattrak_filter ?? 'all',
        souvenir_filter: rule.souvenir_filter ?? 'all',
        allow_stickers: rule.allow_stickers ?? true,
        webhook_ids: rule.webhook_ids,
        enabled: enabled,
      };
      return apiClient.updateRule(rule.id, updateData);
    },
    {
      invalidateKeys: [['rules'], ['admin', 'stats']],
      onSuccess: (_, { enabled }) => {
        toast({
          title: enabled ? "✅ Rule enabled" : "⚠️ Rule disabled",
          description: enabled 
            ? "Rule is now active and monitoring items" 
            : "Rule has been paused",
        })
        syncStats() // Sync stats immediately after rule change
      },
      onError: (error: unknown) => {
        const message =
          error instanceof Error
            ? error.message
            : typeof error === 'object' && error && 'error' in error && typeof (error as { error?: unknown }).error === 'string'
              ? (error as { error?: string }).error
              : 'An error occurred';
        toast({
          variant: "destructive",
          title: "❌ Failed to update rule",
          description: message,
        })
      },
    }
  )

  const deleteRuleMutation = useApiMutation(
    (id: number) => apiClient.deleteRule(id),
    {
      invalidateKeys: [['rules'], ['admin', 'stats']],
      onSuccess: () => {
        toast({
          title: "✅ Rule deleted",
          description: "The monitoring rule has been permanently deleted",
        })
        syncStats() // Sync stats immediately after rule deletion
      },
      onError: (error: unknown) => {
        const message =
          error instanceof Error
            ? error.message
            : typeof error === 'object' && error && 'error' in error && typeof (error as { error?: unknown }).error === 'string'
              ? (error as { error?: string }).error
              : 'An error occurred';
        toast({
          variant: "destructive",
          title: "❌ Failed to delete rule",
          description: message,
        })
      },
    }
  )

  const batchEnableMutation = useApiMutation(
    (ruleIds?: number[]) => apiClient.batchEnableRules(ruleIds),
    {
      invalidateKeys: [['rules'], ['admin', 'stats']],
      onSuccess: (data) => {
        toast({
          title: "✅ Rules enabled",
          description: `${data?.count || 0} rule(s) have been enabled`,
        })
        setSelectedRules(new Set())
        syncStats()
      },
      onError: (error: unknown) => {
        const message =
          error instanceof Error
            ? error.message
            : typeof error === 'object' && error && 'error' in error && typeof (error as { error?: unknown }).error === 'string'
              ? (error as { error?: string }).error
              : 'An error occurred';
        toast({
          variant: "destructive",
          title: "❌ Failed to enable rules",
          description: message,
        })
      },
    }
  )

  const batchDisableMutation = useApiMutation(
    (ruleIds?: number[]) => apiClient.batchDisableRules(ruleIds),
    {
      invalidateKeys: [['rules'], ['admin', 'stats']],
      onSuccess: (data) => {
        toast({
          title: "⚠️ Rules disabled",
          description: `${data?.count || 0} rule(s) have been disabled`,
        })
        setSelectedRules(new Set())
        syncStats()
      },
      onError: (error: unknown) => {
        const message =
          error instanceof Error
            ? error.message
            : typeof error === 'object' && error && 'error' in error && typeof (error as { error?: unknown }).error === 'string'
              ? (error as { error?: string }).error
              : 'An error occurred';
        toast({
          variant: "destructive",
          title: "❌ Failed to disable rules",
          description: message,
        })
      },
    }
  )

  const batchDeleteMutation = useApiMutation(
    ({ ruleIds, confirmAll }: { ruleIds?: number[]; confirmAll: boolean }) => 
      apiClient.batchDeleteRules(ruleIds, confirmAll),
    {
      invalidateKeys: [['rules'], ['admin', 'stats']],
      onSuccess: (data) => {
        toast({
          title: "✅ Rules deleted",
          description: `${data?.count || 0} rule(s) have been permanently deleted`,
        })
        setSelectedRules(new Set())
        syncStats()
      },
      onError: (error: unknown) => {
        const message =
          error instanceof Error
            ? error.message
            : typeof error === 'object' && error && 'error' in error && typeof (error as { error?: unknown }).error === 'string'
              ? (error as { error?: string }).error
              : 'An error occurred';
        toast({
          variant: "destructive",
          title: "❌ Failed to delete rules",
          description: message,
        })
      },
    }
  )

  const handleEdit = (rule: Rule) => {
    setEditingRule(rule)
    setIsEditDialogOpen(true)
  }

  const handleToggleEnabled = (rule: Rule) => {
    if (rule.id) {
      toggleRuleMutation.mutate({ rule: rule, enabled: !rule.enabled })
    }
  }

  const handleDelete = (rule: Rule) => {
    setRuleToDelete(rule)
    setDeleteConfirmOpen(true)
  }

  const confirmDelete = () => {
    if (ruleToDelete?.id) {
      deleteRuleMutation.mutate(ruleToDelete.id)
    }
    setRuleToDelete(null)
  }

  const handleSelectAll = () => {
    if (selectedRules.size === rules.length) {
      setSelectedRules(new Set())
    } else {
      setSelectedRules(new Set(rules.map(r => r.id!).filter(Boolean)))
    }
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
    setBatchAction('delete')
  }

  const confirmBatchDelete = () => {
    const ruleIds = selectedRules.size > 0 ? Array.from(selectedRules) : undefined
    const confirmAll = selectedRules.size === 0
    batchDeleteMutation.mutate({ ruleIds, confirmAll })
    setBatchAction(null)
  }

  if (isLoading) {
    return (
      <div className="min-h-[400px] flex flex-col items-center justify-center">
        <LoadingSpinner size="lg" />
        <p className="text-muted-foreground mt-2">Loading...</p>
      </div>
    )
  }

  if (error) {
    return (
      <Card>
        <CardContent className="pt-6">
          <div className="text-center text-red-600">
            Error loading rules: {error instanceof Error ? error.message : 'Unknown error'}
          </div>
        </CardContent>
      </Card>
    )
  }

  const rules = rulesResponse?.data || []

  if (rules.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>No Rules Found</CardTitle>
          <CardDescription>
            Create your first rule to start monitoring SkinBaron for CS2 skins.
          </CardDescription>
        </CardHeader>
      </Card>
    )
  }

  return (
    <>
      <Card>
        {rules.length > 0 && (
          <CardHeader className="pb-3">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
              <div className="flex items-center gap-2">
                <span className="text-sm text-muted-foreground">
                  {selectedRules.size > 0 ? `${selectedRules.size} selected` : `${rules.length} total`}
                </span>
              </div>
              <div className="flex flex-wrap gap-2 w-full sm:w-auto">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleBatchEnable}
                  disabled={batchEnableMutation.isPending}
                  className="flex-1 sm:flex-none"
                >
                  <span className="hidden sm:inline">{selectedRules.size > 0 ? 'Enable Selected' : 'Enable All'}</span>
                  <span className="sm:hidden">Enable</span>
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleBatchDisable}
                  disabled={batchDisableMutation.isPending}
                  className="flex-1 sm:flex-none"
                >
                  <span className="hidden sm:inline">{selectedRules.size > 0 ? 'Disable Selected' : 'Disable All'}</span>
                  <span className="sm:hidden">Disable</span>
                </Button>
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={handleBatchDelete}
                  disabled={batchDeleteMutation.isPending}
                  className="flex-1 sm:flex-none"
                >
                  <span className="hidden sm:inline">{selectedRules.size > 0 ? 'Delete Selected' : 'Delete All'}</span>
                  <span className="sm:hidden">Delete</span>
                </Button>
              </div>
            </div>
          </CardHeader>
        )}
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-12">
                  <input
                    type="checkbox"
                    checked={selectedRules.size === rules.length && rules.length > 0}
                    onChange={handleSelectAll}
                    className="cursor-pointer"
                    aria-label="Select all rules"
                  />
                </TableHead>
                <TableHead>Item</TableHead>
                <TableHead>Price Range</TableHead>
                <TableHead>Conditions</TableHead>
                <TableHead>Webhook</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rules.map((rule) => (
                <TableRow key={rule.id}>
                  <TableCell>
                    <input
                      type="checkbox"
                      checked={selectedRules.has(rule.id!)}
                      onChange={() => handleSelectRule(rule.id!)}
                      className="cursor-pointer"
                      aria-label={`Select rule ${rule.search_item}`}
                    />
                  </TableCell>
                  <TableCell className="font-medium">
                    {rule.search_item}
                  </TableCell>
                  <TableCell>
                    {rule.max_price !== null && rule.max_price !== undefined ? (
                      <span>{rule.min_price || 0}€ - {rule.max_price}€</span>
                    ) : rule.min_price && rule.min_price > 0 ? (
                      <span>{rule.min_price}€+</span>
                    ) : (
                      <span className="text-muted-foreground">Any</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-1 flex-wrap items-center">
                      {rule.min_wear !== undefined && rule.min_wear !== null && (
                        <Badge variant="secondary" className="text-xs">
                          Min Wear: {formatWearPercentage(rule.min_wear)}
                        </Badge>
                      )}
                      {rule.max_wear !== undefined && rule.max_wear !== null && (
                        <Badge variant="secondary" className="text-xs">
                          Max Wear: {formatWearPercentage(rule.max_wear)}
                        </Badge>
                      )}
                      {rule.stattrak_filter === 'only' && (
                        <Badge variant="outline" className="text-xs">
                          ⭐ StatTrak Only
                        </Badge>
                      )}
                      {rule.stattrak_filter === 'exclude' && (
                        <Badge variant="secondary" className="text-xs">
                          ✗ No StatTrak
                        </Badge>
                      )}
                      {rule.souvenir_filter === 'only' && (
                        <Badge variant="outline" className="text-xs">
                          🏆 Souvenir Only
                        </Badge>
                      )}
                      {rule.souvenir_filter === 'exclude' && (
                        <Badge variant="secondary" className="text-xs">
                          ✗ No Souvenir
                        </Badge>
                      )}
                      {rule.allow_stickers === false && (
                        <Badge variant="secondary" className="text-xs">
                          🚫 No Stickers
                        </Badge>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    {getWebhookDisplay(rule)}
                  </TableCell>
                  <TableCell>
                    <Badge variant={rule.enabled ? "default" : "secondary"}>
                      {rule.enabled ? "Enabled" : "Disabled"}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {rule.created_at ? new Date(rule.created_at).toLocaleDateString('en-GB') : 'N/A'}
                  </TableCell>
                  <TableCell className="text-right">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" className="h-8 w-8 p-0" aria-label="Open rule actions menu">
                          <span className="sr-only">Open menu</span>
                          <MoreHorizontal className="h-4 w-4" />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuLabel>Actions</DropdownMenuLabel>
                        <DropdownMenuItem onClick={() => handleEdit(rule)}>
                          <Edit className="mr-2 h-4 w-4" />
                          Edit
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => handleToggleEnabled(rule)}>
                          {rule.enabled ? (
                            <>
                              <Pause className="mr-2 h-4 w-4" />
                              Disable
                            </>
                          ) : (
                            <>
                              <Play className="mr-2 h-4 w-4" />
                              Enable
                            </>
                          )}
                        </DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem 
                          onClick={() => handleDelete(rule)}
                          className="text-red-600"
                        >
                          <Trash2 className="mr-2 h-4 w-4" />
                          Delete
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Edit Rule Dialog */}
      <RuleDialog
        open={isEditDialogOpen}
        onOpenChange={(open: boolean) => {
          setIsEditDialogOpen(open)
          if (!open) setEditingRule(null)
        }}
        rule={editingRule}
      />

      {/* Delete Confirmation Dialog */}
      <ConfirmDialog
        open={deleteConfirmOpen}
        onOpenChange={setDeleteConfirmOpen}
        title="Delete Rule"
        description={`Are you sure you want to delete the rule for "${ruleToDelete?.search_item}"? This action cannot be undone.`}
        confirmText="Delete"
        cancelText="Cancel"
        variant="destructive"
        onConfirm={confirmDelete}
      />

      {/* Batch Delete Confirmation Dialog */}
      <ConfirmDialog
        open={batchAction === 'delete'}
        onOpenChange={(open) => !open && setBatchAction(null)}
        title="Delete Rules"
        description={
          selectedRules.size > 0
            ? `Are you sure you want to delete ${selectedRules.size} selected rule(s)? This action cannot be undone.`
            : `Are you sure you want to delete ALL ${rules.length} rules? This action cannot be undone and will permanently delete all your monitoring rules.`
        }
        confirmText="Delete"
        cancelText="Cancel"
        variant="destructive"
        onConfirm={confirmBatchDelete}
      />
    </>
  )
}