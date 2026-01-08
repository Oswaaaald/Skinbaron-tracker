"use client"

import { useState } from "react"
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query"
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
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { LoadingSpinner } from "@/components/ui/loading-spinner"
import { MoreHorizontal, Edit, Trash2, Play, Pause } from "lucide-react"
import { toast } from "sonner"
import { apiClient, type Rule } from "@/lib/api"
import { RuleDialog } from "@/components/rule-dialog"
import { formatWearPercentage } from "@/lib/wear-utils"
import { useAuth } from "@/contexts/auth-context"
import { useSyncStats } from "@/hooks/use-sync-stats"

export function RulesTable() {
  const [editingRule, setEditingRule] = useState<Rule | null>(null)
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false)
  const queryClient = useQueryClient()
  const { isReady, isAuthenticated } = useAuth()
  const { syncStats } = useSyncStats()

  const { data: rulesResponse, isLoading, error } = useQuery({
    queryKey: ['rules'],
    queryFn: () => apiClient.getRules(),
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

  const toggleRuleMutation = useMutation({
    mutationFn: ({ rule, enabled }: { rule: Rule; enabled: boolean }) => {
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
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      queryClient.invalidateQueries({ queryKey: ['admin', 'stats'] })
      syncStats() // Sync stats immediately after rule change
      toast.success('Rule updated successfully')
    },
    onError: (error) => {
      toast.error(`Failed to update rule: ${error instanceof Error ? error.message : 'Unknown error'}`)
    },
  })

  const deleteRuleMutation = useMutation({
    mutationFn: (id: number) => apiClient.deleteRule(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      queryClient.invalidateQueries({ queryKey: ['admin', 'stats'] })
      syncStats() // Sync stats immediately after rule deletion
      toast.success('Rule deleted successfully')
    },
    onError: (error) => {
      toast.error(`Failed to delete rule: ${error instanceof Error ? error.message : 'Unknown error'}`)
    },
  })

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
    if (rule.id && confirm('Are you sure you want to delete this rule?')) {
      deleteRuleMutation.mutate(rule.id)
    }
  }

  if (isLoading) {
    return <LoadingSpinner />
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
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
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
                    <div className="flex gap-1 flex-wrap">
                                            {rule.min_wear !== undefined && rule.min_wear !== null && (
                        <div className="text-xs text-muted-foreground">
                          Min Wear: {formatWearPercentage(rule.min_wear)}
                        </div>
                      )}
                      {rule.max_wear !== undefined && rule.max_wear !== null && (
                        <div className="text-xs text-muted-foreground">
                          Max Wear: {formatWearPercentage(rule.max_wear)}
                        </div>
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
                        <Button variant="ghost" className="h-8 w-8 p-0">
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
    </>
  )
}