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
import { MoreHorizontal, Edit, Trash2, TestTube2, Play, Pause } from "lucide-react"
import { toast } from "sonner"
import { apiClient, type Rule } from "@/lib/api"
import { RuleDialog } from "@/components/rule-dialog"

export function RulesTable() {
  const [editingRule, setEditingRule] = useState<Rule | null>(null)
  const [isEditDialogOpen, setIsEditDialogOpen] = useState(false)
  const queryClient = useQueryClient()

  const { data: rulesResponse, isLoading, error } = useQuery({
    queryKey: ['rules'],
    queryFn: () => apiClient.getRules(),
  })

  // Fetch user's webhooks to display webhook names in rules table
  const { data: webhooksResponse, isLoading: webhooksLoading, error: webhooksError } = useQuery({
    queryKey: ['webhooks'],
    queryFn: async () => {
      console.log('Fetching webhooks...')
      const result = await apiClient.getWebhooks()
      console.log('Webhooks API response:', result)
      return result
    },
    retry: 2,
  })

  // Handle both direct array and ApiResponse wrapper
  const webhooks = Array.isArray(webhooksResponse) 
    ? webhooksResponse 
    : (webhooksResponse?.data || [])
  
  // Debug webhooks loading
  console.log('Webhooks loading state:', { webhooksLoading, webhooksError, webhooksResponse, webhooks })

  // Helper function to get webhook display text
  const getWebhookDisplay = (rule: Rule) => {
    
    if (rule.webhook_ids && rule.webhook_ids.length > 0) {
      const webhookNames = rule.webhook_ids
        .map(id => {
          const webhook = webhooks.find(w => w.id === id)
          console.log(`Looking for webhook ID ${id}, found:`, webhook)
          return webhook?.name
        })
        .filter(Boolean)
      
      console.log('webhookNames:', webhookNames)
      
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
    
    console.log('Falling back to "No webhook"')
    return (
      <Badge variant="secondary" className="text-xs">
        No webhook
      </Badge>
    )
  }

  const toggleRuleMutation = useMutation({
    mutationFn: ({ rule, enabled }: { rule: Rule; enabled: boolean }) => {
      // Send complete rule data with updated enabled status (like create)
      const updateData = {
        search_item: rule.search_item,
        min_price: rule.min_price,
        max_price: rule.max_price,
        min_wear: rule.min_wear,
        max_wear: rule.max_wear,
        stattrak: rule.stattrak,
        souvenir: rule.souvenir,
        webhook_ids: rule.webhook_ids,
        enabled: enabled,
      };
      return apiClient.updateRule(rule.id, updateData);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] })
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
      toast.success('Rule deleted successfully')
    },
    onError: (error) => {
      toast.error(`Failed to delete rule: ${error instanceof Error ? error.message : 'Unknown error'}`)
    },
  })

  const testRuleMutation = useMutation({
    mutationFn: ({ id, webhookTest, webhookOnly }: { id: number; webhookTest: boolean; webhookOnly?: boolean }) =>
      apiClient.testRule(id, webhookTest, webhookOnly),
    onSuccess: (data) => {
      if (data.success && data.data) {
        const isWebhookOnly = data.data.matchCount === 0 && data.data.webhookTest !== null;
        if (isWebhookOnly) {
          toast.success(`Webhook test ${data.data.webhookTest ? 'successful' : 'failed'}`)
        } else {
          toast.success(`Test completed: ${data.data.matchCount} matches found${data.data.webhookTest ? ', webhook test sent' : ''}`)
        }
      } else {
        toast.error(data.error || 'Test failed')
      }
    },
    onError: (error) => {
      toast.error(`Test failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
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

  const handleTest = (rule: Rule, webhookTest: boolean = false) => {
    if (rule.id) {
      testRuleMutation.mutate({ id: rule.id, webhookTest })
    }
  }

  const handleTestWebhookOnly = (rule: Rule) => {
    if (rule.id) {
      testRuleMutation.mutate({ id: rule.id, webhookTest: true, webhookOnly: true })
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
                    {rule.min_price || rule.max_price ? (
                      <span>
                        {rule.min_price ? `$${rule.min_price}` : ''}
                        {rule.min_price && rule.max_price ? ' - ' : ''}
                        {rule.max_price ? `$${rule.max_price}` : ''}
                      </span>
                    ) : (
                      <span className="text-muted-foreground">Any</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex gap-1 flex-wrap">
                      {rule.min_wear !== undefined && rule.min_wear !== null && (
                        <Badge variant="outline" className="text-xs">
                          Min Wear: {rule.min_wear}
                        </Badge>
                      )}
                      {rule.max_wear !== undefined && rule.max_wear !== null && (
                        <Badge variant="outline" className="text-xs">
                          Max Wear: {rule.max_wear}
                        </Badge>
                      )}
                      {rule.stattrak && (
                        <Badge variant="outline" className="text-xs">
                          StatTrak
                        </Badge>
                      )}
                      {rule.souvenir && (
                        <Badge variant="outline" className="text-xs">
                          Souvenir
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
                    {rule.created_at ? new Date(rule.created_at).toLocaleDateString() : 'N/A'}
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
                        <DropdownMenuItem onClick={() => handleTest(rule, false)}>
                          <TestTube2 className="mr-2 h-4 w-4" />
                          Test Rule
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => handleTest(rule, true)}>
                          <TestTube2 className="mr-2 h-4 w-4" />
                          Test + Webhook
                        </DropdownMenuItem>
                        <DropdownMenuItem onClick={() => handleTestWebhookOnly(rule)}>
                          <TestTube2 className="mr-2 h-4 w-4" />
                          Test Webhook Only
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