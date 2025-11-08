"use client"

import { useState, useEffect } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import * as z from "zod"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { Label } from "@/components/ui/label"
import { toast } from "sonner"
import { apiClient, type Rule, type Webhook, type CreateRuleData } from "@/lib/api"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useQuery } from "@tanstack/react-query"
import { useAuth } from "@/contexts/auth-context"
import { X } from "lucide-react"

const ruleFormSchema = z.object({
  search_item: z.string().min(1, "Search item is required"),
  min_price: z.number().positive().optional().or(z.literal(0)),
  max_price: z.number().positive().optional().or(z.literal(0)),
  min_wear: z.number().min(0).max(1).optional(),
  max_wear: z.number().min(0).max(1).optional(),
  stattrak: z.boolean().optional(),
  souvenir: z.boolean().optional(),
  webhook_ids: z.array(z.number()).min(1, "At least one webhook must be selected").max(10, "Maximum 10 webhooks allowed"),
  enabled: z.boolean().optional(),
})

type RuleFormData = z.infer<typeof ruleFormSchema>

interface RuleDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  rule?: Rule | null
}

export function RuleDialog({ open, onOpenChange, rule }: RuleDialogProps) {
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [selectedWebhooks, setSelectedWebhooks] = useState<number[]>([])
  const queryClient = useQueryClient()
  const { user } = useAuth()
  const isEditing = !!rule

  // Fetch user's webhooks
  const { data: webhooks = [] } = useQuery({
    queryKey: ['webhooks'],
    queryFn: async () => {
      const result = await apiClient.getWebhooks(false)
      if (!result.success) throw new Error(result.error)
      return result.data || []
    },
    enabled: open, // Only fetch when dialog is open
  })

  const form = useForm<RuleFormData>({
    resolver: zodResolver(ruleFormSchema),
    defaultValues: {
      search_item: "",
      min_price: undefined,
      max_price: undefined,
      min_wear: undefined,
      max_wear: undefined,
      stattrak: false,
      souvenir: false,
      webhook_ids: [],
      enabled: true,
    },
  })

  // Reset form when dialog opens/closes or rule changes
  useEffect(() => {
    if (open) {
      if (rule) {
        // Editing existing rule
        form.reset({
          search_item: rule.search_item || "",
          min_price: rule.min_price || undefined,
          max_price: rule.max_price || undefined,
          min_wear: rule.min_wear || undefined,
          max_wear: rule.max_wear || undefined,
          stattrak: rule.stattrak || false,
          souvenir: rule.souvenir || false,
          webhook_ids: rule.webhook_ids || [],
          enabled: rule.enabled ?? true,
        })
        setSelectedWebhooks(rule.webhook_ids || [])
      } else {
        // Creating new rule
        form.reset({
          search_item: "",
          min_price: undefined,
          max_price: undefined,
          min_wear: undefined,
          max_wear: undefined,
          stattrak: false,
          souvenir: false,
          webhook_ids: [],
          enabled: true,
        })
        setSelectedWebhooks([])
      }
    }
  }, [open, rule, form])

  // Update form when selectedWebhooks changes
  useEffect(() => {
    form.setValue('webhook_ids', selectedWebhooks)
  }, [selectedWebhooks, form])

  const createRuleMutation = useMutation({
    mutationFn: (data: CreateRuleData) => apiClient.createRule(data),
    onSuccess: (result) => {
      if (result.success) {
        toast.success("Rule created successfully!")
        queryClient.invalidateQueries({ queryKey: ['rules'] })
        onOpenChange(false)
      } else {
        toast.error(result.error || "Failed to create rule")
      }
      setIsSubmitting(false)
    },
    onError: (error) => {
      toast.error(`Failed to create rule: ${error instanceof Error ? error.message : 'Unknown error'}`)
      setIsSubmitting(false)
    },
  })

  const updateRuleMutation = useMutation({
    mutationFn: ({ id, data }: { id: number; data: CreateRuleData }) =>
      apiClient.updateRule(id, data),
    onSuccess: (result) => {
      if (result.success) {
        toast.success("Rule updated successfully!")
        queryClient.invalidateQueries({ queryKey: ['rules'] })
        onOpenChange(false)
      } else {
        toast.error(result.error || "Failed to update rule")
      }
      setIsSubmitting(false)
    },
    onError: (error) => {
      toast.error(`Failed to update rule: ${error instanceof Error ? error.message : 'Unknown error'}`)
      setIsSubmitting(false)
    },
  })

  const onSubmit = async (data: RuleFormData) => {
    if (isSubmitting) return
    setIsSubmitting(true)

    try {
      // Convert RuleFormData to CreateRuleData (they have the same structure)
      const createData: CreateRuleData = {
        search_item: data.search_item,
        min_price: data.min_price || undefined,
        max_price: data.max_price || undefined,
        min_wear: data.min_wear,
        max_wear: data.max_wear,
        stattrak: data.stattrak,
        souvenir: data.souvenir,
        webhook_ids: data.webhook_ids,
        enabled: data.enabled ?? true,
      }

      if (isEditing && rule?.id) {
        updateRuleMutation.mutate({ id: rule.id, data: createData })
      } else {
        createRuleMutation.mutate(createData)
      }
    } catch (error) {
      toast.error(`Failed to submit rule: ${error instanceof Error ? error.message : 'Unknown error'}`)
      setIsSubmitting(false)
    }
  }

  const handleWebhookToggle = (webhookId: number) => {
    setSelectedWebhooks(prev => 
      prev.includes(webhookId)
        ? prev.filter(id => id !== webhookId)
        : [...prev, webhookId]
    )
  }

  const getSelectedWebhookNames = () => {
    return webhooks
      .filter(webhook => selectedWebhooks.includes(webhook.id!))
      .map(webhook => webhook.name)
      .join(', ')
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[600px] max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            {isEditing ? "Edit Rule" : "Create New Rule"}
          </DialogTitle>
          <DialogDescription>
            {isEditing 
              ? "Update your alert rule configuration"
              : "Create a new alert rule to monitor SkinBaron listings"
            }
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
            {/* Search Item */}
            <FormField
              control={form.control}
              name="search_item"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Search Item *</FormLabel>
                  <FormControl>
                    <Input 
                      placeholder="e.g., AK-47 Redline, AWP Dragon Lore" 
                      {...field}
                      disabled={isSubmitting}
                    />
                  </FormControl>
                  <FormDescription>
                    Item name or pattern to search for
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

            {/* Price Range */}
            <div className="grid grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="min_price"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Min Price (€)</FormLabel>
                    <FormControl>
                      <Input
                        type="number"
                        min="0"
                        step="0.01"
                        placeholder="0"
                        {...field}
                        onChange={(e) => field.onChange(e.target.value ? parseFloat(e.target.value) : undefined)}
                        disabled={isSubmitting}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="max_price"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Max Price (€)</FormLabel>
                    <FormControl>
                      <Input
                        type="number"
                        min="0"
                        step="0.01"
                        placeholder="No limit"
                        {...field}
                        onChange={(e) => field.onChange(e.target.value ? parseFloat(e.target.value) : undefined)}
                        disabled={isSubmitting}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            {/* Wear Range */}
            <div className="grid grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="min_wear"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Min Wear (0-1)</FormLabel>
                    <FormControl>
                      <Input
                        type="number"
                        min="0"
                        max="1"
                        step="0.001"
                        placeholder="0"
                        {...field}
                        onChange={(e) => field.onChange(e.target.value ? parseFloat(e.target.value) : undefined)}
                        disabled={isSubmitting}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="max_wear"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Max Wear (0-1)</FormLabel>
                    <FormControl>
                      <Input
                        type="number"
                        min="0"
                        max="1"
                        step="0.001"
                        placeholder="1"
                        {...field}
                        onChange={(e) => field.onChange(e.target.value ? parseFloat(e.target.value) : undefined)}
                        disabled={isSubmitting}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            {/* StatTrak and Souvenir */}
            <div className="grid grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="stattrak"
                render={({ field }) => (
                  <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3">
                    <div className="space-y-0.5">
                      <FormLabel>StatTrak™</FormLabel>
                      <FormDescription className="text-sm">
                        Only StatTrak™ items
                      </FormDescription>
                    </div>
                    <FormControl>
                      <Switch
                        checked={field.value}
                        onCheckedChange={field.onChange}
                        disabled={isSubmitting}
                      />
                    </FormControl>
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="souvenir"
                render={({ field }) => (
                  <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3">
                    <div className="space-y-0.5">
                      <FormLabel>Souvenir</FormLabel>
                      <FormDescription className="text-sm">
                        Only Souvenir items
                      </FormDescription>
                    </div>
                    <FormControl>
                      <Switch
                        checked={field.value}
                        onCheckedChange={field.onChange}
                        disabled={isSubmitting}
                      />
                    </FormControl>
                  </FormItem>
                )}
              />
            </div>

            {/* Webhook Selection */}
            <FormField
              control={form.control}
              name="webhook_ids"
              render={() => (
                <FormItem>
                  <FormLabel>Notification Webhooks * (Max 10)</FormLabel>
                  <FormDescription className="mb-3">
                    Select which webhooks should receive notifications for this rule
                  </FormDescription>
                  
                  {webhooks.length === 0 ? (
                    <div className="text-center py-4 text-muted-foreground">
                      No webhooks configured. Create webhooks first in the Webhooks section.
                    </div>
                  ) : (
                    <div className="space-y-2 max-h-40 overflow-y-auto border rounded-md p-3">
                      {webhooks.map(webhook => (
                        <div
                          key={webhook.id}
                          className="flex items-center space-x-2 p-2 rounded border hover:bg-muted cursor-pointer"
                          onClick={() => handleWebhookToggle(webhook.id!)}
                        >
                          <input
                            type="checkbox"
                            checked={selectedWebhooks.includes(webhook.id!)}
                            onChange={() => handleWebhookToggle(webhook.id!)}
                            className="h-4 w-4"
                          />
                          <span className="flex-1 text-sm">{webhook.name}</span>
                          <span className="text-xs text-muted-foreground">
                            {webhook.webhook_type === 'discord' ? '🎮 Discord' : '🔗 Other'}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}

                  {selectedWebhooks.length > 0 && (
                    <div className="mt-2 p-2 bg-muted rounded text-sm">
                      <strong>Selected:</strong> {getSelectedWebhookNames()}
                    </div>
                  )}

                  <FormMessage />
                </FormItem>
              )}
            />

            {/* Enabled */}
            <FormField
              control={form.control}
              name="enabled"
              render={({ field }) => (
                <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3">
                  <div className="space-y-0.5">
                    <FormLabel>Enable Rule</FormLabel>
                    <FormDescription>
                      Rule will be active and send notifications
                    </FormDescription>
                  </div>
                  <FormControl>
                    <Switch
                      checked={field.value}
                      onCheckedChange={field.onChange}
                      disabled={isSubmitting}
                    />
                  </FormControl>
                </FormItem>
              )}
            />

            <DialogFooter>
              <Button
                type="button"
                variant="outline"
                onClick={() => onOpenChange(false)}
                disabled={isSubmitting}
              >
                Cancel
              </Button>
              <Button 
                type="submit" 
                disabled={isSubmitting || selectedWebhooks.length === 0}
              >
                {isSubmitting ? (
                  <>
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                    {isEditing ? "Updating..." : "Creating..."}
                  </>
                ) : (
                  isEditing ? "Update Rule" : "Create Rule"
                )}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  )
}