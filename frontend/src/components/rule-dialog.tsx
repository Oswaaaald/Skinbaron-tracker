"use client"

import { useState, useEffect } from "react"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
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
import { LoadingSpinner } from "@/components/ui/loading-spinner"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { apiClient, type Rule, type CreateRuleData } from "@/lib/api"
import { wearToPercentage, percentageToWear } from "@/lib/wear-utils"
import { useQuery } from "@tanstack/react-query"
import { useAuth } from "@/contexts/auth-context"
import { useSyncStats } from "@/hooks/use-sync-stats"
import { ItemCombobox } from "@/components/ui/item-combobox"
import { useApiMutation } from "@/hooks/use-api-mutation"
import { useToast } from "@/hooks/use-toast"
import { extractErrorMessage } from "@/lib/utils"
import { QUERY_KEYS } from "@/lib/constants"

const ruleFormSchema = z.object({
  search_item: z.string().min(1, "Search item is required"),
  min_price: z.number().min(0, "Minimum price must be positive").optional(),
  max_price: z.number().min(0, "Maximum price must be positive").optional(),
  min_wear: z.number().min(0, "Min wear must be between 0 and 100").max(100, "Min wear must be between 0 and 100").optional(),
  max_wear: z.number().min(0, "Max wear must be between 0 and 100").max(100, "Max wear must be between 0 and 100").optional(),
  stattrak_filter: z.enum(['all', 'only', 'exclude']).default('all'),
  souvenir_filter: z.enum(['all', 'only', 'exclude']).default('all'),
  allow_stickers: z.boolean().default(true),
  webhook_ids: z.array(z.number()).max(10, "Maximum 10 webhooks allowed").default([]),
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
  useAuth()
  const { syncStats } = useSyncStats()
  const { toast } = useToast()
  const isEditing = !!rule

  // Local state for display values (separate from form values)
  const [minPriceDisplay, setMinPriceDisplay] = useState('')
  const [maxPriceDisplay, setMaxPriceDisplay] = useState('')
  const [minWearDisplay, setMinWearDisplay] = useState('')
  const [maxWearDisplay, setMaxWearDisplay] = useState('')

  // Fetch user's webhooks
  const { data: webhooks = [] } = useQuery({
    queryKey: [QUERY_KEYS.WEBHOOKS],
    queryFn: async () => {
      const result = await apiClient.getWebhooks(false)
      if (!result.success) throw new Error(result.error)
      return result.data || []
    },
    enabled: open, // Only fetch when dialog is open
  })

  const form = useForm({
    resolver: zodResolver(ruleFormSchema),
    defaultValues: {
      search_item: "",
      min_price: undefined,
      max_price: undefined,
      min_wear: undefined,
      max_wear: undefined,
      stattrak_filter: 'all' as const,
      souvenir_filter: 'all' as const,
      allow_stickers: true,
      webhook_ids: [],
      enabled: true,
    },
  })

  // Reset form when dialog opens/closes or rule changes
  useEffect(() => {
    if (open && rule) {
      // Only reset when editing existing rule
      form.reset({
        search_item: rule.search_item || "",
        min_price: rule.min_price !== undefined && rule.min_price !== null ? rule.min_price : undefined,
        max_price: rule.max_price !== undefined && rule.max_price !== null ? rule.max_price : undefined,
        min_wear: rule.min_wear !== undefined && rule.min_wear !== null ? wearToPercentage(rule.min_wear) : undefined,
        max_wear: rule.max_wear !== undefined && rule.max_wear !== null ? wearToPercentage(rule.max_wear) : undefined,
        stattrak_filter: rule.stattrak_filter || 'all',
        souvenir_filter: rule.souvenir_filter || 'all',
        allow_stickers: rule.allow_stickers ?? true,
        webhook_ids: rule.webhook_ids || [],
        enabled: rule.enabled ?? true,
      })
      setSelectedWebhooks(rule.webhook_ids || [])
      // Sync display values with rounding
      setMinPriceDisplay(rule.min_price !== undefined && rule.min_price !== null ? (Math.round(rule.min_price * 100) / 100).toString() : '')
      setMaxPriceDisplay(rule.max_price !== undefined && rule.max_price !== null ? (Math.round(rule.max_price * 100) / 100).toString() : '')
      const minWearPct = rule.min_wear !== undefined && rule.min_wear !== null ? wearToPercentage(rule.min_wear) : undefined
      const maxWearPct = rule.max_wear !== undefined && rule.max_wear !== null ? wearToPercentage(rule.max_wear) : undefined
      setMinWearDisplay(minWearPct !== undefined ? minWearPct.toString() : '')
      setMaxWearDisplay(maxWearPct !== undefined ? maxWearPct.toString() : '')
    } else if (!open) {
      // Reset form when dialog closes (for next creation)
      form.reset({
        search_item: "",
        min_price: undefined,
        max_price: undefined,
        min_wear: undefined,
        max_wear: undefined,
        stattrak_filter: 'all',
        souvenir_filter: 'all',
        allow_stickers: true,
        webhook_ids: [],
        enabled: true,
      })
      setSelectedWebhooks([])
      // Reset display values
      setMinPriceDisplay('')
      setMaxPriceDisplay('')
      setMinWearDisplay('')
      setMaxWearDisplay('')
    }
  }, [open, rule, form])

  // Update form when selectedWebhooks changes
  useEffect(() => {
    form.setValue('webhook_ids', selectedWebhooks)
  }, [selectedWebhooks, form])

  const createRuleMutation = useApiMutation(
    (data: CreateRuleData) => apiClient.createRule(data),
    {
      invalidateKeys: [[QUERY_KEYS.RULES], [QUERY_KEYS.ADMIN_STATS]],
      onSuccess: (result) => {
        if (result.success) {
          toast({
            title: "✅ Rule created",
            description: "Your rule has been created successfully",
          })
          syncStats() // Sync stats immediately after rule creation
          onOpenChange(false)
        } else {
          toast({
            variant: "destructive",
            title: "❌ Failed to create rule",
            description: result.error || "Failed to create rule",
          })
        }
        setIsSubmitting(false)
      },
      onError: (error) => {
        toast({
          variant: "destructive",
          title: "❌ Failed to create rule",
          description: extractErrorMessage(error),
        })
        setIsSubmitting(false)
      },
    }
  )

  const updateRuleMutation = useApiMutation(
    ({ id, data }: { id: number; data: CreateRuleData }) =>
      apiClient.updateRule(id, data),
    {
      invalidateKeys: [[QUERY_KEYS.RULES], [QUERY_KEYS.ADMIN_STATS]],
      onSuccess: (result) => {
        if (result.success) {
          toast({
            title: "✅ Rule updated",
            description: "Your rule has been updated successfully",
          })
          syncStats() // Sync stats immediately after rule update
          onOpenChange(false)
        } else {
          toast({
            variant: "destructive",
            title: "❌ Failed to update rule",
            description: result.error || "Failed to update rule",
          })
        }
        setIsSubmitting(false)
      },
      onError: (error) => {
        toast({
          variant: "destructive",
          title: "❌ Failed to update rule",
          description: extractErrorMessage(error),
        })
        setIsSubmitting(false)
      },
    }
  )

  const onSubmit = async (data: RuleFormData) => {
    if (isSubmitting) return
    setIsSubmitting(true)

    try {
      // Convert RuleFormData to CreateRuleData (convert percentages to 0-1 wear values)
      const createData: CreateRuleData = {
        search_item: data.search_item,
        min_price: data.min_price !== undefined ? data.min_price : 0,
        max_price: data.max_price || undefined,
        min_wear: data.min_wear !== undefined ? percentageToWear(data.min_wear) : 0,
        max_wear: data.max_wear !== undefined ? percentageToWear(data.max_wear) : undefined,
        stattrak_filter: data.stattrak_filter,
        souvenir_filter: data.souvenir_filter,
        allow_stickers: data.allow_stickers,
        webhook_ids: data.webhook_ids,
        enabled: data.enabled ?? true,
      }

      if (isEditing && rule?.id) {
        updateRuleMutation.mutate({ id: rule.id, data: createData })
      } else {
        createRuleMutation.mutate(createData)
      }
    } catch (error) {
      toast({
        variant: "destructive",
        title: "❌ Failed to submit rule",
        description: extractErrorMessage(error),
      })
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
    if (!webhooks || !Array.isArray(webhooks)) return ''
    return webhooks
      .filter(webhook => webhook.id && selectedWebhooks.includes(webhook.id))
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
                    <ItemCombobox
                      value={field.value}
                      onValueChange={field.onChange}
                      placeholder="Type to search items (e.g., AK-47, AWP, Avalanche...)"
                      disabled={isSubmitting}
                    />
                  </FormControl>
                  <FormDescription>
                    Search and select an item from SkinBaron
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
                        type="text"
                        placeholder="ex: 10.50"
                        value={minPriceDisplay}
                        onChange={(e) => {
                          setMinPriceDisplay(e.target.value)
                        }}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            const val = e.currentTarget.value.trim()
                            if (val === '') {
                              field.onChange(undefined)
                              setMinPriceDisplay('')
                            } else {
                              const num = parseFloat(val)
                              if (!isNaN(num) && num >= 0) {
                                const rounded = Math.round(num * 100) / 100
                                field.onChange(rounded)
                                setMinPriceDisplay(rounded.toString())
                              } else {
                                field.onChange(undefined)
                                setMinPriceDisplay('')
                              }
                            }
                          }
                        }}
                        onBlur={(e) => {
                          const val = e.target.value.trim()
                          if (val === '') {
                            field.onChange(undefined)
                            setMinPriceDisplay('')
                          } else {
                            const num = parseFloat(val)
                            if (!isNaN(num) && num >= 0) {
                              const rounded = Math.round(num * 100) / 100
                              field.onChange(rounded)
                              setMinPriceDisplay(rounded.toString())
                            } else {
                              field.onChange(undefined)
                              setMinPriceDisplay('')
                            }
                          }
                        }}
                        disabled={isSubmitting}
                      />
                    </FormControl>
                    <FormDescription>
                      Minimum price in euros. Leave blank to ignore.
                    </FormDescription>
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
                        type="text"
                        placeholder="ex: 50"
                        value={maxPriceDisplay}
                        onChange={(e) => {
                          setMaxPriceDisplay(e.target.value)
                        }}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            const val = e.currentTarget.value.trim()
                            if (val === '') {
                              field.onChange(undefined)
                              setMaxPriceDisplay('')
                            } else {
                              const num = parseFloat(val)
                              if (!isNaN(num) && num >= 0) {
                                const rounded = Math.round(num * 100) / 100
                                field.onChange(rounded)
                                setMaxPriceDisplay(rounded.toString())
                              } else {
                                field.onChange(undefined)
                                setMaxPriceDisplay('')
                              }
                            }
                          }
                        }}
                        onBlur={(e) => {
                          const val = e.target.value.trim()
                          if (val === '') {
                            field.onChange(undefined)
                            setMaxPriceDisplay('')
                          } else {
                            const num = parseFloat(val)
                            if (!isNaN(num) && num >= 0) {
                              const rounded = Math.round(num * 100) / 100
                              field.onChange(rounded)
                              setMaxPriceDisplay(rounded.toString())
                            } else {
                              field.onChange(undefined)
                              setMaxPriceDisplay('')
                            }
                          }
                        }}
                        disabled={isSubmitting}
                      />
                    </FormControl>
                    <FormDescription>
                      Maximum price in euros. Leave blank to ignore.
                    </FormDescription>
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
                    <FormLabel>Min Wear (0-100%)</FormLabel>
                    <FormControl>
                      <Input
                        type="text"
                        placeholder="ex: 15"
                        value={minWearDisplay}
                        onChange={(e) => {
                          setMinWearDisplay(e.target.value)
                        }}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            const val = e.currentTarget.value.trim()
                            if (val === '') {
                              field.onChange(undefined)
                              setMinWearDisplay('')
                            } else {
                              const num = parseFloat(val)
                              if (!isNaN(num) && num >= 0 && num <= 100) {
                                const rounded = Math.round(num * 100) / 100
                                field.onChange(rounded)
                                setMinWearDisplay(rounded.toString())
                              } else {
                                field.onChange(undefined)
                                setMinWearDisplay('')
                              }
                            }
                          }
                        }}
                        onBlur={(e) => {
                          const val = e.target.value.trim()
                          if (val === '') {
                            field.onChange(undefined)
                            setMinWearDisplay('')
                          } else {
                            const num = parseFloat(val)
                            if (!isNaN(num) && num >= 0 && num <= 100) {
                              const rounded = Math.round(num * 100) / 100
                              field.onChange(rounded)
                              setMinWearDisplay(rounded.toString())
                            } else {
                              field.onChange(undefined)
                              setMinWearDisplay('')
                            }
                          }
                        }}
                        disabled={isSubmitting}
                      />
                    </FormControl>
                    <FormDescription>
                      Between 0 and 100. Leave blank to ignore.
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="max_wear"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Max Wear (0-100%)</FormLabel>
                    <FormControl>
                      <Input
                        type="text"
                        placeholder="ex: 85"
                        value={maxWearDisplay}
                        onChange={(e) => {
                          setMaxWearDisplay(e.target.value)
                        }}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            const val = e.currentTarget.value.trim()
                            if (val === '') {
                              field.onChange(undefined)
                              setMaxWearDisplay('')
                            } else {
                              const num = parseFloat(val)
                              if (!isNaN(num) && num >= 0 && num <= 100) {
                                const rounded = Math.round(num * 100) / 100
                                field.onChange(rounded)
                                setMaxWearDisplay(rounded.toString())
                              } else {
                                field.onChange(undefined)
                                setMaxWearDisplay('')
                              }
                            }
                          }
                        }}
                        onBlur={(e) => {
                          const val = e.target.value.trim()
                          if (val === '') {
                            field.onChange(undefined)
                            setMaxWearDisplay('')
                          } else {
                            const num = parseFloat(val)
                            if (!isNaN(num) && num >= 0 && num <= 100) {
                              const rounded = Math.round(num * 100) / 100
                              field.onChange(rounded)
                              setMaxWearDisplay(rounded.toString())
                            } else {
                              field.onChange(undefined)
                              setMaxWearDisplay('')
                            }
                          }
                        }}
                        disabled={isSubmitting}
                      />
                    </FormControl>
                    <FormDescription>
                      Between 0 and 100. Leave blank to ignore.
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            {/* StatTrak, Souvenir and Stickers Filters */}
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <FormField
                  control={form.control}
                  name="stattrak_filter"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>StatTrak™ Filter</FormLabel>
                      <Select onValueChange={field.onChange} value={field.value}>
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue placeholder="Select..." />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="all">✓ Accept all</SelectItem>
                          <SelectItem value="only">⭐ Only StatTrak™</SelectItem>
                          <SelectItem value="exclude">✗ Exclude StatTrak™</SelectItem>
                        </SelectContent>
                      </Select>
                      <FormDescription>
                        Filter StatTrak™ items
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="souvenir_filter"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Souvenir Filter</FormLabel>
                      <Select onValueChange={field.onChange} value={field.value}>
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue placeholder="Select..." />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="all">✓ Accept all</SelectItem>
                          <SelectItem value="only">🏆 Only Souvenir</SelectItem>
                          <SelectItem value="exclude">✗ Exclude Souvenir</SelectItem>
                        </SelectContent>
                      </Select>
                      <FormDescription>
                        Filter Souvenir items
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              <FormField
                control={form.control}
                name="allow_stickers"
                render={({ field }) => (
                  <FormItem className="flex flex-row items-center justify-between rounded-lg border p-3">
                    <div className="space-y-0.5">
                      <FormLabel>Allow Stickers</FormLabel>
                      <FormDescription className="text-sm">
                        Include items with stickers
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
                  <FormLabel>Notification Webhooks (Optional - Max 10)</FormLabel>
                  <FormDescription className="mb-3">
                    Select which webhooks should receive notifications for this rule. Leave empty to create a rule without notifications.
                  </FormDescription>
                  
                  {!webhooks || webhooks.length === 0 ? (
                    <div className="text-center py-4 text-muted-foreground">
                      {!webhooks ? 'Loading webhooks...' : 'No webhooks configured. You can create a rule without notifications or add webhooks in the Webhooks section.'}
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
                disabled={isSubmitting}
              >
                {isSubmitting ? (
                  <>
                    <LoadingSpinner size="sm" className="mr-2" inline />
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