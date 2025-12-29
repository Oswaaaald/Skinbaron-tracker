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
import { wearToPercentage, percentageToWear } from "@/lib/wear-utils"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useQuery } from "@tanstack/react-query"
import { useAuth } from "@/contexts/auth-context"
import { useSyncStats } from "@/hooks/use-sync-stats"
import { X } from "lucide-react"

const ruleFormSchema = z.object({
  search_item: z.string().min(1, "Search item is required"),
  min_price: z.number().min(0, "Prix minimum doit être positif").optional(),
  max_price: z.number().min(0, "Prix maximum doit être positif").optional(),
  min_wear: z.number().min(0, "Wear minimum doit être entre 0 et 100").max(100, "Wear minimum doit être entre 0 et 100").optional(),
  max_wear: z.number().min(0, "Wear maximum doit être entre 0 et 100").max(100, "Wear maximum doit être entre 0 et 100").optional(),
  stattrak: z.boolean().optional(),
  souvenir: z.boolean().optional(),
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
  const queryClient = useQueryClient()
  const { user } = useAuth()
  const { syncStats } = useSyncStats()
  const isEditing = !!rule

  // Local state for display values (separate from form values)
  const [minPriceDisplay, setMinPriceDisplay] = useState('')
  const [maxPriceDisplay, setMaxPriceDisplay] = useState('')
  const [minWearDisplay, setMinWearDisplay] = useState('')
  const [maxWearDisplay, setMaxWearDisplay] = useState('')

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

  const form = useForm({
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
          min_price: rule.min_price !== undefined && rule.min_price !== null ? rule.min_price : undefined,
          max_price: rule.max_price !== undefined && rule.max_price !== null ? rule.max_price : undefined,
          min_wear: rule.min_wear !== undefined && rule.min_wear !== null ? wearToPercentage(rule.min_wear) : undefined,
          max_wear: rule.max_wear !== undefined && rule.max_wear !== null ? wearToPercentage(rule.max_wear) : undefined,
          stattrak: rule.stattrak || false,
          souvenir: rule.souvenir || false,
          webhook_ids: rule.webhook_ids || [],
          enabled: rule.enabled ?? true,
        })
        setSelectedWebhooks(rule.webhook_ids || [])
        // Sync display values
        setMinPriceDisplay(rule.min_price !== undefined && rule.min_price !== null ? rule.min_price.toString() : '')
        setMaxPriceDisplay(rule.max_price !== undefined && rule.max_price !== null ? rule.max_price.toString() : '')
        setMinWearDisplay(rule.min_wear !== undefined && rule.min_wear !== null ? wearToPercentage(rule.min_wear).toString() : '')
        setMaxWearDisplay(rule.max_wear !== undefined && rule.max_wear !== null ? wearToPercentage(rule.max_wear).toString() : '')
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
        // Reset display values
        setMinPriceDisplay('')
        setMaxPriceDisplay('')
        setMinWearDisplay('')
        setMaxWearDisplay('')
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
        syncStats() // Sync stats immediately after rule creation
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
        syncStats() // Sync stats immediately after rule update
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
      // Convert RuleFormData to CreateRuleData (convert percentages to 0-1 wear values)
      const createData: CreateRuleData = {
        search_item: data.search_item,
        min_price: data.min_price !== undefined ? data.min_price : 0,
        max_price: data.max_price || undefined,
        min_wear: data.min_wear !== undefined ? percentageToWear(data.min_wear) : 0,
        max_wear: data.max_wear !== undefined ? percentageToWear(data.max_wear) : undefined,
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
                render={({ field }) => {
                  const [displayValue, setDisplayValue] = useState(field.value?.toString() || '')
                  
                  return (
                    <FormItem>
                      <FormLabel>Min Price (€)</FormLabel>
                      <FormControl>
                        <Input
                          type="text"
                          placeholder="ex: 10.50"
                          value={displayValue}
                          onChange={(e) => {
                            setDisplayValue(e.target.value)
                          }}
                          onBlur={(e) => {
                            const val = e.target.value.trim()
                            if (val === '') {
                              field.onChange(undefined)
                              setDisplayValue('')
                            } else {
                              const num = parseFloat(val)
                              if (!isNaN(num) && num >= 0) {
                                field.onChange(num)
                                setDisplayValue(num.toString())
                              } else {
                                field.onChange(undefined)
                                setDisplayValue('')
                              }
                            }
                          }}
                          disabled={isSubmitting}
                        />
                      </FormControl>
                      <FormDescription>
                        Prix minimum en euros. Laissez vide pour ignorer.
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )
                }}
              />

              <FormField
                control={form.control}
                name="max_price"
                render={({ field }) => {
                  const [displayValue, setDisplayValue] = useState(field.value?.toString() || '')
                  
                  return (
                    <FormItem>
                      <FormLabel>Max Price (€)</FormLabel>
                      <FormControl>
                        <Input
                          type="text"
                          placeholder="ex: 50"
                          value={displayValue}
                          onChange={(e) => {
                            setDisplayValue(e.target.value)
                          }}
                          onBlur={(e) => {
                            const val = e.target.value.trim()
                            if (val === '') {
                              field.onChange(undefined)
                              setDisplayValue('')
                            } else {
                              const num = parseFloat(val)
                              if (!isNaN(num) && num >= 0) {
                                field.onChange(num)
                                setDisplayValue(num.toString())
                              } else {
                                field.onChange(undefined)
                                setDisplayValue('')
                              }
                            }
                          }}
                          disabled={isSubmitting}
                        />
                      </FormControl>
                      <FormDescription>
                        Prix maximum en euros. Laissez vide pour ignorer.
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )
                }}
              />
            </div>

            {/* Wear Range */}
            <div className="grid grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="min_wear"
                render={({ field }) => {
                  const [displayValue, setDisplayValue] = useState(field.value?.toString() || '')
                  
                  return (
                    <FormItem>
                      <FormLabel>Min Wear (0-100%)</FormLabel>
                      <FormControl>
                        <Input
                          type="text"
                          placeholder="ex: 15"
                          value={displayValue}
                          onChange={(e) => {
                            setDisplayValue(e.target.value)
                          }}
                          onBlur={(e) => {
                            const val = e.target.value.trim()
                            if (val === '') {
                              field.onChange(undefined)
                              setDisplayValue('')
                            } else {
                              const num = parseFloat(val)
                              if (!isNaN(num) && num >= 0 && num <= 100) {
                                field.onChange(num)
                                setDisplayValue(num.toString())
                              } else {
                                field.onChange(undefined)
                                setDisplayValue('')
                              }
                            }
                          }}
                          disabled={isSubmitting}
                        />
                      </FormControl>
                      <FormDescription>
                        Entre 0 et 100. Laissez vide pour ignorer.
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )
                }}
              />

              <FormField
                control={form.control}
                name="max_wear"
                render={({ field }) => {
                  const [displayValue, setDisplayValue] = useState(field.value?.toString() || '')
                  
                  return (
                    <FormItem>
                      <FormLabel>Max Wear (0-100%)</FormLabel>
                      <FormControl>
                        <Input
                          type="text"
                          placeholder="ex: 85"
                          value={displayValue}
                          onChange={(e) => {
                            setDisplayValue(e.target.value)
                          }}
                          onBlur={(e) => {
                            const val = e.target.value.trim()
                            if (val === '') {
                              field.onChange(undefined)
                              setDisplayValue('')
                            } else {
                              const num = parseFloat(val)
                              if (!isNaN(num) && num >= 0 && num <= 100) {
                                field.onChange(num)
                                setDisplayValue(num.toString())
                              } else {
                                field.onChange(undefined)
                                setDisplayValue('')
                              }
                            }
                          }}
                          disabled={isSubmitting}
                        />
                      </FormControl>
                      <FormDescription>
                        Entre 0 et 100. Laissez vide pour ignorer.
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )
                }}
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