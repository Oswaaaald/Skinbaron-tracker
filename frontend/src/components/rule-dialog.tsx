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
import { apiClient, type Rule, type Webhook } from "@/lib/api"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useQuery } from "@tanstack/react-query"
import { useAuth } from "@/contexts/auth-context"

const ruleFormSchema = z.object({
  search_item: z.string().min(1, "Search item is required"),
  min_price: z.number().positive().optional().or(z.literal(0)),
  max_price: z.number().positive().optional().or(z.literal(0)),
  min_wear: z.number().min(0).max(1).optional(),
  max_wear: z.number().min(0).max(1).optional(),
  stattrak: z.boolean().optional(),
  souvenir: z.boolean().optional(),
  webhook_ids: z.array(z.number()).optional(), // New: array of webhook IDs
  discord_webhook: z.string().url("Invalid webhook URL").optional(), // Keep for backward compatibility
  enabled: z.boolean().optional(),
}).refine(
  (data) => {
    // Must have either webhook_ids with at least one element OR discord_webhook with valid URL
    const hasWebhookIds = data.webhook_ids && data.webhook_ids.length > 0
    const hasDiscordWebhook = data.discord_webhook && data.discord_webhook.trim().length > 0
    return hasWebhookIds || hasDiscordWebhook
  },
  {
    message: "At least one webhook must be selected",
    path: ["webhook_ids"],
  }
)

type RuleFormData = z.infer<typeof ruleFormSchema>

interface RuleDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  rule?: Rule | null
}

export function RuleDialog({ open, onOpenChange, rule }: RuleDialogProps) {
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [useDirectWebhook, setUseDirectWebhook] = useState(false)
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
      min_price: 0,
      max_price: 0,
      min_wear: undefined,
      max_wear: undefined,
      stattrak: false,
      souvenir: false,
      webhook_ids: [],
      discord_webhook: "",
      enabled: true,
    },
  })

  // Reset form when dialog opens/closes or rule changes
  useEffect(() => {
    if (open) {
      if (rule) {
        // Editing existing rule - determine which webhook method was used
        const hasDirectWebhook = !!rule.discord_webhook && (!rule.webhook_ids || rule.webhook_ids.length === 0)
        const hasWebhookIds = !!rule.webhook_ids && rule.webhook_ids.length > 0
        setUseDirectWebhook(hasDirectWebhook)
        
        form.reset({
          search_item: rule.search_item,
          min_price: rule.min_price || 0,
          max_price: rule.max_price || 0,
          min_wear: rule.min_wear,
          max_wear: rule.max_wear,
          stattrak: rule.stattrak || false,
          souvenir: rule.souvenir || false,
          webhook_ids: rule.webhook_ids || [], // Load existing webhook_ids
          discord_webhook: rule.discord_webhook || "",
          enabled: rule.enabled ?? true,
        })
      } else {
        // Creating new rule
        setUseDirectWebhook(false)
        
        form.reset({
          search_item: "",
          min_price: 0,
          max_price: 0,
          min_wear: undefined,
          max_wear: undefined,
          stattrak: false,
          souvenir: false,
          webhook_ids: [],
          discord_webhook: "",
          enabled: true,
        })
      }
    }
  }, [open, rule, form])

  const createRuleMutation = useMutation({
    mutationFn: (data: Omit<Rule, 'id' | 'created_at' | 'updated_at'>) =>
      apiClient.createRule(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      toast.success('Rule created successfully')
      onOpenChange(false)
    },
    onError: (error) => {
      toast.error(`Failed to create rule: ${error instanceof Error ? error.message : 'Unknown error'}`)
    },
    onSettled: () => {
      setIsSubmitting(false)
    },
  })

  const updateRuleMutation = useMutation({
    mutationFn: ({ id, data }: { id: number; data: Partial<Rule> }) =>
      apiClient.updateRule(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] })
      toast.success('Rule updated successfully')
      onOpenChange(false)
    },
    onError: (error) => {
      toast.error(`Failed to update rule: ${error instanceof Error ? error.message : 'Unknown error'}`)
    },
    onSettled: () => {
      setIsSubmitting(false)
    },
  })

  const onSubmit = async (data: RuleFormData) => {
    if (!user) {
      toast.error('User not authenticated')
      return
    }

    setIsSubmitting(true)
    
    // Convert empty numbers to undefined and clean webhook data
    const processedData: any = {
      ...data,
      user_id: user.id, // Automatically use authenticated user's ID
      min_price: data.min_price === 0 ? undefined : data.min_price,
      max_price: data.max_price === 0 ? undefined : data.max_price,
    }

    // Clean webhook data based on selection
    if (useDirectWebhook) {
      // Using direct webhook URL - clear webhook_ids
      delete processedData.webhook_ids
    } else {
      // Using saved webhooks - clear discord_webhook
      delete processedData.discord_webhook
    }

    if (isEditing && rule?.id) {
      updateRuleMutation.mutate({ id: rule.id, data: processedData })
    } else {
      createRuleMutation.mutate(processedData)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[600px] max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{isEditing ? 'Edit Rule' : 'Create New Rule'}</DialogTitle>
          <DialogDescription>
            {isEditing 
              ? 'Update your skin monitoring rule settings.'
              : 'Configure a new rule to monitor CS2 skins on SkinBaron.'
            }
          </DialogDescription>
        </DialogHeader>
        
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
            <div className="grid grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="search_item"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Search Item</FormLabel>
                    <FormControl>
                      <Input placeholder="e.g., AK-47 | Redline" {...field} />
                    </FormControl>
                    <FormDescription>
                      The skin name to search for
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="min_price"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Min Price ($)</FormLabel>
                    <FormControl>
                      <Input 
                        type="number" 
                        placeholder="0" 
                        step="0.01"
                        {...field}
                        onChange={(e) => field.onChange(e.target.value === '' ? 0 : Number(e.target.value))}
                      />
                    </FormControl>
                    <FormDescription>
                      Minimum price filter (leave 0 for no minimum)
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
                    <FormLabel>Max Price ($)</FormLabel>
                    <FormControl>
                      <Input 
                        type="number" 
                        placeholder="0" 
                        step="0.01"
                        {...field}
                        onChange={(e) => field.onChange(e.target.value === '' ? 0 : Number(e.target.value))}
                      />
                    </FormControl>
                    <FormDescription>
                      Maximum price filter (leave 0 for no maximum)
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="min_wear"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Min Wear Value</FormLabel>
                    <FormControl>
                      <Input 
                        type="number" 
                        placeholder="0.00" 
                        step="0.01"
                        min="0"
                        max="1"
                        {...field}
                        onChange={(e) => field.onChange(e.target.value === '' ? undefined : Number(e.target.value))}
                        value={field.value || ''}
                      />
                    </FormControl>
                    <FormDescription>
                      Minimum wear value (0.00 - 1.00)
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
                    <FormLabel>Max Wear Value</FormLabel>
                    <FormControl>
                      <Input 
                        type="number" 
                        placeholder="1.00" 
                        step="0.01"
                        min="0"
                        max="1"
                        {...field}
                        onChange={(e) => field.onChange(e.target.value === '' ? undefined : Number(e.target.value))}
                        value={field.value || ''}
                      />
                    </FormControl>
                    <FormDescription>
                      Maximum wear value (0.00 - 1.00)
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            {/* Webhook Selection */}
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <FormLabel>Notification Settings</FormLabel>
                <div className="flex items-center space-x-2">
                  <Switch
                    id="use-direct"
                    checked={useDirectWebhook}
                    onCheckedChange={setUseDirectWebhook}
                  />
                  <Label htmlFor="use-direct" className="text-sm">Use direct URL</Label>
                </div>
              </div>

              {!useDirectWebhook ? (
                <FormField
                  control={form.control}
                  name="webhook_ids"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Select Webhooks</FormLabel>
                      <FormControl>
                        <Select
                          value={field.value?.[0]?.toString() || ""}
                          onValueChange={(value) => field.onChange(value ? [Number(value)] : [])}
                        >
                          <SelectTrigger>
                            <SelectValue placeholder="Choose a webhook..." />
                          </SelectTrigger>
                          <SelectContent>
                            {webhooks
                              .filter(w => w.is_active)
                              .map((webhook) => (
                                <SelectItem key={webhook.id} value={webhook.id!.toString()}>
                                  {webhook.name} ({webhook.webhook_type.toUpperCase()})
                                </SelectItem>
                              ))}
                          </SelectContent>
                        </Select>
                      </FormControl>
                      <FormDescription>
                        Choose from your saved encrypted webhooks
                        {webhooks.filter(w => w.is_active).length === 0 && (
                          <span className="text-orange-500"> - No active webhooks found. Create one in the Webhooks tab.</span>
                        )}
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              ) : (
                <FormField
                  control={form.control}
                  name="discord_webhook"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Discord Webhook URL</FormLabel>
                      <FormControl>
                        <Input placeholder="https://discord.com/api/webhooks/..." {...field} />
                      </FormControl>
                      <FormDescription>
                        Direct webhook URL (not encrypted)
                      </FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              )}
            </div>

            <div className="grid grid-cols-3 gap-4">
              <FormField
                control={form.control}
                name="stattrak"
                render={({ field }) => (
                  <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4">
                    <div className="space-y-0.5">
                      <FormLabel className="text-base">StatTrak™</FormLabel>
                      <FormDescription>
                        Only StatTrak™ versions
                      </FormDescription>
                    </div>
                    <FormControl>
                      <Switch
                        checked={field.value}
                        onCheckedChange={field.onChange}
                      />
                    </FormControl>
                  </FormItem>
                )}
              />
              
              <FormField
                control={form.control}
                name="souvenir"
                render={({ field }) => (
                  <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4">
                    <div className="space-y-0.5">
                      <FormLabel className="text-base">Souvenir</FormLabel>
                      <FormDescription>
                        Only souvenir versions
                      </FormDescription>
                    </div>
                    <FormControl>
                      <Switch
                        checked={field.value}
                        onCheckedChange={field.onChange}
                      />
                    </FormControl>
                  </FormItem>
                )}
              />
              
              <FormField
                control={form.control}
                name="enabled"
                render={({ field }) => (
                  <FormItem className="flex flex-row items-center justify-between rounded-lg border p-4">
                    <div className="space-y-0.5">
                      <FormLabel className="text-base">Enabled</FormLabel>
                      <FormDescription>
                        Rule is active
                      </FormDescription>
                    </div>
                    <FormControl>
                      <Switch
                        checked={field.value}
                        onCheckedChange={field.onChange}
                      />
                    </FormControl>
                  </FormItem>
                )}
              />
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button type="submit" disabled={isSubmitting}>
                {isSubmitting ? 'Saving...' : isEditing ? 'Update Rule' : 'Create Rule'}
              </Button>
            </DialogFooter>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  )
}