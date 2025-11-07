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
import { toast } from "sonner"
import { apiClient, type Rule } from "@/lib/api"

const ruleFormSchema = z.object({
  user_id: z.string().min(1, "User ID is required"),
  search_item: z.string().min(1, "Search item is required"),
  min_price: z.number().positive().optional().or(z.literal(0)),
  max_price: z.number().positive().optional().or(z.literal(0)),
  min_wear: z.number().min(0).max(1).optional(),
  max_wear: z.number().min(0).max(1).optional(),
  stattrak: z.boolean().optional(),
  souvenir: z.boolean().optional(),
  discord_webhook: z.string().url("Invalid webhook URL"),
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
  const queryClient = useQueryClient()
  const isEditing = !!rule

  const form = useForm<RuleFormData>({
    resolver: zodResolver(ruleFormSchema),
    defaultValues: {
      user_id: "",
      search_item: "",
      min_price: 0,
      max_price: 0,
      min_wear: undefined,
      max_wear: undefined,
      stattrak: false,
      souvenir: false,
      discord_webhook: "",
      enabled: true,
    },
  })

  // Reset form when dialog opens/closes or rule changes
  useEffect(() => {
    if (open) {
      if (rule) {
        // Editing existing rule
        form.reset({
          user_id: rule.user_id,
          search_item: rule.search_item,
          min_price: rule.min_price || 0,
          max_price: rule.max_price || 0,
          min_wear: rule.min_wear,
          max_wear: rule.max_wear,
          stattrak: rule.stattrak || false,
          souvenir: rule.souvenir || false,
          discord_webhook: rule.discord_webhook,
          enabled: rule.enabled ?? true,
        })
      } else {
        // Creating new rule
        form.reset({
          user_id: "",
          search_item: "",
          min_price: 0,
          max_price: 0,
          min_wear: undefined,
          max_wear: undefined,
          stattrak: false,
          souvenir: false,
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
    setIsSubmitting(true)
    
    // Convert empty numbers to undefined
    const processedData = {
      ...data,
      min_price: data.min_price === 0 ? undefined : data.min_price,
      max_price: data.max_price === 0 ? undefined : data.max_price,
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
                name="user_id"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>User ID</FormLabel>
                    <FormControl>
                      <Input placeholder="e.g., user123" {...field} />
                    </FormControl>
                    <FormDescription>
                      Unique identifier for this rule owner
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
              
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
                    Discord webhook URL where alerts will be sent
                  </FormDescription>
                  <FormMessage />
                </FormItem>
              )}
            />

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