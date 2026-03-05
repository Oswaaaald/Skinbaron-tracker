'use client'

import { useEffect, useRef, useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import { useQuery } from '@tanstack/react-query'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { Form } from '@/components/ui/form'
import { apiClient, type CreateRuleData, type Rule } from '@/lib/api'
import { QUERY_KEYS } from '@/lib/constants'
import { extractErrorMessage } from '@/lib/utils'
import { percentageToWear, wearToPercentage } from '@/lib/wear-utils'
import { useApiMutation } from '@/hooks/use-api-mutation'
import { useNumericInputHandlers } from '@/hooks/use-numeric-input'
import { useSyncStats } from '@/hooks/use-sync-stats'
import { useToast } from '@/hooks/use-toast'
import {
  defaultRuleFormValues,
  ruleFormSchema,
  type RuleFormData,
} from '@/components/rule-dialog/schema'
import {
  RuleDialogMainFields,
  RuleDialogWebhookAndStatus,
} from '@/components/rule-dialog/form-sections'

interface RuleDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  rule?: Rule | null
}

export function RuleDialog({ open, onOpenChange, rule }: RuleDialogProps) {
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [selectedWebhooks, setSelectedWebhooks] = useState<number[]>([])
  const [minPriceDisplay, setMinPriceDisplay] = useState('')
  const [maxPriceDisplay, setMaxPriceDisplay] = useState('')
  const [minWearDisplay, setMinWearDisplay] = useState('')
  const [maxWearDisplay, setMaxWearDisplay] = useState('')
  const hasPreselectedWebhooks = useRef(false)

  const { syncStats } = useSyncStats()
  const { toast } = useToast()
  const isEditing = !!rule

  const { data: webhooks = [] } = useQuery({
    queryKey: [QUERY_KEYS.WEBHOOKS],
    queryFn: async () => {
      const result = await apiClient.getWebhooks(false)
      if (!result.success) throw new Error(result.error)
      return result.data || []
    },
    enabled: open,
  })

  const form = useForm<RuleFormData>({
    resolver: zodResolver(ruleFormSchema),
    defaultValues: defaultRuleFormValues,
  })

  useEffect(() => {
    if (open && rule) {
      form.reset({
        search_item: rule.search_item || '',
        min_price: rule.min_price !== undefined && rule.min_price !== null ? rule.min_price : undefined,
        max_price: rule.max_price !== undefined && rule.max_price !== null ? rule.max_price : undefined,
        min_wear: rule.min_wear !== undefined && rule.min_wear !== null ? wearToPercentage(rule.min_wear) : undefined,
        max_wear: rule.max_wear !== undefined && rule.max_wear !== null ? wearToPercentage(rule.max_wear) : undefined,
        stattrak_filter: rule.stattrak_filter || 'all',
        souvenir_filter: rule.souvenir_filter || 'all',
        sticker_filter: rule.sticker_filter || 'all',
        webhook_ids: rule.webhook_ids || [],
        enabled: rule.enabled ?? true,
      })
      // eslint-disable-next-line react-hooks/set-state-in-effect -- Syncing selected webhooks from edited rule
      setSelectedWebhooks(rule.webhook_ids || [])
      setMinPriceDisplay(
        rule.min_price !== undefined && rule.min_price !== null
          ? (Math.round(rule.min_price * 100) / 100).toString()
          : ''
      )
      setMaxPriceDisplay(
        rule.max_price !== undefined && rule.max_price !== null
          ? (Math.round(rule.max_price * 100) / 100).toString()
          : ''
      )
      const minWearPct =
        rule.min_wear !== undefined && rule.min_wear !== null ? wearToPercentage(rule.min_wear) : undefined
      const maxWearPct =
        rule.max_wear !== undefined && rule.max_wear !== null ? wearToPercentage(rule.max_wear) : undefined
      setMinWearDisplay(minWearPct !== undefined ? minWearPct.toString() : '')
      setMaxWearDisplay(maxWearPct !== undefined ? maxWearPct.toString() : '')
      return undefined
    }

    if (!open) {
      const timeout = setTimeout(() => {
        form.reset(defaultRuleFormValues)
        setSelectedWebhooks([])
        hasPreselectedWebhooks.current = false
        setMinPriceDisplay('')
        setMaxPriceDisplay('')
        setMinWearDisplay('')
        setMaxWearDisplay('')
      }, 200)

      return () => clearTimeout(timeout)
    }

    return undefined
  }, [open, rule, form])

  useEffect(() => {
    form.setValue('webhook_ids', selectedWebhooks)
  }, [selectedWebhooks, form])

  useEffect(() => {
    if (open && !rule && webhooks.length > 0 && !hasPreselectedWebhooks.current) {
      const allIds = webhooks.map((webhook) => webhook.id).filter((id): id is number => id != null)
      // eslint-disable-next-line react-hooks/set-state-in-effect -- One-time preset from loaded webhooks
      setSelectedWebhooks(allIds)
      hasPreselectedWebhooks.current = true
    }
  }, [open, rule, webhooks])

  const createRuleMutation = useApiMutation(
    (data: CreateRuleData) => apiClient.createRule(data),
    {
      invalidateKeys: [[QUERY_KEYS.RULES], [QUERY_KEYS.ADMIN_STATS]],
      onSuccess: (result) => {
        if (result.success) {
          toast({ title: '✅ Rule created', description: 'Your rule has been created successfully' })
          void syncStats()
          onOpenChange(false)
        } else {
          toast({
            variant: 'destructive',
            title: '❌ Failed to create rule',
            description: result.error || 'Failed to create rule',
          })
        }
        setIsSubmitting(false)
      },
      onError: (error) => {
        toast({
          variant: 'destructive',
          title: '❌ Failed to create rule',
          description: extractErrorMessage(error),
        })
        setIsSubmitting(false)
      },
    }
  )

  const updateRuleMutation = useApiMutation(
    ({ id, data }: { id: number; data: CreateRuleData }) => apiClient.updateRule(id, data),
    {
      invalidateKeys: [[QUERY_KEYS.RULES], [QUERY_KEYS.ADMIN_STATS]],
      onSuccess: (result) => {
        if (result.success) {
          toast({ title: '✅ Rule updated', description: 'Your rule has been updated successfully' })
          void syncStats()
          onOpenChange(false)
        } else {
          toast({
            variant: 'destructive',
            title: '❌ Failed to update rule',
            description: result.error || 'Failed to update rule',
          })
        }
        setIsSubmitting(false)
      },
      onError: (error) => {
        toast({
          variant: 'destructive',
          title: '❌ Failed to update rule',
          description: extractErrorMessage(error),
        })
        setIsSubmitting(false)
      },
    }
  )

  const onSubmit = (data: RuleFormData) => {
    if (isSubmitting) return
    setIsSubmitting(true)

    try {
      const createData: CreateRuleData = {
        search_item: data.search_item,
        min_price: data.min_price !== undefined ? data.min_price : 0,
        max_price: data.max_price || undefined,
        min_wear: data.min_wear !== undefined ? percentageToWear(data.min_wear) : undefined,
        max_wear: data.max_wear !== undefined ? percentageToWear(data.max_wear) : undefined,
        stattrak_filter: data.stattrak_filter,
        souvenir_filter: data.souvenir_filter,
        sticker_filter: data.sticker_filter,
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
        variant: 'destructive',
        title: '❌ Failed to submit rule',
        description: extractErrorMessage(error),
      })
      setIsSubmitting(false)
    }
  }

  const handleWebhookToggle = (webhookId: number) => {
    setSelectedWebhooks((prev) =>
      prev.includes(webhookId) ? prev.filter((id) => id !== webhookId) : [...prev, webhookId]
    )
  }

  const minPriceHandlers = useNumericInputHandlers({ min: 0, onCommit: (v) => form.setValue('min_price', v), setDisplay: setMinPriceDisplay })
  const maxPriceHandlers = useNumericInputHandlers({ min: 0, onCommit: (v) => form.setValue('max_price', v), setDisplay: setMaxPriceDisplay })
  const minWearHandlers = useNumericInputHandlers({ min: 0, max: 100, onCommit: (v) => form.setValue('min_wear', v), setDisplay: setMinWearDisplay })
  const maxWearHandlers = useNumericInputHandlers({ min: 0, max: 100, onCommit: (v) => form.setValue('max_wear', v), setDisplay: setMaxWearDisplay })

  const getSelectedWebhookNames = () => {
    if (!webhooks || !Array.isArray(webhooks)) return ''
    return webhooks
      .filter((webhook) => webhook.id && selectedWebhooks.includes(webhook.id))
      .map((webhook) => webhook.name)
      .join(', ')
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[600px] max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>{isEditing ? 'Edit Rule' : 'Create New Rule'}</DialogTitle>
          <DialogDescription>
            {isEditing
              ? 'Update your alert rule configuration'
              : 'Create a new alert rule to monitor SkinBaron listings'}
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form
            onSubmit={(e) => {
              e.preventDefault()
              void form.handleSubmit(onSubmit)(e)
            }}
            className="space-y-6"
          >
            <RuleDialogMainFields
              form={form}
              isSubmitting={isSubmitting}
              minPriceDisplay={minPriceDisplay}
              maxPriceDisplay={maxPriceDisplay}
              minWearDisplay={minWearDisplay}
              maxWearDisplay={maxWearDisplay}
              minPriceHandlers={minPriceHandlers}
              maxPriceHandlers={maxPriceHandlers}
              minWearHandlers={minWearHandlers}
              maxWearHandlers={maxWearHandlers}
            />

            <RuleDialogWebhookAndStatus
              form={form}
              webhooks={webhooks}
              selectedWebhooks={selectedWebhooks}
              isSubmitting={isSubmitting}
              isEditing={isEditing}
              onOpenChange={onOpenChange}
              onWebhookToggle={handleWebhookToggle}
              getSelectedWebhookNames={getSelectedWebhookNames}
            />
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  )
}
