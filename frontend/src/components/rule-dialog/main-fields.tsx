'use client'

import type { ChangeEvent, FocusEvent, KeyboardEvent } from 'react'
import type { UseFormReturn } from 'react-hook-form'
import {
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { ItemCombobox } from '@/components/ui/item-combobox'
import type { RuleFormData } from '@/components/rule-dialog/schema'

type NumericHandlers = {
  onChange: (e: ChangeEvent<HTMLInputElement>) => void
  onKeyDown: (e: KeyboardEvent<HTMLInputElement>) => void
  onBlur: (e: FocusEvent<HTMLInputElement>) => void
}

interface RuleDialogMainFieldsProps {
  form: UseFormReturn<RuleFormData>
  isSubmitting: boolean
  minPriceDisplay: string
  maxPriceDisplay: string
  minWearDisplay: string
  maxWearDisplay: string
  minPriceHandlers: NumericHandlers
  maxPriceHandlers: NumericHandlers
  minWearHandlers: NumericHandlers
  maxWearHandlers: NumericHandlers
}

export function RuleDialogMainFields({
  form,
  isSubmitting,
  minPriceDisplay,
  maxPriceDisplay,
  minWearDisplay,
  maxWearDisplay,
  minPriceHandlers,
  maxPriceHandlers,
  minWearHandlers,
  maxWearHandlers,
}: RuleDialogMainFieldsProps) {
  return (
    <>
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
                placeholder="Type to search items"
                disabled={isSubmitting}
              />
            </FormControl>
            <FormDescription>Search and select an item from SkinBaron</FormDescription>
            <FormMessage />
          </FormItem>
        )}
      />

      <div className="grid grid-cols-2 gap-4">
        <FormField
          control={form.control}
          name="min_price"
          render={() => (
            <FormItem>
              <FormLabel>Min Price (€)</FormLabel>
              <FormControl>
                <Input type="text" placeholder="ex: 10.50" value={minPriceDisplay} {...minPriceHandlers} disabled={isSubmitting} />
              </FormControl>
              <FormDescription>Minimum price in euros. Leave blank to ignore.</FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="max_price"
          render={() => (
            <FormItem>
              <FormLabel>Max Price (€)</FormLabel>
              <FormControl>
                <Input type="text" placeholder="ex: 50" value={maxPriceDisplay} {...maxPriceHandlers} disabled={isSubmitting} />
              </FormControl>
              <FormDescription>Maximum price in euros. Leave blank to ignore.</FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <FormField
          control={form.control}
          name="min_wear"
          render={() => (
            <FormItem>
              <FormLabel>Min Wear (0-100%)</FormLabel>
              <FormControl>
                <Input type="text" placeholder="ex: 15" value={minWearDisplay} {...minWearHandlers} disabled={isSubmitting} />
              </FormControl>
              <FormDescription>Between 0 and 100. Leave blank to ignore.</FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="max_wear"
          render={() => (
            <FormItem>
              <FormLabel>Max Wear (0-100%)</FormLabel>
              <FormControl>
                <Input type="text" placeholder="ex: 85" value={maxWearDisplay} {...maxWearHandlers} disabled={isSubmitting} />
              </FormControl>
              <FormDescription>Between 0 and 100. Leave blank to ignore.</FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
      </div>

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
                    <SelectTrigger><SelectValue placeholder="Select..." /></SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    <SelectItem value="all">✓ Accept all</SelectItem>
                    <SelectItem value="only">⭐ Only StatTrak™</SelectItem>
                    <SelectItem value="exclude">🚫 Exclude StatTrak™</SelectItem>
                  </SelectContent>
                </Select>
                <FormDescription>Filter StatTrak™ items</FormDescription>
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
                    <SelectTrigger><SelectValue placeholder="Select..." /></SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    <SelectItem value="all">✓ Accept all</SelectItem>
                    <SelectItem value="only">🏆 Only Souvenir</SelectItem>
                    <SelectItem value="exclude">🚫 Exclude Souvenir</SelectItem>
                  </SelectContent>
                </Select>
                <FormDescription>Filter Souvenir items</FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <FormField
            control={form.control}
            name="sticker_filter"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Stickers</FormLabel>
                <Select onValueChange={field.onChange} defaultValue={field.value} value={field.value} disabled={isSubmitting}>
                  <FormControl>
                    <SelectTrigger><SelectValue placeholder="Select sticker filter" /></SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    <SelectItem value="all">✓ Accept all</SelectItem>
                    <SelectItem value="only">⭐ Only with Stickers</SelectItem>
                    <SelectItem value="exclude">🚫 Exclude Stickers</SelectItem>
                  </SelectContent>
                </Select>
                <FormDescription>Filter items with stickers</FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
        </div>
      </div>
    </>
  )
}
