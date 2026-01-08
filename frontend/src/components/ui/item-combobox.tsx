"use client"

import * as React from "react"
import { Check, ChevronsUpDown, Loader2 } from "lucide-react"
import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import {
  Command,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command"
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover"
import { useDebounce } from "@/hooks/use-debounce"
import { apiClient } from "@/lib/api"

interface ItemSuggestion {
  name: string
  imageUrl?: string
}

interface ItemComboboxProps {
  value?: string
  onValueChange: (value: string) => void
  placeholder?: string
  disabled?: boolean
}

export function ItemCombobox({
  value,
  onValueChange,
  placeholder = "Search for an item...",
  disabled = false,
}: ItemComboboxProps) {
  const [open, setOpen] = React.useState(false)
  const [searchQuery, setSearchQuery] = React.useState(value || "")
  const [suggestions, setSuggestions] = React.useState<ItemSuggestion[]>([])
  const [isLoading, setIsLoading] = React.useState(false)
  
  const debouncedSearch = useDebounce(searchQuery, 300)

  // Fetch suggestions when search query changes
  React.useEffect(() => {
    const fetchSuggestions = async () => {
      if (!debouncedSearch || debouncedSearch.trim().length < 2) {
        setSuggestions([])
        return
      }

      setIsLoading(true)
      try {
        const result = await apiClient.searchItems(debouncedSearch)
        if (result.success && result.data) {
          setSuggestions(result.data)
        } else {
          setSuggestions([])
        }
      } catch (error) {
        console.error("Failed to fetch item suggestions:", error)
        setSuggestions([])
      } finally {
        setIsLoading(false)
      }
    }

    fetchSuggestions()
  }, [debouncedSearch])

  // Update search query when value prop changes
  React.useEffect(() => {
    if (value !== undefined) {
      setSearchQuery(value)
    }
  }, [value])

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          role="combobox"
          aria-expanded={open}
          className="w-full justify-between h-10 font-normal"
          disabled={disabled}
        >
          <span className="truncate text-left flex-1">
            {value || <span className="text-muted-foreground">{placeholder}</span>}
          </span>
          <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent 
        className="p-0 shadow-lg border-border" 
        align="start"
        sideOffset={4}
        style={{ width: 'var(--radix-popover-trigger-width)' }}
      >
        <Command shouldFilter={false} className="rounded-lg border-0">
          <CommandInput
            placeholder={placeholder}
            value={searchQuery}
            onValueChange={setSearchQuery}
            className="h-11"
          />
          <CommandList className="max-h-[300px] overflow-y-auto touch-auto">
            {isLoading ? (
              <div className="flex items-center justify-center py-6">
                <Loader2 className="h-5 w-5 animate-spin text-primary" />
                <span className="ml-2 text-sm text-muted-foreground">Searching SkinBaron...</span>
              </div>
            ) : (
              <>
                <CommandEmpty className="py-6 text-center text-sm text-muted-foreground">
                  {searchQuery.length < 2
                    ? "Type at least 2 characters to search"
                    : "No items found"}
                </CommandEmpty>
                {suggestions.length > 0 && (
                  <CommandGroup className="p-2">
                    {suggestions.map((item) => (
                      <CommandItem
                        key={item.name}
                        value={item.name}
                        onSelect={(currentValue) => {
                          onValueChange(currentValue)
                          setSearchQuery(currentValue)
                          setOpen(false)
                        }}
                        className="flex items-center gap-2 px-2 py-2.5 cursor-pointer rounded-md hover:bg-accent"
                      >
                        <Check
                          className={cn(
                            "h-4 w-4 shrink-0",
                            value === item.name ? "opacity-100 text-primary" : "opacity-0"
                          )}
                        />
                        {item.imageUrl && (
                          <div className="shrink-0 w-10 h-10 flex items-center justify-center bg-muted rounded">
                            <img
                              src={item.imageUrl}
                              alt={item.name}
                              className="max-w-full max-h-full object-contain"
                            />
                          </div>
                        )}
                        <span className="truncate flex-1 text-sm">{item.name}</span>
                      </CommandItem>
                    ))}
                  </CommandGroup>
                )}
              </>
            )}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  )
}
