import { LoadingSpinner } from '@/components/ui/loading-spinner'

type LoadingVariant = 'page' | 'section' | 'card' | 'inline'

interface LoadingStateProps {
  /** 
   * page: min-h-screen centered (route-level)
   * section: min-h-[400px] centered (tab content)
   * card: py-12 centered (inside a card)
   * inline: py-8 centered, no text (compact)
   */
  variant?: LoadingVariant
  /** Override the default "Loading..." text */
  message?: string
}

const variantClasses: Record<LoadingVariant, string> = {
  page: 'min-h-screen flex flex-col items-center justify-center',
  section: 'min-h-[400px] flex flex-col items-center justify-center',
  card: 'flex flex-col items-center justify-center py-12',
  inline: 'flex justify-center py-8',
}

/**
 * Centralized loading state component — replaces 17 duplicated spinner patterns.
 */
export function LoadingState({ variant = 'card', message = 'Loading...' }: LoadingStateProps) {
  if (variant === 'inline') {
    return (
      <div className={variantClasses.inline} role="status" aria-live="polite">
        <LoadingSpinner />
      </div>
    )
  }

  return (
    <div className={variantClasses[variant]} role="status" aria-live="polite">
      <LoadingSpinner size="lg" />
      <p className="text-muted-foreground mt-2">{message}</p>
    </div>
  )
}
