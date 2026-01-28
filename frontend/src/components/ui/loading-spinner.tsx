import { cn } from "@/lib/utils"

interface LoadingSpinnerProps {
  className?: string
  size?: "sm" | "md" | "lg"
  inline?: boolean
}

export function LoadingSpinner({ className, size = "md", inline = false }: LoadingSpinnerProps) {
  const sizes = {
    sm: "h-4 w-4 border-b-2",
    md: "h-8 w-8 border-b-2",
    lg: "h-12 w-12 border-b-2"
  }

  // Mode inline pour les boutons : pas de wrapper, couleur adaptée au bouton
  if (inline) {
    return (
      <span
        className={cn(
          "animate-spin rounded-full border-2 border-current border-t-transparent inline-block align-middle shrink-0",
          sizes[size],
          className
        )}
      />
    )
  }

  // Mode normal pour les pages : avec wrapper et couleur primary
  return (
    <div className="flex items-center justify-center p-4">
      <div
        className={cn(
          "animate-spin rounded-full border-2 border-primary border-t-transparent",
          sizes[size],
          className
        )}
      />
    </div>
  )
}