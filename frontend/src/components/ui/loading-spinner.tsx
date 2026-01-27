import { cn } from "@/lib/utils"

interface LoadingSpinnerProps {
  className?: string
  size?: "sm" | "md" | "lg"
}

export function LoadingSpinner({ className, size = "md" }: LoadingSpinnerProps) {
  const sizes = {
    sm: "h-4 w-4 border-b",
    md: "h-8 w-8 border-b-2",
    lg: "h-12 w-12 border-b-2"
  }

  return (
    <div className="flex items-center justify-center p-4">
      <div
        className={cn(
          "animate-spin rounded-full border-primary",
          sizes[size],
          className
        )}
      />
    </div>
  )
}