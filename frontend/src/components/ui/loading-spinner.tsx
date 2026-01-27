import { cn } from "@/lib/utils"

interface LoadingSpinnerProps {
  className?: string
  size?: "sm" | "md" | "lg"
  inline?: boolean
}

export function LoadingSpinner({ className, size = "md", inline = false }: LoadingSpinnerProps) {
  const sizes = {
    sm: "h-4 w-4 border-b",
    md: "h-8 w-8 border-b-2",
    lg: "h-12 w-12 border-b-2"
  }

  const spinner = (
    <div
      className={cn(
        "animate-spin rounded-full border-primary",
        sizes[size],
        className
      )}
    />
  )

  if (inline) {
    return spinner
  }

  return (
    <div className="flex items-center justify-center p-4">
      {spinner}
    </div>
  )
}