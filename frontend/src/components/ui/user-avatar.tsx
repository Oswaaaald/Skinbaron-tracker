'use client'

import { useState } from 'react'
import Image from 'next/image'
import { cn } from '@/lib/utils'
import { User } from 'lucide-react'
import { Skeleton } from '@/components/ui/skeleton'

interface UserAvatarProps {
  src: string | null | undefined
  alt?: string
  fallback?: string
  /** Pixel size (width & height). Defaults to 28. */
  size?: number
  className?: string
}

/**
 * Avatar with skeleton placeholder that fades in when loaded.
 * Shows a muted User icon when no src is provided.
 */
export function UserAvatar({ src, alt = '', fallback, size = 28, className }: UserAvatarProps) {
  const [loaded, setLoaded] = useState(false)

  const style = { width: size, height: size }

  if (!src) {
    return (
      <span
        className={cn('rounded-full bg-muted flex items-center justify-center shrink-0', className)}
        style={style}
      >
        {fallback ? (
          <span className="font-semibold text-muted-foreground" style={{ fontSize: size * 0.35 }}>
            {fallback}
          </span>
        ) : (
          <User className="text-muted-foreground" style={{ width: size * 0.5, height: size * 0.5 }} />
        )}
      </span>
    )
  }

  return (
    <span className={cn('relative rounded-full overflow-hidden shrink-0 block', className)} style={style}>
      {/* Skeleton shown until image loads */}
      {!loaded && <Skeleton className="absolute inset-0 rounded-full" />}
      <Image
        src={src}
        alt={alt}
        width={size}
        height={size}
        sizes={`${size}px`}
        className={cn(
          'h-full w-full object-cover transition-opacity duration-200',
          loaded ? 'opacity-100' : 'opacity-0',
        )}
        onLoad={() => setLoaded(true)}
      />
    </span>
  )
}
