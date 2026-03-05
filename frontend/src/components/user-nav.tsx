'use client'

import Image from 'next/image'
import Link from 'next/link'
import { useAuth } from '@/contexts/auth-context'
import { Button } from '@/components/ui/button'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { LogOut, Settings } from 'lucide-react'

export function UserNav() {
  const { user, logout } = useAuth()

  if (!user) return null

  const userInitials = user.username
    .split(' ')
    .map(name => name[0])
    .join('')
    .toUpperCase()
    .slice(0, 2)

  return (
    <div className="flex items-center gap-2.5">
      <div className="hidden lg:flex flex-col text-right leading-tight">
        <span className="text-xs text-muted-foreground">Signed in as</span>
        <span className="text-sm font-medium">{user.username}</span>
      </div>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="ghost"
            size="sm"
            className="h-9 w-9 rounded-full p-0 overflow-hidden border border-border/70 bg-background/80 hover:border-primary/50 transition-all"
          >
            {user.avatar_url ? (
              <Image 
                src={user.avatar_url} 
                alt={user.username}
                width={36}
                height={36}
                className="h-full w-full object-cover"
                priority
              />
            ) : (
              <span className="flex h-full w-full items-center justify-center bg-gradient-to-br from-primary/90 to-cyan-500/80 text-xs font-semibold text-primary-foreground">
                {userInitials}
              </span>
            )}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent className="w-60 rounded-xl border-border/70" align="end">
          <DropdownMenuLabel className="font-normal">
            <div className="flex flex-col space-y-1">
              <p className="text-sm font-medium leading-none">{user.username}</p>
              <p className="text-xs leading-none text-muted-foreground">
                {user.email}
              </p>
            </div>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem asChild>
            <Link href="/settings" className="cursor-pointer">
              <Settings className="mr-2 h-4 w-4" />
              <span>Settings</span>
            </Link>
          </DropdownMenuItem>
          <DropdownMenuItem onClick={() => { void logout() }} className="text-destructive focus:text-destructive">
            <LogOut className="mr-2 h-4 w-4" />
            <span>Log out</span>
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  )
}
