'use client'

import Image from 'next/image'
import { useAuth } from '@/contexts/auth-context'
import { Button } from '@/components/ui/button'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { LogOut } from 'lucide-react'

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
    <div className="flex items-center gap-4">
      <span className="hidden sm:inline text-sm text-muted-foreground">
        Welcome, {user.username}
      </span>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="sm" className="h-8 w-8 rounded-full p-0 overflow-hidden">
            {user.avatar_url ? (
              <Image 
                src={user.avatar_url} 
                alt={user.username}
                width={32}
                height={32}
                className="h-full w-full object-cover"
                priority
              />
            ) : (
              <span className="text-xs font-medium">{userInitials}</span>
            )}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent className="w-56" align="end">
          <DropdownMenuLabel className="font-normal">
            <div className="flex flex-col space-y-1">
              <p className="text-sm font-medium leading-none">{user.username}</p>
              <p className="text-xs leading-none text-muted-foreground">
                {user.email}
              </p>
            </div>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={logout} className="text-red-600 focus:text-red-600">
            <LogOut className="mr-2 h-4 w-4" />
            <span>Log out</span>
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  )
}