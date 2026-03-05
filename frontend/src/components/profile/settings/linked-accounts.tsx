'use client'

import { useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ShieldCheck } from 'lucide-react'
import { apiClient } from '@/lib/api'
import { PROVIDER_META } from '@/lib/oauth-icons'
import { extractErrorMessage } from '@/lib/utils'
import { useToast } from '@/hooks/use-toast'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'
import { LinkedAccountsSkeleton } from '@/components/ui/skeletons'
import { LoadingSpinner } from '@/components/ui/loading-spinner'

export function LinkedAccounts() {
  const { toast } = useToast()
  const [unlinking, setUnlinking] = useState<string | null>(null)
  const [confirmUnlink, setConfirmUnlink] = useState<string | null>(null)
  const [confirmLink, setConfirmLink] = useState<string | null>(null)

  const lastUnlinkProvider = useRef<string>('')
  const lastLinkProvider = useRef<string>('')
  if (confirmUnlink) lastUnlinkProvider.current = confirmUnlink
  if (confirmLink) lastLinkProvider.current = confirmLink

  const unlinkLabel = PROVIDER_META[lastUnlinkProvider.current]?.label ?? lastUnlinkProvider.current
  const linkLabel = PROVIDER_META[lastLinkProvider.current]?.label ?? lastLinkProvider.current

  const { data: enabledProviders, isLoading: isLoadingProviders } = useQuery({
    queryKey: ['oauth-providers'],
    queryFn: async () => {
      const res = await apiClient.getOAuthProviders()
      return res.success ? (res.data?.providers ?? []) : []
    },
    staleTime: 5 * 60 * 1000,
  })

  const { data: accounts, refetch } = useQuery({
    queryKey: ['oauth-accounts'],
    queryFn: async () => {
      const res = await apiClient.getOAuthAccounts()
      return res.success ? (res.data ?? []) : []
    },
    staleTime: 30_000,
  })

  const handleUnlink = async (provider: string) => {
    setUnlinking(provider)
    try {
      const res = await apiClient.unlinkOAuthAccount(provider)
      if (res.success) {
        toast({
          title: '✅ Account unlinked',
          description: `${PROVIDER_META[provider]?.label ?? provider} account has been unlinked.`,
        })
        void refetch()
      } else {
        toast({
          variant: 'destructive',
          title: '❌ Unlink failed',
          description: res.message || 'Could not unlink account.',
        })
      }
    } catch (error) {
      toast({
        variant: 'destructive',
        title: '❌ Unlink failed',
        description: extractErrorMessage(error, 'Could not unlink account.'),
      })
    } finally {
      setUnlinking(null)
    }
  }

  const handleLink = (provider: string) => {
    window.location.href = apiClient.getOAuthLoginUrl(provider)
  }

  const linkedProviders = useMemo(
    () => new Set((accounts ?? []).map((account) => account.provider)),
    [accounts]
  )

  if (isLoadingProviders) return <LinkedAccountsSkeleton />
  if (!enabledProviders || enabledProviders.length === 0) return null

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <ShieldCheck className="h-5 w-5" /> Linked Accounts
        </CardTitle>
        <CardDescription>Manage your social login connections</CardDescription>
      </CardHeader>
      <CardContent className="mt-2 space-y-2">
        {enabledProviders.map((provider) => {
          const meta = PROVIDER_META[provider] ?? { label: provider, icon: null }
          const isLinked = linkedProviders.has(provider)
          const account = (accounts ?? []).find((entry) => entry.provider === provider)

          return (
            <div key={provider} className="flex items-center justify-between rounded-lg border p-3">
              <div className="flex items-center gap-3">
                <div className="flex items-center justify-center h-9 w-9 rounded-md bg-muted/50 shrink-0">
                  {meta.icon}
                </div>
                <div>
                  <p className="text-sm font-medium">{meta.label}</p>
                  {isLinked && account?.provider_email && (
                    <p className="text-xs text-muted-foreground">{account.provider_email}</p>
                  )}
                </div>
              </div>
              {isLinked ? (
                <Button
                  variant="outline"
                  size="sm"
                  disabled={unlinking === provider}
                  onClick={() => setConfirmUnlink(provider)}
                >
                  {unlinking === provider ? <LoadingSpinner size="sm" inline /> : 'Unlink'}
                </Button>
              ) : (
                <Button variant="outline" size="sm" onClick={() => setConfirmLink(provider)}>
                  Link
                </Button>
              )}
            </div>
          )
        })}
      </CardContent>

      <ConfirmDialog
        open={!!confirmUnlink}
        onOpenChange={(open) => {
          if (!open) setConfirmUnlink(null)
        }}
        title="Unlink account?"
        description={`Are you sure you want to unlink your ${unlinkLabel} account? You can always re-link it later.`}
        confirmText="Unlink"
        variant="destructive"
        onConfirm={() => {
          if (confirmUnlink) void handleUnlink(confirmUnlink)
        }}
      />

      <ConfirmDialog
        open={!!confirmLink}
        onOpenChange={(open) => {
          if (!open) setConfirmLink(null)
        }}
        title={`Link ${linkLabel} account?`}
        description={`You will be redirected to ${linkLabel} to authorize your account. You can unlink it at any time.`}
        confirmText="Continue"
        onConfirm={() => {
          if (confirmLink) handleLink(confirmLink)
        }}
      />
    </Card>
  )
}
