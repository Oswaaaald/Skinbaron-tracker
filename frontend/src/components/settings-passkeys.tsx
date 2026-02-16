'use client'

import { useState, useCallback } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { startRegistration } from '@simplewebauthn/browser'
import { QUERY_KEYS } from '@/lib/constants'
import { apiClient, type PasskeyInfo } from '@/lib/api'
import { extractErrorMessage } from '@/lib/utils'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { ConfirmDialog } from '@/components/ui/confirm-dialog'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { AlertCircle, CheckCircle, Cloud, Key, Monitor, Pencil, Plus, Trash2, Usb } from 'lucide-react'
import { useAuth } from '@/contexts/auth-context'
import { useToast } from '@/hooks/use-toast'

function formatDate(iso: string | null): string {
  if (!iso) return 'Never'
  const d = new Date(iso)
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
}

function DeviceIcon({ deviceType, backedUp }: { deviceType: string; backedUp: boolean }) {
  if (deviceType === 'singleDevice') return <Usb className="h-5 w-5 text-amber-500" />
  if (backedUp) return <Cloud className="h-5 w-5 text-blue-500" />
  return <Monitor className="h-5 w-5 text-muted-foreground" />
}

function DeviceBadge({ deviceType, backedUp }: { deviceType: string; backedUp: boolean }) {
  if (deviceType === 'singleDevice') {
    return <Badge variant="outline" className="text-xs shrink-0 border-amber-500/30 text-amber-600 dark:text-amber-400">Hardware key</Badge>
  }
  if (backedUp) {
    return <Badge variant="secondary" className="text-xs shrink-0">Synced</Badge>
  }
  return <Badge variant="outline" className="text-xs shrink-0">Device-bound</Badge>
}

export function PasskeyManager() {
  const { isReady, isAuthenticated } = useAuth()
  const { toast } = useToast()
  const queryClient = useQueryClient()

  const [registering, setRegistering] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  // Rename state
  const [renameDialog, setRenameDialog] = useState(false)
  const [renameTarget, setRenameTarget] = useState<PasskeyInfo | null>(null)
  const [renameName, setRenameName] = useState('')
  const [renaming, setRenaming] = useState(false)

  // Delete state
  const [deleteTarget, setDeleteTarget] = useState<PasskeyInfo | null>(null)

  const { data: passkeys, isLoading } = useQuery({
    queryKey: [QUERY_KEYS.PASSKEYS],
    queryFn: async () => {
      const res = await apiClient.getPasskeys()
      return res.success ? (res.data ?? []) : []
    },
    enabled: isReady && isAuthenticated,
    staleTime: 30_000,
  })

  const invalidate = useCallback(() => {
    void queryClient.invalidateQueries({ queryKey: [QUERY_KEYS.PASSKEYS] })
    void queryClient.invalidateQueries({ queryKey: [QUERY_KEYS.USER_AUDIT_LOGS] })
  }, [queryClient])

  const handleRegister = async () => {
    setError(null)
    setSuccess(null)
    setRegistering(true)
    try {
      const optionsRes = await apiClient.getPasskeyRegisterOptions()
      if (!optionsRes.success || !optionsRes.data) {
        setError(optionsRes.message || 'Failed to get registration options')
        return
      }

      // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment
      const attResp = await startRegistration({ optionsJSON: optionsRes.data as any })

      // Backend auto-detects the name from AAGUID (e.g. "iCloud Keychain", "Dashlane")
      const verifyRes = await apiClient.verifyPasskeyRegistration(attResp)
      if (!verifyRes.success) {
        setError(verifyRes.message || 'Passkey verification failed')
        return
      }

      setSuccess('Passkey registered successfully!')
      toast({ title: '✅ Passkey registered', description: `"${verifyRes.data?.name ?? 'Passkey'}" has been added to your account.` })
      invalidate()
    } catch (err: unknown) {
      // User cancelled the ceremony
      if (err instanceof Error && (err.name === 'NotAllowedError' || err.name === 'AbortError')) {
        // Silently ignore
        return
      }
      setError(extractErrorMessage(err, 'Failed to register passkey'))
    } finally {
      setRegistering(false)
    }
  }

  const handleRename = async () => {
    if (!renameTarget || !renameName.trim()) return
    setRenaming(true)
    try {
      const res = await apiClient.renamePasskey(renameTarget.id, renameName.trim())
      if (res.success) {
        toast({ title: '✅ Passkey renamed', description: `Passkey renamed to "${renameName.trim()}"` })
        invalidate()
        setRenameDialog(false)
        setRenameTarget(null)
        setRenameName('')
      } else {
        toast({ variant: 'destructive', title: '❌ Rename failed', description: res.message || 'Could not rename passkey' })
      }
    } catch (err) {
      toast({ variant: 'destructive', title: '❌ Rename failed', description: extractErrorMessage(err, 'Could not rename passkey') })
    } finally {
      setRenaming(false)
    }
  }

  const handleDelete = async () => {
    if (!deleteTarget) return
    try {
      const res = await apiClient.deletePasskey(deleteTarget.id)
      if (res.success) {
        toast({ title: '✅ Passkey deleted', description: `"${deleteTarget.name}" has been removed.` })
        invalidate()
        setDeleteTarget(null)
      } else {
        toast({ variant: 'destructive', title: '❌ Delete failed', description: res.message || 'Could not delete passkey' })
      }
    } catch (err) {
      toast({ variant: 'destructive', title: '❌ Delete failed', description: extractErrorMessage(err, 'Could not delete passkey') })
    }
  }

  return (
    <div className="mt-2 space-y-4">
      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {success && (
        <Alert className="border-primary/50 bg-primary/10">
          <CheckCircle className="h-4 w-4 text-primary" />
          <AlertDescription className="text-primary">{success}</AlertDescription>
        </Alert>
      )}

      {/* List existing passkeys */}
      {isLoading ? (
        <div className="flex items-center justify-center py-6">
          <LoadingSpinner size="sm" />
        </div>
      ) : passkeys && passkeys.length > 0 ? (
        <div className="space-y-2">
          {passkeys.map((pk) => (
            <div key={pk.id} className="flex items-center justify-between rounded-lg border p-3">
              <div className="flex items-center gap-3 min-w-0">
                <div className="flex items-center justify-center h-9 w-9 rounded-md bg-muted/50 shrink-0">
                  <DeviceIcon deviceType={pk.device_type} backedUp={pk.backed_up} />
                </div>
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-medium truncate">{pk.name}</p>
                    <DeviceBadge deviceType={pk.device_type} backedUp={pk.backed_up} />
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Added {formatDate(pk.created_at)}
                    {pk.last_used_at && <> · Last used {formatDate(pk.last_used_at)}</>}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-1 shrink-0 ml-2">
                <Button variant="ghost" size="icon" className="h-8 w-8" onClick={() => { setRenameTarget(pk); setRenameName(pk.name); setRenameDialog(true) }}>
                  <Pencil className="h-3.5 w-3.5" />
                </Button>
                <Button variant="ghost" size="icon" className="h-8 w-8 text-destructive hover:text-destructive" onClick={() => setDeleteTarget(pk)}>
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="text-center py-6 text-muted-foreground">
          <Key className="h-8 w-8 mx-auto mb-2 opacity-50" />
          <p className="text-sm">No passkeys registered yet</p>
          <p className="text-xs mt-1">Add a passkey or hardware key for passwordless sign-in</p>
        </div>
      )}

      <Button onClick={() => void handleRegister()} disabled={registering} className="w-full sm:w-auto">
        {registering ? (
          <><LoadingSpinner size="sm" inline className="mr-2" /> Registering...</>
        ) : (
          <><Plus className="h-4 w-4 mr-2" /> Add Passkey</>
        )}
      </Button>

      {/* Rename Dialog */}
      <Dialog open={renameDialog} onOpenChange={(open) => { if (!open) { setRenameDialog(false); setRenameTarget(null); setRenameName('') } }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rename Passkey</DialogTitle>
            <DialogDescription>Give this passkey a memorable name</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="passkey-name">Name</Label>
              <Input
                id="passkey-name"
                value={renameName}
                onChange={(e) => setRenameName(e.target.value)}
                placeholder="e.g. MacBook Touch ID, YubiKey 5"
                maxLength={64}
                onKeyDown={(e) => { if (e.key === 'Enter') void handleRename() }}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => { setRenameDialog(false); setRenameTarget(null); setRenameName('') }}>Cancel</Button>
            <Button onClick={() => void handleRename()} disabled={renaming || !renameName.trim()}>
              {renaming ? <><LoadingSpinner size="sm" inline /> <span className="ml-2">Saving...</span></> : 'Save'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirm */}
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={(open) => { if (!open) setDeleteTarget(null) }}
        title="Delete passkey?"
        description={`Are you sure you want to delete "${deleteTarget?.name ?? 'this passkey'}"? You won't be able to log in with it anymore.`}
        confirmText="Delete"
        variant="destructive"
        onConfirm={() => void handleDelete()}
      />
    </div>
  )
}
