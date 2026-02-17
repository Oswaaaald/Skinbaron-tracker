'use client'

import { useState, useEffect } from 'react'
import { useAuth } from '@/contexts/auth-context'
import { useToast } from '@/hooks/use-toast'
import { validateRegistration, validateLogin } from '@/lib/validation'
import { apiClient } from '@/lib/api'
import { PROVIDER_ICONS, PROVIDER_LABELS } from '@/lib/oauth-icons'
import { startAuthentication } from '@simplewebauthn/browser'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { LoadingState } from '@/components/ui/loading-state'
import { Eye, EyeOff, Mail, Lock, User, Shield, Fingerprint } from 'lucide-react'
import Link from 'next/link'

interface AuthFormProps {
  mode: 'login' | 'register'
  onToggleMode: () => void
}

export function AuthForm({ mode, onToggleMode }: AuthFormProps) {
  const { login, register } = useAuth()
  const { toast } = useToast()
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [requires2FA, setRequires2FA] = useState(false)
  const [oauthPending2FA, setOauthPending2FA] = useState(false)
  const [oauthPendingRegistration, setOauthPendingRegistration] = useState(false)
  const [oauthPendingData, setOauthPendingData] = useState<{ email: string; suggested_username: string; provider: string } | null>(null)
  const [totpCode, setTotpCode] = useState('')
  const [oauthProviders, setOAuthProviders] = useState<string[]>([])
  const [oauthReady, setOauthReady] = useState(false)
  
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: '',
    tosAccepted: false,
  })

  // Fetch enabled OAuth providers
  useEffect(() => {
    void (async () => {
      try {
        const res = await apiClient.getOAuthProviders()
        if (res.success && res.data?.providers) {
          setOAuthProviders(res.data.providers)
        }
      } catch {
        // OAuth not available — hide buttons silently
      } finally {
        setOauthReady(true)
      }
    })()
  }, [])

  // Show error from URL params (e.g. ?error=oauth_denied after failed OAuth)
  // Also detect ?oauth_2fa=pending for 2FA challenge after OAuth login
  useEffect(() => {
    if (typeof window === 'undefined') return
    const params = new URLSearchParams(window.location.search)

    // Check for OAuth 2FA pending
    const oauth2fa = params.get('oauth_2fa')
    if (oauth2fa === 'pending') {
      setOauthPending2FA(true)
      // Clean the URL
      const url = new URL(window.location.href)
      url.searchParams.delete('oauth_2fa')
      window.history.replaceState({}, '', url.pathname + url.search)
      return
    }

    // Check for OAuth finalize registration
    const oauthFinalize = params.get('oauth_finalize')
    if (oauthFinalize === 'pending') {
      // Clean the URL immediately
      const url = new URL(window.location.href)
      url.searchParams.delete('oauth_finalize')
      window.history.replaceState({}, '', url.pathname + url.search)

      // Fetch pending registration data from backend cookie
      void (async () => {
        try {
          const res = await apiClient.getOAuthPendingRegistration()
          if (res.success && res.data) {
            setOauthPendingRegistration(true)
            setOauthPendingData(res.data)
            setFormData(prev => ({
              ...prev,
              username: res.data?.suggested_username ?? '',
              email: res.data?.email ?? '',
              tosAccepted: false,
            }))
          } else {
            setError('OAuth registration session expired. Please try again.')
          }
        } catch {
          setError('OAuth registration session expired. Please try again.')
        }
      })()
      return
    }

    const oauthError = params.get('error')
    if (oauthError) {
      const messages: Record<string, string> = {
        oauth_denied: 'OAuth authorization was cancelled.',
        oauth_missing_params: 'OAuth response was incomplete. Please try again.',
        invalid_provider: 'Invalid OAuth provider.',
        oauth_state_missing: 'OAuth session expired. Please try again.',
        oauth_state_invalid: 'OAuth session was invalid. Please try again.',
        oauth_state_mismatch: 'OAuth state mismatch. Please try again.',
        oauth_exchange_failed: 'Failed to complete OAuth sign-in. Please try again.',
        oauth_email_not_verified: 'Your email is not verified with this provider. Please verify it first.',
        oauth_email_taken: 'An account with this email already exists. Please log in with your password, then link this provider from Settings.',
        oauth_user_not_found: 'Associated account not found.',
        oauth_already_linked_other: 'This social account is already linked to another user.',
        pending_approval: 'Your account is awaiting admin approval.',
        account_restricted: 'Your account has been suspended.',
        oauth_no_account: 'No account found with this email. Please register first.',
        rate_limited: 'Too many attempts. Please try again in a moment.',
        oauth_server_error: 'An unexpected error occurred. Please try again.'
      }
      setError(messages[oauthError] || 'OAuth sign-in failed. Please try again.')
      // Clean the URL
      const url = new URL(window.location.href)
      url.searchParams.delete('error')
      window.history.replaceState({}, '', url.pathname + url.search)
    }
  }, [])

  const handleInputChange = (field: string, value: string) => {
    setFormData(prev => ({ ...prev, [field]: value }))
    if (error) setError('')
  }

  const validateForm = () => {
    if (mode === 'register') {
      const result = validateRegistration({
        username: formData.username,
        email: formData.email,
        password: formData.password,
        confirmPassword: formData.confirmPassword,
      })
      
      if (!result.valid) {
        setError(result.error || 'Validation failed')
        return false
      }

      if (!formData.tosAccepted) {
        setError('You must accept the Terms of Service to create an account')
        return false
      }
    } else {
      const result = validateLogin({
        email: formData.email,
        password: formData.password,
      })
      
      if (!result.valid) {
        setError(result.error || 'Validation failed')
        return false
      }
    }

    return true
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    // OAuth finalize registration
    if (oauthPendingRegistration) {
      if (!formData.username || formData.username.trim().length < 3) {
        setError('Username must be at least 3 characters')
        return
      }
      if (formData.username.length > 20) {
        setError('Username must be at most 20 characters')
        return
      }
      if (!/^[a-zA-Z0-9_]+$/.test(formData.username)) {
        setError('Username can only contain letters, numbers and underscores')
        return
      }
      if (!formData.tosAccepted) {
        setError('You must accept the Terms of Service to create an account')
        return
      }

      setIsLoading(true)
      setError('')

      try {
        const result = await apiClient.finalizeOAuthRegistration(formData.username.trim(), formData.tosAccepted)

        if (result.success) {
          if (typeof window !== 'undefined') {
            localStorage.setItem('has_session', 'true')
          }
          toast({
            title: '\u2705 Account created',
            description: 'Your account has been created successfully',
          })
          window.location.href = '/'
        } else {
          setError(result.message || 'Registration failed. Please try again.')
        }
      } catch (err) {
        setError(err instanceof Error ? err.message : 'An unexpected error occurred')
      } finally {
        setIsLoading(false)
      }
      return
    }
    
    // OAuth 2FA verification
    if (oauthPending2FA) {
      if (!totpCode || (totpCode.length !== 6 && totpCode.length !== 8)) {
        setError('Please enter a valid 6-digit code or 8-character recovery code')
        return
      }

      setIsLoading(true)
      setError('')

      try {
        const result = await apiClient.verifyOAuth2FA(totpCode)

        if (result.success) {
          // Set session flag and redirect
          if (typeof window !== 'undefined') {
            localStorage.setItem('has_session', 'true')
          }
          toast({
            title: '✅ Welcome back!',
            description: 'You have been logged in successfully',
          })
          window.location.href = '/'
        } else {
          setError(result.message || 'Invalid 2FA code')
          setTotpCode('')
        }
      } catch {
        setError('An unexpected error occurred')
      } finally {
        setIsLoading(false)
      }
      return
    }

    // For 2FA step, only validate the code
    if (requires2FA) {
      if (!totpCode || (totpCode.length !== 6 && totpCode.length !== 8)) {
        setError('Please enter a valid 6-digit code or 8-character recovery code')
        return
      }
      
      setIsLoading(true)
      setError('')
      
      try {
        const result = await login(formData.email, formData.password, totpCode)
        
        if (!result.success) {
          setError(result.error || 'Invalid 2FA code')
          setTotpCode('') // Clear the code
        }
        // If successful, auth context will handle redirect
      } catch {
        setError('An unexpected error occurred')
      } finally {
        setIsLoading(false)
      }
      return
    }
    
    if (!validateForm()) return
    
    setIsLoading(true)
    setError('')

    try {
      const result: { success: boolean; error?: string; requires2FA?: boolean } = mode === 'login' 
        ? await login(formData.email, formData.password)
        : await register(formData.username, formData.email, formData.password)

      if (!result.success) {
        // Check if 2FA is required
        if (result.requires2FA) {
          setRequires2FA(true)
          setError('') // Clear any previous errors
        } else if (result.error === 'Account pending approval') {
          setError('Your account is awaiting admin approval. Please check back later.')
          toast({
            variant: "destructive",
            title: "❌ Account pending",
            description: "Your account is awaiting admin approval",
          })
        } else {
          // Use backend error messages directly (they're already user-friendly)
          const errorMessage = result.error || `${mode} failed`
          
          setError(errorMessage)
          toast({
            variant: "destructive",
            title: `❌ ${mode === 'login' ? 'Login' : 'Registration'} failed`,
            description: errorMessage,
          })
        }
      } else {
        // Success toast
        if (mode === 'login') {
          toast({
            title: "✅ Welcome back!",
            description: "You have been logged in successfully",
          })
        }
        
        if (mode === 'register') {
        // Registration successful but pending approval
        if (result.error && result.error.includes('awaiting admin approval')) {
          setError('Registration successful! Your account is awaiting admin approval.')
          toast({
            title: "✅ Account created",
            description: "Your account is awaiting admin approval",
          })
          // Redirect to login after 2 seconds
          setTimeout(() => {
            onToggleMode()
          }, 2000)
        } else {
          toast({
            title: "✅ Account created",
            description: "Your account has been created successfully",
          })
        }
      }
      }
      // If successful login, the auth context will handle the redirect
    } catch (error) {
      // Network or unexpected error
      const errorMessage = error instanceof Error 
        ? error.message 
        : 'An unexpected error occurred. Please try again.'
      
      setError(errorMessage)
      toast({
        variant: "destructive",
        title: "❌ Error",
        description: errorMessage,
      })
    } finally {
      setIsLoading(false)
    }
  }

  const handleKeyDownSubmit = (e: React.KeyboardEvent<HTMLFormElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault()
      
      // Check if button should be disabled
      if (isLoading) return
      if (!requires2FA && !oauthPending2FA && !isLogin && !formData.tosAccepted) return
      if ((requires2FA || oauthPending2FA) && totpCode.length !== 6 && totpCode.length !== 8) return
      
      void handleSubmit(e as unknown as React.FormEvent)
    }
  }

  const handlePasskeyLogin = async () => {
    setError('')
    setIsLoading(true)
    try {
      const optionsRes = await apiClient.getPasskeyAuthOptions()
      if (!optionsRes.success || !optionsRes.data) {
        setError(optionsRes.message || 'Failed to start passkey authentication')
        return
      }

      // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment
      const opts = optionsRes.data as any
      // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
      const challengeKey = String(opts.challengeKey || '')
      // The backend spreads the WebAuthn options flat alongside challengeKey,
      // so we extract challengeKey and pass the rest to startAuthentication.
      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const { challengeKey: _ck, ...publicKeyOptions } = opts

      // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
      const assertion = await startAuthentication({ optionsJSON: publicKeyOptions })

      const verifyRes = await apiClient.verifyPasskeyAuth(assertion, challengeKey)
      if (verifyRes.success && verifyRes.data) {
        // The auth context doesn't expose setUser directly, so we use localStorage + reload
        if (typeof window !== 'undefined') {
          localStorage.setItem('has_session', 'true')
        }
        toast({
          title: '✅ Welcome back!',
          description: 'Signed in with passkey',
        })
        window.location.href = '/'
      } else {
        setError(verifyRes.message || 'Passkey authentication failed')
      }
    } catch (err: unknown) {
      if (err instanceof Error && (err.name === 'NotAllowedError' || err.name === 'AbortError')) {
        // User cancelled — silently ignore
        return
      }
      setError(err instanceof Error ? err.message : 'Passkey authentication failed')
    } finally {
      setIsLoading(false)
    }
  }

  const isLogin = mode === 'login'

  if (!oauthReady) {
    return <LoadingState variant="page" />
  }

  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-background p-4 relative" style={{ minHeight: '100vh', paddingTop: '4rem', paddingBottom: '4rem' }}>
      <div className="absolute inset-0 -z-10 bg-[radial-gradient(ellipse_80%_50%_at_50%_-20%,oklch(0.5_0_0/0.06),transparent)]" />
      <Card className="w-full max-w-md border-border/50 shadow-lg">
        <CardHeader className="space-y-1.5 text-center pb-2">
          <CardTitle className="text-2xl font-bold tracking-tight">
            {oauthPendingRegistration
              ? 'Finalize Registration'
              : (requires2FA || oauthPending2FA)
                ? 'Two-Factor Authentication'
                : (isLogin ? 'Welcome Back' : 'Create Account')
            }
          </CardTitle>
          <CardDescription className="text-sm">
            {oauthPendingRegistration
              ? 'Choose your username and accept the terms to create your account'
              : (requires2FA || oauthPending2FA) 
                ? 'Enter the code from your authenticator app' 
                : (isLogin 
                  ? 'Sign in to your SkinBaron Tracker account' 
                  : 'Get started with SkinBaron Tracker'
                )
            }
          </CardDescription>
        </CardHeader>
        
        <CardContent>
          <form onSubmit={(e) => { void handleSubmit(e) }} onKeyDown={handleKeyDownSubmit} className="space-y-4">
            {oauthPendingRegistration && oauthPendingData ? (
              // OAuth Finalize Registration Form
              <div className="space-y-4">
                <Alert>
                  <AlertDescription>
                    You&apos;re signing up with <strong className="capitalize">{oauthPendingData.provider}</strong>. Choose your username and accept the terms to create your account.
                  </AlertDescription>
                </Alert>

                <div className="space-y-2">
                  <Label htmlFor="oauth-email">Email</Label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                    <Input
                      id="oauth-email"
                      type="email"
                      value={oauthPendingData.email}
                      className="pl-10 bg-muted"
                      disabled
                    />
                  </div>
                  <p className="text-xs text-muted-foreground">Email from your {oauthPendingData.provider} account (cannot be changed)</p>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="oauth-username">Username</Label>
                  <div className="relative">
                    <User className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                    <Input
                      id="oauth-username"
                      type="text"
                      placeholder="Choose a username"
                      value={formData.username}
                      onChange={(e) => handleInputChange('username', e.target.value)}
                      className="pl-10"
                      disabled={isLoading}
                      maxLength={20}
                      autoFocus
                    />
                  </div>
                  <p className="text-xs text-muted-foreground">3–20 characters, letters, numbers and underscores only</p>
                </div>

                <div className="flex items-start gap-2">
                  <input
                    id="oauth-tos"
                    type="checkbox"
                    checked={formData.tosAccepted}
                    onChange={(e) => setFormData(prev => ({ ...prev, tosAccepted: e.target.checked }))}
                    disabled={isLoading}
                    className="mt-1 h-4 w-4 rounded border-border accent-primary"
                  />
                  <Label htmlFor="oauth-tos" className="text-sm font-normal leading-snug">
                    I agree to the{' '}
                    <Link href="/tos" target="_blank" className="underline hover:text-foreground">
                      Terms of Service
                    </Link>{' '}
                    and{' '}
                    <Link href="/privacy" target="_blank" className="underline hover:text-foreground">
                      Privacy Policy
                    </Link>
                  </Label>
                </div>
              </div>
            ) : (requires2FA || oauthPending2FA) ? (
              // 2FA Code Input
              <div className="space-y-4">
                <Alert>
                  <Shield className="h-4 w-4" />
                  <AlertDescription>
                    Enter the 6-digit code from your authenticator app. You can also use a recovery code.
                  </AlertDescription>
                </Alert>
                
                <div className="space-y-2">
                  <Label htmlFor="totp-code">Authentication Code</Label>
                  <Input
                    id="totp-code"
                    type="text"
                    maxLength={8}
                    placeholder="000000"
                    value={totpCode}
                    onChange={(e) => {
                      const value = e.target.value.replace(/[^0-9A-Fa-f]/g, '').toUpperCase()
                      setTotpCode(value)
                      if (error) setError('')
                    }}
                    className="text-center text-2xl tracking-widest font-mono"
                    autoComplete="off"
                    autoFocus
                    disabled={isLoading}
                  />
                  <p className="text-sm text-muted-foreground text-center">
                    Enter 6-digit code or 8-character recovery code
                  </p>
                </div>
              </div>
            ) : (
              // Regular Login/Register Form
              <>
                {!isLogin && (
                  <div className="space-y-2">
                    <Label htmlFor="username">Username</Label>
                    <div className="relative">
                      <User className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                      <Input
                        id="username"
                        type="text"
                        placeholder="Your username"
                        value={formData.username}
                        onChange={(e) => handleInputChange('username', e.target.value)}
                        className="pl-10"
                        disabled={isLoading}
                        maxLength={20}
                      />
                    </div>
                  </div>
                )}

                <div className="space-y-2">
                  <Label htmlFor="email">Email</Label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                    <Input
                      id="email"
                      type="email"
                      placeholder="your@email.com"
                      value={formData.email}
                      onChange={(e) => handleInputChange('email', e.target.value)}
                      className="pl-10"
                      disabled={isLoading}
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="password">Password</Label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                    <Input
                      id="password"
                      type={showPassword ? 'text' : 'password'}
                      placeholder="Your password"
                      value={formData.password}
                      onChange={(e) => handleInputChange('password', e.target.value)}
                      className="pl-10 pr-10"
                      disabled={isLoading}
                    />
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="absolute right-0 top-0 h-full px-3 hover:bg-transparent"
                      onClick={() => setShowPassword(!showPassword)}
                      disabled={isLoading}
                      aria-label={showPassword ? "Hide password" : "Show password"}
                    >
                      {showPassword ? (
                        <EyeOff className="h-4 w-4 text-muted-foreground" />
                      ) : (
                        <Eye className="h-4 w-4 text-muted-foreground" />
                      )}
                    </Button>
                  </div>
                </div>

                {!isLogin && (
                  <div className="space-y-2">
                    <Label htmlFor="confirmPassword">Confirm Password</Label>
                    <div className="relative">
                      <Lock className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                      <Input
                        id="confirmPassword"
                        type={showPassword ? 'text' : 'password'}
                        placeholder="Confirm your password"
                        value={formData.confirmPassword}
                        onChange={(e) => handleInputChange('confirmPassword', e.target.value)}
                        className="pl-10"
                        disabled={isLoading}
                      />
                    </div>
                  </div>
                )}

                {!isLogin && (
                  <div className="flex items-start gap-2">
                    <input
                      id="tos"
                      type="checkbox"
                      checked={formData.tosAccepted}
                      onChange={(e) => setFormData(prev => ({ ...prev, tosAccepted: e.target.checked }))}
                      disabled={isLoading}
                      className="mt-1 h-4 w-4 rounded border-border accent-primary"
                    />
                    <Label htmlFor="tos" className="text-sm font-normal leading-snug">
                      I agree to the{' '}
                      <Link href="/tos" target="_blank" className="underline hover:text-foreground">
                        Terms of Service
                      </Link>{' '}
                      and{' '}
                      <Link href="/privacy" target="_blank" className="underline hover:text-foreground">
                        Privacy Policy
                      </Link>
                    </Label>
                  </div>
                )}
              </>
            )}

            {error && (
              <Alert variant={error.includes('successful') ? 'default' : 'destructive'}>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            {oauthPendingRegistration ? (
              // Finalize registration buttons
              <>
                <Button
                  type="submit"
                  className="w-full"
                  disabled={isLoading || !formData.tosAccepted}
                >
                  {isLoading ? (
                    <>
                      <LoadingSpinner size="sm" inline />
                      <span className="ml-2">Creating Account...</span>
                    </>
                  ) : (
                    'Create Account'
                  )}
                </Button>

                <Button
                  type="button"
                  variant="ghost"
                  className="w-full"
                  onClick={() => {
                    setOauthPendingRegistration(false)
                    setOauthPendingData(null)
                    setError('')
                    setFormData(prev => ({ ...prev, username: '', email: '', tosAccepted: false }))
                  }}
                  disabled={isLoading}
                >
                  Cancel
                </Button>
              </>
            ) : !requires2FA && !oauthPending2FA && (
              <>
                <Button 
                  type="submit" 
                  className="w-full" 
                  disabled={isLoading || (!isLogin && !formData.tosAccepted)}
                >
                  {isLoading ? (
                    <>
                      <LoadingSpinner size="sm" inline />
                      <span className="ml-2">{isLogin ? 'Signing In...' : 'Creating Account...'}</span>
                    </>
                  ) : (
                    isLogin ? 'Sign In' : 'Create Account'
                  )}
                </Button>

                {/* Passkey sign-in (login only) */}
                {isLogin && (
                  <>
                    <div className="relative my-2">
                      <div className="absolute inset-0 flex items-center">
                        <span className="w-full border-t" />
                      </div>
                      <div className="relative flex justify-center text-xs uppercase">
                        <span className="bg-card px-2 text-muted-foreground">Or</span>
                      </div>
                    </div>

                    <Button
                      type="button"
                      variant="outline"
                      className="w-full"
                      disabled={isLoading}
                      onClick={() => void handlePasskeyLogin()}
                    >
                      <Fingerprint className="mr-2 h-4 w-4" />
                      Sign in with a passkey
                    </Button>
                  </>
                )}

                {/* OAuth providers */}
                {oauthProviders.length > 0 && (
                  <>
                    <div className="relative my-2">
                      <div className="absolute inset-0 flex items-center">
                        <span className="w-full border-t" />
                      </div>
                      <div className="relative flex justify-center text-xs uppercase">
                        <span className="bg-card px-2 text-muted-foreground">Or continue with</span>
                      </div>
                    </div>

                    <div className="grid gap-2">
                      {(['google', 'github', 'discord'] as const).filter(p => oauthProviders.includes(p)).map(provider => (
                        <Button
                          key={provider}
                          type="button"
                          variant="outline"
                          className="w-full"
                          disabled={isLoading}
                          onClick={() => { window.location.href = apiClient.getOAuthLoginUrl(provider, isLogin ? 'login' : 'register') }}
                        >
                          <span className="mr-2">{PROVIDER_ICONS[provider]}</span>
                          {PROVIDER_LABELS[provider]}
                        </Button>
                      ))}
                    </div>
                  </>
                )}

                <div className="text-center">
                  <Button
                    type="button"
                    variant="link"
                    className="text-sm"
                    onClick={onToggleMode}
                    disabled={isLoading}
                  >
                    {isLogin 
                      ? "Don't have an account? Sign up" 
                      : "Already have an account? Sign in"
                    }
                  </Button>
                </div>
              </>
            )}
            
            {(requires2FA || oauthPending2FA) && (
              <>
                <Button 
                  type="submit" 
                  className="w-full" 
                  disabled={isLoading || totpCode.length === 7 || totpCode.length < 6}
                >
                  {isLoading ? (
                    <>
                      <LoadingSpinner size="sm" inline />
                      <span className="ml-2">Verifying...</span>
                    </>
                  ) : (
                    <>
                      <Shield className="mr-2 h-4 w-4" />
                      {totpCode.length === 8 ? 'Verify Backup Code' : 'Verify Code'}
                    </>
                  )}
                </Button>
                
                {requires2FA && (
                  <Button
                    type="button"
                    variant="ghost"
                    className="w-full"
                    onClick={() => {
                      setRequires2FA(false)
                      setTotpCode('')
                      setError('')
                    }}
                    disabled={isLoading}
                  >
                    Back to Login
                  </Button>
                )}
              </>
            )}
          </form>
        </CardContent>
      </Card>
    </div>
  )
}