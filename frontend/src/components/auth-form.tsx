'use client'

import { useState, useEffect } from 'react'
import { useAuth } from '@/contexts/auth-context'
import { useToast } from '@/hooks/use-toast'
import { validateRegistration, validateLogin } from '@/lib/validation'
import { apiClient } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { Eye, EyeOff, Mail, Lock, User, Shield } from 'lucide-react'
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
  const [totpCode, setTotpCode] = useState('')
  const [oauthProviders, setOAuthProviders] = useState<string[]>([])
  
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
      }
    })()
  }, [])

  // Show error from URL params (e.g. ?error=oauth_denied after failed OAuth)
  useEffect(() => {
    if (typeof window === 'undefined') return
    const params = new URLSearchParams(window.location.search)
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
      if (requires2FA && (totpCode.length === 7 || totpCode.length < 6)) return
      
      void handleSubmit(e as unknown as React.FormEvent)
    }
  }

  const isLogin = mode === 'login'

  return (
    <div className="min-h-screen w-full flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800 p-4" style={{ minHeight: '100vh', paddingTop: '4rem', paddingBottom: '4rem' }}>
      <Card className="w-full max-w-md">
        <CardHeader className="space-y-1 text-center">
          <CardTitle className="text-2xl font-bold">
            {requires2FA ? 'Two-Factor Authentication' : (isLogin ? 'Welcome Back' : 'Create Account')}
          </CardTitle>
          <CardDescription>
            {requires2FA 
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
            {requires2FA ? (
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

            {!requires2FA && (
              <>
                <Button 
                  type="submit" 
                  className="w-full" 
                  disabled={isLoading}
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
                      {oauthProviders.includes('google') && (
                        <Button
                          type="button"
                          variant="outline"
                          className="w-full"
                          disabled={isLoading}
                          onClick={() => { window.location.href = apiClient.getOAuthLoginUrl('google') }}
                        >
                          <svg className="mr-2 h-4 w-4" viewBox="0 0 24 24"><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>
                          Google
                        </Button>
                      )}
                      {oauthProviders.includes('github') && (
                        <Button
                          type="button"
                          variant="outline"
                          className="w-full"
                          disabled={isLoading}
                          onClick={() => { window.location.href = apiClient.getOAuthLoginUrl('github') }}
                        >
                          <svg className="mr-2 h-4 w-4" viewBox="0 0 24 24" fill="currentColor"><path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12"/></svg>
                          GitHub
                        </Button>
                      )}
                      {oauthProviders.includes('discord') && (
                        <Button
                          type="button"
                          variant="outline"
                          className="w-full"
                          disabled={isLoading}
                          onClick={() => { window.location.href = apiClient.getOAuthLoginUrl('discord') }}
                        >
                          <svg className="mr-2 h-4 w-4" viewBox="0 0 24 24" fill="#5865F2"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028c.462-.63.874-1.295 1.226-1.994a.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/></svg>
                          Discord
                        </Button>
                      )}
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
            
            {requires2FA && (
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
              </>
            )}
          </form>
        </CardContent>
      </Card>
    </div>
  )
}