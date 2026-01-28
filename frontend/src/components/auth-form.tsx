'use client'

import { useState } from 'react'
import { useAuth } from '@/contexts/auth-context'
import { useToast } from '@/hooks/use-toast'
import { validateRegistration, validateLogin } from '@/lib/validation'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { LoadingSpinner } from '@/components/ui/loading-spinner'
import { Eye, EyeOff, Mail, Lock, User, Shield } from 'lucide-react'

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
  
  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: '',
    confirmPassword: ''
  })

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
      } catch (error) {
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
      
      handleSubmit(e as unknown as React.FormEvent)
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
          <form onSubmit={handleSubmit} onKeyDown={handleKeyDownSubmit} className="space-y-4">
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