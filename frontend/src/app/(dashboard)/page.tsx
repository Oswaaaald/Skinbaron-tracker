"use client"

import { useQuery } from "@tanstack/react-query"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import Link from "next/link"
import { 
  Activity, 
  Bell, 
  Settings,
  ArrowRight,
  Webhook,
  Zap,
  Lock,
  Github
} from "lucide-react"
import { apiClient } from "@/lib/api"
import { useAuth } from "@/contexts/auth-context"
import { usePageVisible } from "@/hooks/use-page-visible"
import { useState } from "react"
import { AuthForm } from "@/components/auth-form"
import { ThemeToggle } from "@/components/theme-toggle"

function LandingPage() {
  const [authMode, setAuthMode] = useState<'login' | 'register'>('login')
  const [showAuth, setShowAuth] = useState(false)

  if (showAuth) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <AuthForm 
          mode={authMode} 
          onToggleMode={() => setAuthMode(authMode === 'login' ? 'register' : 'login')} 
        />
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Bell className="h-6 w-6 text-primary" />
            <span className="text-xl font-bold">SkinBaron Tracker</span>
          </div>
          <div className="flex items-center gap-4">
            <ThemeToggle />
            <Button variant="ghost" onClick={() => { setAuthMode('login'); setShowAuth(true); }}>
              Sign In
            </Button>
            <Button onClick={() => { setAuthMode('register'); setShowAuth(true); }}>
              Get Started
            </Button>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="container mx-auto px-4 py-20 text-center">
        <h1 className="text-5xl font-bold tracking-tight mb-6">
          Never Miss a Deal on CS2 Skins
        </h1>
        <p className="text-xl text-muted-foreground max-w-2xl mx-auto mb-8">
          Get instant Discord notifications when CS2 skins matching your criteria appear on SkinBaron. 
          Set custom price alerts, track specific items, and catch the best deals before anyone else.
        </p>
        <div className="flex gap-4 justify-center">
          <Button size="lg" onClick={() => { setAuthMode('register'); setShowAuth(true); }}>
            Start Tracking for Free
          </Button>
          <Link href="#features">
            <Button size="lg" variant="outline">
              Learn More
            </Button>
          </Link>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="container mx-auto px-4 py-20">
        <h2 className="text-3xl font-bold text-center mb-12">Why SkinBaron Tracker?</h2>
        <div className="grid md:grid-cols-3 gap-8">
          <Card>
            <CardHeader>
              <Zap className="h-10 w-10 text-primary mb-2" />
              <CardTitle>Real-Time Alerts</CardTitle>
              <CardDescription>
                Instant Discord notifications when items matching your rules appear on the market
              </CardDescription>
            </CardHeader>
          </Card>

          <Card>
            <CardHeader>
              <Settings className="h-10 w-10 text-primary mb-2" />
              <CardTitle>Custom Rules</CardTitle>
              <CardDescription>
                Filter by weapon, skin, wear, price range, StatTrak, Souvenir, and even specific stickers
              </CardDescription>
            </CardHeader>
          </Card>

          <Card>
            <CardHeader>
              <Lock className="h-10 w-10 text-primary mb-2" />
              <CardTitle>Secure & Private</CardTitle>
              <CardDescription>
                GDPR compliant, encrypted webhooks, 2FA authentication, and hosted in EU
              </CardDescription>
            </CardHeader>
          </Card>
        </div>
      </section>

      {/* How it works */}
      <section className="bg-muted/50 py-20">
        <div className="container mx-auto px-4">
          <h2 className="text-3xl font-bold text-center mb-12">How It Works</h2>
          <div className="grid md:grid-cols-3 gap-8 max-w-4xl mx-auto">
            <div className="text-center">
              <div className="bg-primary text-primary-foreground rounded-full w-12 h-12 flex items-center justify-center text-xl font-bold mx-auto mb-4">1</div>
              <h3 className="font-semibold mb-2">Create Rules</h3>
              <p className="text-sm text-muted-foreground">
                Set up custom monitoring rules with your desired filters and price limits
              </p>
            </div>
            <div className="text-center">
              <div className="bg-primary text-primary-foreground rounded-full w-12 h-12 flex items-center justify-center text-xl font-bold mx-auto mb-4">2</div>
              <h3 className="font-semibold mb-2">Connect Discord</h3>
              <p className="text-sm text-muted-foreground">
                Add your Discord webhook to receive notifications in your server or DMs
              </p>
            </div>
            <div className="text-center">
              <div className="bg-primary text-primary-foreground rounded-full w-12 h-12 flex items-center justify-center text-xl font-bold mx-auto mb-4">3</div>
              <h3 className="font-semibold mb-2">Get Notified</h3>
              <p className="text-sm text-muted-foreground">
                Receive instant alerts when matching items are listed on SkinBaron
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="container mx-auto px-4 py-20 text-center">
        <h2 className="text-3xl font-bold mb-4">Ready to Start Tracking?</h2>
        <p className="text-muted-foreground mb-8 max-w-xl mx-auto">
          Join traders who never miss a good deal. Free to use, no credit card required.
        </p>
        <Button size="lg" onClick={() => { setAuthMode('register'); setShowAuth(true); }}>
          Create Your Free Account
        </Button>
      </section>

      {/* Footer */}
      <footer className="border-t py-8">
        <div className="container mx-auto px-4 flex items-center justify-between text-sm text-muted-foreground">
          <div>
            © 2026 SkinBaron Tracker. Personal non-commercial project.
          </div>
          <div className="flex gap-6">
            <Link href="/legal" className="hover:text-foreground">Legal Notice</Link>
            <Link href="/privacy" className="hover:text-foreground">Privacy Policy</Link>
            <a href="https://github.com/Oswaaaald" target="_blank" rel="noopener noreferrer" className="hover:text-foreground flex items-center gap-1">
              <Github className="h-4 w-4" />
              GitHub
            </a>
          </div>
        </div>
      </footer>
    </div>
  )
}

function DashboardContent() {
  const { isReady, isAuthenticated } = useAuth()
  const isVisible = usePageVisible()

  const { data: systemStatus } = useQuery({
    queryKey: ['system-status'],
    queryFn: async () => apiClient.ensureSuccess(await apiClient.getSystemStatus(), 'Failed to load system status'),
    enabled: isReady && isAuthenticated && isVisible,
    staleTime: 5 * 60 * 1000,
    refetchInterval: isVisible ? 5 * 60 * 1000 : false,
    refetchOnWindowFocus: true,
  })

  const { data: userStats } = useQuery({
    queryKey: ['user-stats'],
    queryFn: async () => apiClient.ensureSuccess(await apiClient.getUserStats(), 'Failed to load user stats'),
    enabled: isReady && isAuthenticated && isVisible,
    staleTime: 30_000,
    refetchInterval: isVisible ? 30_000 : false,
    refetchOnWindowFocus: true,
  })

  const isSchedulerRunning = systemStatus?.data?.scheduler.isRunning
  const totalRules = userStats?.data?.totalRules || 0
  const enabledRules = userStats?.data?.enabledRules || 0
  const todayAlerts = userStats?.data?.todayAlerts || 0

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Dashboard</h2>
        <p className="text-muted-foreground">
          Monitor CS2 skins with custom alerts and Discord notifications
        </p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">System Status</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <Badge variant={isSchedulerRunning ? "default" : "secondary"}>
              {isSchedulerRunning ? "Active" : "Inactive"}
            </Badge>
            <p className="text-xs text-muted-foreground mt-2">
              {isSchedulerRunning ? "Monitoring active" : "Monitoring paused"}
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Rules</CardTitle>
            <Settings className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{enabledRules}/{totalRules}</div>
            <p className="text-xs text-muted-foreground">
              Enabled rules
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Today&apos;s Alerts</CardTitle>
            <Bell className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{todayAlerts}</div>
            <p className="text-xs text-muted-foreground">
              Last 24 hours
            </p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Link href="/rules" className="block">
          <Card className="hover:border-primary transition-colors cursor-pointer h-full">
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <Settings className="h-5 w-5" />
                  Rules
                </span>
                <ArrowRight className="h-4 w-4" />
              </CardTitle>
              <CardDescription>
                Manage monitoring rules
              </CardDescription>
            </CardHeader>
          </Card>
        </Link>

        <Link href="/alerts" className="block">
          <Card className="hover:border-primary transition-colors cursor-pointer h-full">
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <Bell className="h-5 w-5" />
                  Alerts
                </span>
                <ArrowRight className="h-4 w-4" />
              </CardTitle>
              <CardDescription>
                View triggered alerts
              </CardDescription>
            </CardHeader>
          </Card>
        </Link>

        <Link href="/webhooks" className="block">
          <Card className="hover:border-primary transition-colors cursor-pointer h-full">
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <Webhook className="h-5 w-5" />
                  Webhooks
                </span>
                <ArrowRight className="h-4 w-4" />
              </CardTitle>
              <CardDescription>
                Discord notifications
              </CardDescription>
            </CardHeader>
          </Card>
        </Link>
      </div>

      {totalRules === 0 && (
        <Card className="border-dashed">
          <CardHeader>
            <CardTitle>Get Started</CardTitle>
            <CardDescription>
              Create your first rule to start monitoring CS2 skins
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Link href="/rules">
              <Button>
                <Settings className="mr-2 h-4 w-4" />
                Create Your First Rule
              </Button>
            </Link>
          </CardContent>
        </Card>
      )}
    </div>
  )
}

export default function HomePage() {
  const { isAuthenticated } = useAuth()
  
  if (!isAuthenticated) {
    return <LandingPage />
  }
  
  return <DashboardContent />
}
