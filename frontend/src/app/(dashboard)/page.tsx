"use client"

import { AlertsGrid } from "@/components/alerts-grid"
import { useAuth } from "@/contexts/auth-context"
import { LoadingState } from "@/components/ui/loading-state"
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import Link from "next/link"
import { Bell, Settings, Lock, Zap } from "lucide-react"
import { ThemeToggle } from "@/components/theme-toggle"

function LandingPage() {
  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Bell className="h-5 w-5 sm:h-6 sm:w-6 text-primary" />
            <span className="text-lg sm:text-xl font-bold">SkinBaron Tracker</span>
          </div>
          <div className="flex items-center gap-2 sm:gap-4">
            <ThemeToggle />
            <Link href="/login">
              <Button variant="ghost" size="sm" className="sm:h-10 sm:px-4">
                <span className="hidden sm:inline">Sign In</span>
                <span className="sm:hidden">Login</span>
              </Button>
            </Link>
            <Link href="/register">
              <Button size="sm" className="sm:h-10 sm:px-4">
                <span className="hidden sm:inline">Get Started</span>
                <span className="sm:hidden">Sign Up</span>
              </Button>
            </Link>
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
          <Link href="/register">
            <Button size="lg">
              Start Tracking for Free
            </Button>
          </Link>
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
        <Link href="/register">
          <Button size="lg">
            Create Your Free Account
          </Button>
        </Link>
      </section>
    </div>
  )
}

function AlertsContent() {
  const { isReady } = useAuth()

  if (!isReady) {
    return <LoadingState variant="card" />
  }

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Alert History</h2>
        <p className="text-muted-foreground">
          View all triggered alerts with detailed information
        </p>
      </div>
      <AlertsGrid />
    </div>
  )
}

export default function HomePage() {
  const { isAuthenticated, isLoading, isReady } = useAuth()
  
  // Show loading state while checking authentication
  if (isLoading || !isReady) {
    return <LoadingState variant="page" />
  }
  
  if (!isAuthenticated) {
    return <LandingPage />
  }
  
  return <AlertsContent />
}
