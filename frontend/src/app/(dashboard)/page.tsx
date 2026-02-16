"use client"

import { AlertsGrid } from "@/components/alerts-grid"
import { useAuth } from "@/contexts/auth-context"
import { LoadingState } from "@/components/ui/loading-state"
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import Link from "next/link"
import { Bell, Settings, Lock, Zap } from "lucide-react"
import { ThemeToggle } from "@/components/theme-toggle"

function LandingPage() {
  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-40 border-b border-border/40 bg-background/80 backdrop-blur-lg supports-[backdrop-filter]:bg-background/60">
        <div className="container mx-auto px-4 sm:px-6">
          <div className="flex h-14 items-center justify-between">
            <div className="flex items-center gap-2">
              <Bell className="h-5 w-5 text-primary" />
              <span className="text-base font-semibold tracking-tight">SkinBaron Tracker</span>
            </div>
            <div className="flex items-center gap-2">
              <ThemeToggle />
              <Link href="/login">
                <Button variant="ghost" size="sm">Sign In</Button>
              </Link>
              <Link href="/register">
                <Button size="sm">Get Started</Button>
              </Link>
            </div>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 -z-10 bg-[radial-gradient(ellipse_80%_50%_at_50%_-20%,oklch(0.5_0_0/0.06),transparent)]" />
        <div className="container mx-auto px-4 sm:px-6 pt-20 pb-16 sm:pt-28 sm:pb-24 text-center">
          <Badge variant="secondary" className="mb-6 px-3 py-1 text-xs font-medium">
            Free &amp; Open Source
          </Badge>
          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight mb-5 max-w-3xl mx-auto leading-[1.1]">
            Never Miss a Deal on{" "}
            <span className="text-primary">SkinBaron</span>
          </h1>
          <p className="text-lg sm:text-xl text-muted-foreground max-w-2xl mx-auto mb-10 leading-relaxed">
            Get instant Discord notifications when CS2 skins matching your criteria appear on SkinBaron.
            Set custom price alerts, track specific items, and catch the best deals.
          </p>
          <div className="flex flex-col sm:flex-row gap-3 justify-center">
            <Link href="/register">
              <Button size="lg" className="w-full sm:w-auto text-sm px-8">
                Start Tracking for Free
              </Button>
            </Link>
            <Link href="#features">
              <Button size="lg" variant="outline" className="w-full sm:w-auto text-sm px-8">
                Learn More
              </Button>
            </Link>
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="container mx-auto px-4 sm:px-6 py-20">
        <div className="text-center mb-14">
          <h2 className="text-2xl sm:text-3xl font-bold tracking-tight mb-3">Why SkinBaron Tracker?</h2>
          <p className="text-muted-foreground max-w-lg mx-auto">Everything you need to monitor the CS2 skin market efficiently.</p>
        </div>
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-5">
          <Card className="group border-border/50 bg-card/50 hover:bg-card hover:shadow-md hover:border-border transition-all duration-200">
            <CardHeader className="pb-3">
              <div className="h-10 w-10 rounded-lg bg-primary/10 text-primary flex items-center justify-center mb-3 group-hover:bg-primary/15 transition-colors">
                <Zap className="h-5 w-5" />
              </div>
              <CardTitle className="text-lg">Real-Time Alerts</CardTitle>
              <CardDescription className="leading-relaxed">
                Instant Discord notifications when items matching your rules appear on the market.
              </CardDescription>
            </CardHeader>
          </Card>

          <Card className="group border-border/50 bg-card/50 hover:bg-card hover:shadow-md hover:border-border transition-all duration-200">
            <CardHeader className="pb-3">
              <div className="h-10 w-10 rounded-lg bg-primary/10 text-primary flex items-center justify-center mb-3 group-hover:bg-primary/15 transition-colors">
                <Settings className="h-5 w-5" />
              </div>
              <CardTitle className="text-lg">Custom Rules</CardTitle>
              <CardDescription className="leading-relaxed">
                Filter by weapon, skin, wear, price range, StatTrak, Souvenir, and stickers.
              </CardDescription>
            </CardHeader>
          </Card>

          <Card className="group border-border/50 bg-card/50 hover:bg-card hover:shadow-md hover:border-border transition-all duration-200 sm:col-span-2 lg:col-span-1">
            <CardHeader className="pb-3">
              <div className="h-10 w-10 rounded-lg bg-primary/10 text-primary flex items-center justify-center mb-3 group-hover:bg-primary/15 transition-colors">
                <Lock className="h-5 w-5" />
              </div>
              <CardTitle className="text-lg">Secure &amp; Private</CardTitle>
              <CardDescription className="leading-relaxed">
                GDPR compliant, encrypted webhooks, 2FA authentication, and EU hosted.
              </CardDescription>
            </CardHeader>
          </Card>
        </div>
      </section>

      {/* How it works */}
      <section className="border-y border-border/40 bg-muted/30">
        <div className="container mx-auto px-4 sm:px-6 py-20">
          <div className="text-center mb-14">
            <h2 className="text-2xl sm:text-3xl font-bold tracking-tight mb-3">How It Works</h2>
            <p className="text-muted-foreground max-w-lg mx-auto">Three simple steps to start tracking deals.</p>
          </div>
          <div className="grid sm:grid-cols-3 gap-10 max-w-3xl mx-auto">
            <div className="text-center">
              <div className="bg-primary text-primary-foreground rounded-full w-10 h-10 flex items-center justify-center text-sm font-bold mx-auto mb-4">1</div>
              <h3 className="font-semibold mb-1.5">Create Rules</h3>
              <p className="text-sm text-muted-foreground leading-relaxed">
                Set up monitoring rules with your desired filters and price limits.
              </p>
            </div>
            <div className="text-center">
              <div className="bg-primary text-primary-foreground rounded-full w-10 h-10 flex items-center justify-center text-sm font-bold mx-auto mb-4">2</div>
              <h3 className="font-semibold mb-1.5">Connect Discord</h3>
              <p className="text-sm text-muted-foreground leading-relaxed">
                Add your Discord webhook to receive notifications in your server.
              </p>
            </div>
            <div className="text-center">
              <div className="bg-primary text-primary-foreground rounded-full w-10 h-10 flex items-center justify-center text-sm font-bold mx-auto mb-4">3</div>
              <h3 className="font-semibold mb-1.5">Get Notified</h3>
              <p className="text-sm text-muted-foreground leading-relaxed">
                Receive instant alerts when matching items are listed on SkinBaron.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="container mx-auto px-4 sm:px-6 py-20 text-center">
        <h2 className="text-2xl sm:text-3xl font-bold tracking-tight mb-3">Ready to Start Tracking?</h2>
        <p className="text-muted-foreground mb-8 max-w-md mx-auto">
          Join traders who never miss a good deal. Free to use, no credit card required.
        </p>
        <Link href="/register">
          <Button size="lg" className="px-8">
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
    <div className="space-y-6">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Alert History</h2>
        <p className="text-sm text-muted-foreground mt-1">
          Items that matched your monitoring rules
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
