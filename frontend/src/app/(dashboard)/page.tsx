"use client"

import { useEffect } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { Bell, Lock, Settings } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { LoadingState } from "@/components/ui/loading-state"
import { ThemeToggle } from "@/components/theme-toggle"
import { useAuth } from "@/contexts/auth-context"

function LandingPage() {
  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-40 border-b border-border/70 bg-background/85 backdrop-blur-xl supports-[backdrop-filter]:bg-background/75">
        <div className="mx-auto flex h-16 w-full max-w-7xl items-center justify-between px-4 sm:px-6">
          <div className="flex items-center gap-3">
            <span
              aria-hidden="true"
              className="inline-flex h-8 w-8 items-center justify-center rounded-lg border border-border/70 bg-card text-[11px] font-semibold text-muted-foreground"
            >
              SB
            </span>
            <span className="text-base font-semibold tracking-tight">SkinBaron Tracker</span>
          </div>
          <div className="flex items-center gap-2">
            <ThemeToggle />
            <Link href="/login">
              <Button variant="ghost" size="sm">Sign in</Button>
            </Link>
            <Link href="/register">
              <Button size="sm">Create account</Button>
            </Link>
          </div>
        </div>
      </header>

      <section className="mx-auto w-full max-w-7xl px-4 pb-16 pt-16 sm:px-6 sm:pb-20 sm:pt-20">
        <div className="max-w-3xl space-y-6">
          <Badge variant="outline" className="rounded-full px-3 py-1 text-[11px] uppercase tracking-[0.1em]">
            Open Source - EU Hosted
          </Badge>
          <h1 className="text-4xl font-semibold leading-[1.05] tracking-[-0.03em] sm:text-5xl lg:text-6xl">
            Monitor SkinBaron listings with a clean, focused workflow.
          </h1>
          <p className="max-w-2xl text-base leading-relaxed text-muted-foreground sm:text-lg">
            Build precise rules, receive instant Discord notifications, and move quickly when interesting listings appear.
          </p>
          <div className="flex flex-col gap-3 sm:flex-row">
            <Link href="/register">
              <Button size="lg" className="w-full sm:w-auto">Start free</Button>
            </Link>
            <Link href="#features">
              <Button size="lg" variant="outline" className="w-full sm:w-auto">See features</Button>
            </Link>
          </div>
        </div>
      </section>

      <section id="features" className="border-y border-border/65 bg-muted/25">
        <div className="mx-auto w-full max-w-7xl px-4 py-14 sm:px-6 sm:py-16">
          <div className="mb-8 max-w-xl space-y-3">
            <h2 className="text-3xl font-semibold tracking-[-0.02em] sm:text-4xl">Everything you need, nothing noisy</h2>
            <p className="text-sm text-muted-foreground sm:text-base">
              The product is optimized for day-to-day use: quick scans, clear decisions, minimal interface overhead.
            </p>
          </div>

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            <Card className="border-border/70 bg-card/90">
              <CardHeader className="space-y-3 pb-2">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-border/70 bg-background/80 text-muted-foreground">
                  <Bell className="h-5 w-5" />
                </div>
                <CardTitle className="text-lg">Reliable alerts</CardTitle>
                <CardDescription className="leading-relaxed">
                  Receive structured notifications with direct links when rules are matched.
                </CardDescription>
              </CardHeader>
            </Card>

            <Card className="border-border/70 bg-card/90">
              <CardHeader className="space-y-3 pb-2">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-border/70 bg-background/80 text-muted-foreground">
                  <Settings className="h-5 w-5" />
                </div>
                <CardTitle className="text-lg">Precise rules</CardTitle>
                <CardDescription className="leading-relaxed">
                  Filter by item name, wear, stickers, StatTrak and price range.
                </CardDescription>
              </CardHeader>
            </Card>

            <Card className="border-border/70 bg-card/90 sm:col-span-2 lg:col-span-1">
              <CardHeader className="space-y-3 pb-2">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-border/70 bg-background/80 text-muted-foreground">
                  <Lock className="h-5 w-5" />
                </div>
                <CardTitle className="text-lg">Secure by default</CardTitle>
                <CardDescription className="leading-relaxed">
                  2FA, session controls, passkeys and encrypted webhook endpoints.
                </CardDescription>
              </CardHeader>
            </Card>
          </div>
        </div>
      </section>

      <section className="mx-auto w-full max-w-7xl px-4 py-14 sm:px-6 sm:py-16">
        <div className="grid gap-4 sm:grid-cols-3">
          <Card className="border-border/70 bg-card/90">
            <CardHeader className="space-y-2 pb-2">
              <CardTitle className="text-lg">1. Create rules</CardTitle>
              <CardDescription>Configure the exact listings you want to track.</CardDescription>
            </CardHeader>
          </Card>
          <Card className="border-border/70 bg-card/90">
            <CardHeader className="space-y-2 pb-2">
              <CardTitle className="text-lg">2. Connect webhooks</CardTitle>
              <CardDescription>Choose where alerts should be sent and in which format.</CardDescription>
            </CardHeader>
          </Card>
          <Card className="border-border/70 bg-card/90">
            <CardHeader className="space-y-2 pb-2">
              <CardTitle className="text-lg">3. React fast</CardTitle>
              <CardDescription>Open matching listings immediately and decide quickly.</CardDescription>
            </CardHeader>
          </Card>
        </div>
      </section>
    </div>
  )
}

export default function HomePage() {
  const { isAuthenticated, isLoading, isReady } = useAuth()
  const router = useRouter()

  useEffect(() => {
    if (isReady && isAuthenticated) {
      router.replace('/alerts')
    }
  }, [isReady, isAuthenticated, router])

  if (isLoading || !isReady || isAuthenticated) {
    return <LoadingState variant="page" />
  }

  return <LandingPage />
}
