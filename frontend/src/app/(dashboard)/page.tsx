"use client"

import { useEffect } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { Bell, Lock, Radar, Settings, Sparkles } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { LoadingState } from "@/components/ui/loading-state"
import { ThemeToggle } from "@/components/theme-toggle"
import { useAuth } from "@/contexts/auth-context"

function LandingPage() {
  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-40 border-b border-border/70 bg-background/80 backdrop-blur-xl supports-[backdrop-filter]:bg-background/70">
        <div className="mx-auto flex h-16 w-full max-w-7xl items-center justify-between px-4 sm:px-6">
          <div className="flex items-center gap-3">
            <span
              aria-hidden="true"
              className="inline-flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-primary/90 via-primary to-cyan-500/80 text-[11px] font-bold text-primary-foreground shadow-sm"
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

      <section className="relative overflow-hidden">
        <div className="pointer-events-none absolute inset-0 -z-10">
          <div className="absolute inset-x-0 -top-24 h-80 bg-[radial-gradient(circle_at_center,oklch(0.75_0.08_235_/_24%),transparent_65%)]" />
          <div className="absolute -left-24 top-24 h-72 w-72 rounded-full bg-[radial-gradient(circle,oklch(0.82_0.08_195_/_24%),transparent_65%)]" />
          <div className="absolute -right-24 top-16 h-72 w-72 rounded-full bg-[radial-gradient(circle,oklch(0.74_0.09_255_/_20%),transparent_65%)]" />
        </div>

        <div className="mx-auto w-full max-w-7xl px-4 pb-20 pt-16 sm:px-6 sm:pb-24 sm:pt-24">
          <div className="grid gap-10 lg:grid-cols-[1.1fr_0.9fr] lg:items-center">
            <div className="space-y-7">
              <Badge
                variant="secondary"
                className="inline-flex rounded-full border border-border/70 bg-background/75 px-3.5 py-1 text-[11px] uppercase tracking-[0.12em]"
              >
                Open Source - EU Hosted
              </Badge>

              <div className="space-y-4">
                <h1 className="max-w-3xl text-4xl font-semibold leading-[1.03] tracking-[-0.03em] sm:text-5xl lg:text-6xl">
                  Track SkinBaron listings like a pro, in real time.
                </h1>
                <p className="max-w-2xl text-base leading-relaxed text-muted-foreground sm:text-lg">
                  Define precise filters, receive low-latency Discord alerts, and focus on the listings that matter.
                  Built for traders who want signal, not noise.
                </p>
              </div>

              <div className="flex flex-col gap-3 sm:flex-row">
                <Link href="/register">
                  <Button size="lg" className="w-full sm:min-w-44 sm:w-auto">
                    Start Free
                  </Button>
                </Link>
                <Link href="#features">
                  <Button size="lg" variant="outline" className="w-full sm:min-w-44 sm:w-auto">
                    Explore Features
                  </Button>
                </Link>
              </div>

              <div className="grid max-w-xl grid-cols-3 gap-3">
                <div className="rounded-xl border border-border/70 bg-card/70 px-3 py-2">
                  <p className="text-lg font-semibold leading-none">5s</p>
                  <p className="mt-1 text-xs text-muted-foreground">Polling cadence</p>
                </div>
                <div className="rounded-xl border border-border/70 bg-card/70 px-3 py-2">
                  <p className="text-lg font-semibold leading-none">AES-256</p>
                  <p className="mt-1 text-xs text-muted-foreground">Webhook encryption</p>
                </div>
                <div className="rounded-xl border border-border/70 bg-card/70 px-3 py-2">
                  <p className="text-lg font-semibold leading-none">2FA</p>
                  <p className="mt-1 text-xs text-muted-foreground">Account security</p>
                </div>
              </div>
            </div>

            <Card className="border-border/70 bg-card/80 shadow-lg">
              <CardHeader className="space-y-4 pb-0">
                <CardTitle className="text-xl">Live monitoring cockpit</CardTitle>
                <CardDescription className="text-sm leading-relaxed">
                  Combine rule filters, webhook routing and secure account controls in a single workflow.
                </CardDescription>
              </CardHeader>
              <div className="space-y-3 p-6">
                {[
                  { icon: Radar, title: "Real-time listing scan", detail: "Continuous market polling with lightweight processing." },
                  { icon: Settings, title: "Flexible rule engine", detail: "Filter by item, wear, stickers, StatTrak and price range." },
                  { icon: Lock, title: "Hardened account model", detail: "Passkeys, TOTP, session control and encrypted webhooks." },
                ].map((feature) => (
                  <div key={feature.title} className="flex gap-3 rounded-xl border border-border/70 bg-background/60 p-3.5">
                    <div className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-primary/15 text-primary">
                      <feature.icon className="h-4 w-4" />
                    </div>
                    <div>
                      <p className="text-sm font-semibold">{feature.title}</p>
                      <p className="text-xs leading-relaxed text-muted-foreground">{feature.detail}</p>
                    </div>
                  </div>
                ))}
              </div>
            </Card>
          </div>
        </div>
      </section>

      <section id="features" className="mx-auto w-full max-w-7xl px-4 py-20 sm:px-6 sm:py-24">
        <div className="mb-12 text-center">
          <Badge variant="outline" className="mb-3 rounded-full px-3 py-1 text-[11px] uppercase tracking-[0.1em]">
            Product highlights
          </Badge>
          <h2 className="text-3xl font-semibold tracking-[-0.02em] sm:text-4xl">
            Built for fast decision loops
          </h2>
          <p className="mx-auto mt-3 max-w-xl text-sm text-muted-foreground sm:text-base">
            The interface stays compact and actionable so you can evaluate opportunities without friction.
          </p>
        </div>

        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 animate-stagger">
          <Card className="border-border/70 bg-card/75">
            <CardHeader className="space-y-3 pb-2">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/15 text-primary">
                <Bell className="h-5 w-5" />
              </div>
              <CardTitle className="text-lg">Actionable alerts</CardTitle>
              <CardDescription className="leading-relaxed">
                Structured notifications with direct links and key context, not noisy pings.
              </CardDescription>
            </CardHeader>
          </Card>

          <Card className="border-border/70 bg-card/75">
            <CardHeader className="space-y-3 pb-2">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/15 text-primary">
                <Settings className="h-5 w-5" />
              </div>
              <CardTitle className="text-lg">Rule precision</CardTitle>
              <CardDescription className="leading-relaxed">
                Configure exact matching conditions to surface only listings aligned with your strategy.
              </CardDescription>
            </CardHeader>
          </Card>

          <Card className="border-border/70 bg-card/75 sm:col-span-2 lg:col-span-1">
            <CardHeader className="space-y-3 pb-2">
              <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/15 text-primary">
                <Sparkles className="h-5 w-5" />
              </div>
              <CardTitle className="text-lg">Focused workflow</CardTitle>
              <CardDescription className="leading-relaxed">
                Fast navigation, clear states and secure defaults designed for daily high-frequency use.
              </CardDescription>
            </CardHeader>
          </Card>
        </div>
      </section>

      <section className="border-y border-border/65 bg-muted/25">
        <div className="mx-auto w-full max-w-7xl px-4 py-16 sm:px-6 sm:py-20">
          <div className="grid gap-6 sm:grid-cols-3 animate-stagger">
            {[
              {
                title: "1. Build rules",
                text: "Set weapons, skin names, wear limits and price windows for your target setup.",
              },
              {
                title: "2. Route notifications",
                text: "Attach one or multiple Discord webhooks and choose your preferred payload style.",
              },
              {
                title: "3. React instantly",
                text: "Review incoming listings and jump directly to SkinBaron in one click.",
              },
            ].map((step) => (
              <Card key={step.title} className="border-border/70 bg-card/80">
                <CardHeader className="space-y-2 pb-2">
                  <CardTitle className="text-lg">{step.title}</CardTitle>
                  <CardDescription className="leading-relaxed">{step.text}</CardDescription>
                </CardHeader>
              </Card>
            ))}
          </div>
        </div>
      </section>

      <section className="mx-auto w-full max-w-7xl px-4 py-16 text-center sm:px-6 sm:py-20">
        <h2 className="text-3xl font-semibold tracking-[-0.02em] sm:text-4xl">
          Ready to monitor the market with less noise?
        </h2>
        <p className="mx-auto mt-3 max-w-xl text-sm text-muted-foreground sm:text-base">
          Launch your first alert rule in minutes and keep full control over your notification flow.
        </p>
        <div className="mt-7 flex flex-col justify-center gap-3 sm:flex-row">
          <Link href="/register">
            <Button size="lg" className="w-full sm:min-w-44 sm:w-auto">
              Create free account
            </Button>
          </Link>
          <Link href="/login">
            <Button size="lg" variant="outline" className="w-full sm:min-w-44 sm:w-auto">
              I already have an account
            </Button>
          </Link>
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
