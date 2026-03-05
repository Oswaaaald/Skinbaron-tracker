"use client"

import { useEffect } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { ArrowRight, Bell, Clock3, Lock, ShieldCheck, SlidersHorizontal } from "lucide-react"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { LoadingState } from "@/components/ui/loading-state"
import { ThemeToggle } from "@/components/theme-toggle"
import { useAuth } from "@/contexts/auth-context"

const featureCards = [
  {
    title: "Reliable alerts",
    description: "Receive structured notifications with direct links when a listing matches your rules.",
    icon: Bell,
  },
  {
    title: "Precise filtering",
    description: "Target exact item names, wear ranges, sticker constraints, StatTrak and price thresholds.",
    icon: SlidersHorizontal,
  },
  {
    title: "Secure by default",
    description: "2FA, passkeys, session controls and encrypted webhook endpoints built into the core.",
    icon: ShieldCheck,
  },
]

const onboardingSteps = [
  {
    title: "Create your rules",
    description: "Define exactly what should trigger a notification.",
  },
  {
    title: "Connect your channels",
    description: "Attach one or multiple webhooks with your preferred payload style.",
  },
  {
    title: "React immediately",
    description: "Open matching listings in one click and make fast decisions.",
  },
]

const livePreview = [
  {
    item: "AWP | Asiimov",
    price: "EUR 186.90",
    rule: "sniper-lowwear",
    ago: "9s ago",
  },
  {
    item: "AK-47 | Redline",
    price: "EUR 62.30",
    rule: "ak-budget",
    ago: "21s ago",
  },
  {
    item: "M4A1-S | Printstream",
    price: "EUR 141.00",
    rule: "m4-premium",
    ago: "37s ago",
  },
]

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

      <section className="border-b border-border/65 bg-muted/15">
        <div className="mx-auto w-full max-w-7xl px-4 py-12 sm:px-6 sm:py-18">
          <div className="grid gap-8 lg:grid-cols-[1.08fr_0.92fr] lg:items-center">
            <div className="space-y-6">
              <Badge variant="outline" className="rounded-full px-3 py-1 text-[10px] uppercase tracking-[0.12em]">
                Open Source - EU Hosted
              </Badge>

              <div className="space-y-3.5">
                <h1 className="max-w-3xl text-4xl font-semibold leading-[1.06] tracking-[-0.03em] sm:text-5xl lg:text-[3.45rem]">
                  Monitor SkinBaron listings without interface noise.
                </h1>
                <p className="max-w-2xl text-[15px] leading-relaxed text-muted-foreground sm:text-lg">
                  Build focused rules, route alerts to Discord instantly, and keep your trading workflow compact and actionable.
                </p>
              </div>

              <div className="flex flex-col gap-3 sm:flex-row">
                <Link href="/register">
                  <Button size="lg" className="w-full sm:w-auto sm:min-w-40">
                    Start free
                    <ArrowRight className="h-4 w-4" />
                  </Button>
                </Link>
                <Link href="#features">
                  <Button size="lg" variant="outline" className="w-full sm:w-auto sm:min-w-40">
                    See features
                  </Button>
                </Link>
              </div>

              <div className="grid gap-1.5 text-xs text-muted-foreground sm:grid-cols-3 sm:text-sm">
                <span className="inline-flex items-center gap-1.5"><Clock3 className="h-3.5 w-3.5" /> 5s polling cadence</span>
                <span className="inline-flex items-center gap-1.5"><Lock className="h-3.5 w-3.5" /> encrypted webhooks</span>
                <span className="inline-flex items-center gap-1.5"><ShieldCheck className="h-3.5 w-3.5" /> passkeys + 2FA</span>
              </div>
            </div>

            <Card className="border-border/70 bg-card/95 py-0 shadow-sm">
              <CardHeader className="border-b border-border/65 pb-3 pt-5">
                <div className="flex items-center justify-between gap-2">
                  <CardTitle className="text-base">Live feed preview</CardTitle>
                  <Badge variant="secondary" className="rounded-md px-2 py-0.5 text-[10px] uppercase tracking-[0.08em]">
                    Demo
                  </Badge>
                </div>
                <CardDescription>How listings surface inside the alerts dashboard.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3 p-4">
                {livePreview.map((event) => (
                  <div key={event.item} className="rounded-xl border border-border/70 bg-background/70 p-3.5">
                    <div className="flex items-start justify-between gap-3">
                      <p className="line-clamp-1 text-sm font-medium tracking-[-0.01em]">{event.item}</p>
                      <span className="text-[11px] text-muted-foreground whitespace-nowrap">{event.ago}</span>
                    </div>
                    <div className="mt-2.5 flex items-center justify-between gap-2">
                      <span className="text-sm font-semibold tabular-nums">{event.price}</span>
                      <Badge variant="secondary" className="rounded-md px-2 py-0.5 font-medium text-[10px] tracking-[0.02em]">
                        {event.rule}
                      </Badge>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        </div>
      </section>

      <section id="features" className="mx-auto w-full max-w-7xl px-4 py-14 sm:px-6 sm:py-16">
        <div className="mb-8 max-w-xl space-y-3">
          <h2 className="text-3xl font-semibold tracking-[-0.02em] sm:text-4xl">Designed for signal over noise</h2>
          <p className="text-sm text-muted-foreground sm:text-base">
            Every screen keeps decision speed in mind: clear data hierarchy, direct actions, and secure defaults.
          </p>
        </div>

        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {featureCards.map((feature) => (
            <Card key={feature.title} className="border-border/70 bg-card/90">
              <CardHeader className="space-y-3 pb-2">
                <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-border/70 bg-background/80 text-muted-foreground">
                  <feature.icon className="h-5 w-5" />
                </div>
                <CardTitle className="text-lg">{feature.title}</CardTitle>
                <CardDescription className="leading-relaxed">{feature.description}</CardDescription>
              </CardHeader>
            </Card>
          ))}
        </div>
      </section>

      <section className="border-y border-border/65 bg-muted/20">
        <div className="mx-auto w-full max-w-7xl px-4 py-14 sm:px-6 sm:py-16">
          <div className="grid gap-4 sm:grid-cols-3">
            {onboardingSteps.map((step, index) => (
              <Card key={step.title} className="border-border/70 bg-card/90">
                <CardHeader className="space-y-2 pb-2">
                  <p className="text-xs font-medium uppercase tracking-[0.1em] text-muted-foreground">Step {index + 1}</p>
                  <CardTitle className="text-lg">{step.title}</CardTitle>
                  <CardDescription>{step.description}</CardDescription>
                </CardHeader>
              </Card>
            ))}
          </div>
        </div>
      </section>

      <section className="mx-auto flex w-full max-w-7xl flex-col items-start gap-4 px-4 py-14 sm:px-6 sm:py-16">
        <h2 className="text-3xl font-semibold tracking-[-0.02em] sm:text-4xl">Ready to ship your first rule?</h2>
        <p className="max-w-2xl text-sm text-muted-foreground sm:text-base">
          Create an account, configure one rule, and start receiving alerts in a few minutes.
        </p>
        <div className="flex flex-col gap-3 sm:flex-row">
          <Link href="/register">
            <Button size="lg">Create free account</Button>
          </Link>
          <Link href="/login">
            <Button size="lg" variant="outline">I already have an account</Button>
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
