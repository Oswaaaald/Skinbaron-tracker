import Link from "next/link"
import { Button } from "@/components/ui/button"
import { ArrowLeft } from "lucide-react"

export default function PrivacyPolicy() {
  return (
    <div className="container mx-auto p-6 space-y-8">
      <Link href="/">
        <Button variant="outline" size="icon" aria-label="Go back">
          <ArrowLeft className="h-4 w-4" />
        </Button>
      </Link>
      <div className="space-y-2">
        <p className="text-sm text-muted-foreground">Last updated: 17 Feb 2026</p>
        <h1 className="text-3xl font-bold">Privacy Policy</h1>
        <p className="text-muted-foreground">
          This personal, non-commercial project collects limited data to provide the alerting service and protect the platform. Below is a concise overview of what is collected, why, and how you can exercise your rights under GDPR.
        </p>
      </div>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">Data collected</h2>
        <ul className="list-disc pl-6 space-y-1 text-muted-foreground">
          <li>Account data: username, email, password hash.</li>
          <li>
            Security data: TOTP secrets, recovery codes, passkey/WebAuthn credentials (all encrypted at rest),
            authentication logs and IP addresses for security and anti-abuse.
          </li>
          <li>
            OAuth data: linked provider accounts (Google, GitHub, Discord) and associated provider emails.
          </li>
          <li>
            Alert configuration: rules, price/wear filters, StatTrak/Souvenir
            filters, sticker preference.
          </li>
          <li>Notifications: webhook URLs (stored encrypted) and related metadata.</li>
          <li>Avatar data: custom uploaded avatars and Gravatar display preferences.</li>
          <li>Moderation data: account restriction history (sanctions, reasons, durations).</li>
          <li>System logs: technical logs to monitor performance and reliability.</li>
        </ul>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">Purposes and legal bases</h2>
        <ul className="list-disc pl-6 space-y-1 text-muted-foreground">
          <li>Provide the alerting service and notifications (user request).</li>
          <li>Security, fraud/abuse prevention, and audit trail (legitimate interest).</li>
          <li>Account management and support (user request).</li>
        </ul>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">Retention</h2>
        <p className="text-muted-foreground">
          Data is kept only as long as needed for the purposes above.
          Authentication and audit logs are retained for a limited period necessary
          for security. Alerts and rules are kept while your account is active.
        </p>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">Cookies and tracking</h2>
        <p className="text-muted-foreground">
          Only technical cookies or session storage required for authentication
          and application functionality are used. No advertising or analytics
          cookies are used.
        </p>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">Data sharing and hosting</h2>
        <p className="text-muted-foreground">
          Data is hosted in the European Union and not sold. Webhook payloads are
          sent to the destinations you configure. Infrastructure providers
          (hosting, email or notification services) act as sub-processors where
          applicable.
        </p>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">Your rights (GDPR)</h2>
        <ul className="list-disc pl-6 space-y-1 text-muted-foreground">
          <li>Access, rectification, deletion, restriction, and portability of your personal data.</li>
          <li>Objection to processing based on legitimate interest.</li>
          <li>Withdraw consent (where applicable) without affecting prior processing.</li>
          <li>
            Lodge a complaint with your supervisory authority (Belgian Data
            Protection Authority – Autorité de protection des données).
          </li>
        </ul>
        <p className="text-muted-foreground">
          <strong>Note:</strong> If your account is restricted (temporarily or permanently),
          self-service features such as data export and account deletion are
          unavailable. To exercise your GDPR rights while restricted, contact the
          operator at{" "}
          <a className="underline" href="mailto:admin@oswaaaald.be">admin@oswaaaald.be</a>
          {" "}who will process your request manually.
        </p>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">Contact</h2>
        <p className="text-muted-foreground">
          For any privacy request (access, deletion, questions), contact the site
          operator at{" "}
          <a className="underline" href="mailto:admin@oswaaaald.be">
            admin@oswaaaald.be
          </a>
          . This is a personal, non-commercial project operated from Belgium.
        </p>
      </section>
    </div>
  );
}
