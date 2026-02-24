import Link from "next/link"
import { Button } from "@/components/ui/button"
import { ArrowLeft } from "lucide-react"

export default function TermsOfService() {
  return (
    <div className="container mx-auto p-6 space-y-8">
      <Link href="/">
        <Button variant="outline" size="icon" aria-label="Go back">
          <ArrowLeft className="h-4 w-4" />
        </Button>
      </Link>
      <div className="space-y-2">
        <p className="text-sm text-muted-foreground">Last updated: 24 Feb 2026</p>
        <h1 className="text-3xl font-bold">Terms of Service &amp; Legal Notice</h1>
        <p className="text-muted-foreground">
          By creating an account or using SkinBaron Tracker you agree to these
          terms. If you do not agree, please do not use the service.
        </p>
      </div>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">1. Nature of the service</h2>
        <p className="text-muted-foreground">
          SkinBaron Tracker is a personal, non-commercial hobby project. It
          monitors public CS2 item listings on SkinBaron and sends notifications
          based on rules you configure. It does not facilitate purchases, handle
          payments, or act as a marketplace.
        </p>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">2. Eligibility</h2>
        <p className="text-muted-foreground">
          You must be at least 16 years old to create an account. By registering
          you confirm that you meet this age requirement.
        </p>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">3. Account responsibilities</h2>
        <ul className="list-disc pl-6 space-y-1 text-muted-foreground">
          <li>You are responsible for keeping your credentials secure.</li>
          <li>You must not share accounts or create multiple accounts.</li>
          <li>You must not use the service for any unlawful purpose.</li>
          <li>You must not attempt to abuse, disrupt, or overload the service.</li>
        </ul>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">4. Acceptable use</h2>
        <ul className="list-disc pl-6 space-y-1 text-muted-foreground">
          <li>Do not scrape, spider, or programmatically access the service outside the provided interface.</li>
          <li>Do not attempt to reverse-engineer or tamper with backend systems.</li>
          <li>Webhook destinations you configure must comply with applicable laws.</li>
        </ul>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">5. Data and privacy</h2>
        <p className="text-muted-foreground">
          Your data is processed in accordance with our{" "}
          <Link className="underline" href="/privacy">Privacy Policy</Link>.
          You may export or request deletion of your data at any time.
        </p>
        <ul className="list-disc pl-6 space-y-1 text-muted-foreground">
          <li>You can view and revoke your active sessions from the settings page.</li>
          <li>IP addresses and user-agent strings are recorded for each session and in audit logs for security purposes.</li>
        </ul>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">6. Availability and warranty</h2>
        <ul className="list-disc pl-6 space-y-1 text-muted-foreground">
          <li>The service is provided &ldquo;as is&rdquo; without warranty of any kind.</li>
          <li>Uptime, accuracy, or timeliness of notifications are not guaranteed.</li>
          <li>The operator may suspend or discontinue the service at any time without prior notice.</li>
        </ul>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">7. Limitation of liability</h2>
        <p className="text-muted-foreground">
          To the maximum extent permitted by law, the operator shall not be
          liable for any indirect, incidental, or consequential damages arising
          from the use of this service, including missed alerts, delayed
          notifications, or data loss.
        </p>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">8. Intellectual property</h2>
        <p className="text-muted-foreground">
          The project branding, user interface, and code are provided for personal
          use only. Redistribution or commercial use is not permitted without
          written consent.
        </p>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">9. Moderation and termination</h2>
        <ul className="list-disc pl-6 space-y-1 text-muted-foreground">
          <li>
            The operator may temporarily or permanently restrict your account for
            violation of these terms, abuse, or any other reason, with or without
            prior notice.
          </li>
          <li>
            Restricted accounts lose access to all service features, including
            creating rules, receiving alerts, sending notifications, exporting
            data, and deleting the account. Permanent restrictions also ban the
            associated email address(es) from future registration.
          </li>
          <li>
            The specific reason for a restriction is not disclosed to the user.
            If you believe your restriction is in error, contact the operator at{" "}
            <a className="underline" href="mailto:admin@oswaaaald.be">admin@oswaaaald.be</a>.
          </li>
          <li>
            Restriction decisions and reasons are recorded internally for
            administrative and audit purposes.
          </li>
          <li>
            The operator may delete your account at any time. You may also delete
            your account at any time through the settings page (while your
            account is not restricted).
          </li>
        </ul>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">10. Disclaimer</h2>
        <p className="text-muted-foreground">
          This project is not affiliated with, endorsed by, or sponsored by
          SkinBaron, Valve, or Counter-Strike 2. All trademarks belong to their
          respective owners.
        </p>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">11. Changes to these terms</h2>
        <p className="text-muted-foreground">
          These terms may be updated from time to time. Continued use of the
          service after changes constitutes acceptance of the revised terms.
        </p>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">12. Governing law</h2>
        <p className="text-muted-foreground">
          These terms are governed by the laws of Belgium. Any disputes will be
          resolved in the courts of Belgium.
        </p>
      </section>

      <hr className="border-border" />

      <div className="space-y-2">
        <h2 className="text-2xl font-bold">Legal Notice</h2>
      </div>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">Publisher</h2>
        <ul className="list-disc pl-6 space-y-1 text-muted-foreground">
          <li>Operator: Personal project (individual, not ASBL/company).</li>
          <li>
            Contact email:{" "}
            <a className="underline" href="mailto:admin@oswaaaald.be">
              admin@oswaaaald.be
            </a>
          </li>
          <li>Country: Belgium.</li>
          <li>Purpose: hobby project providing non-commercial alerts.</li>
        </ul>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">Hosting</h2>
        <p className="text-muted-foreground">
          Hosting provider: OVHcloud (EU infrastructure).
        </p>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">Content and liability</h2>
        <ul className="list-disc pl-6 space-y-1 text-muted-foreground">
          <li>Service offered as-is without commercial guarantees.</li>
          <li>No resale of data; see the{" "}
            <Link className="underline" href="/privacy">Privacy Policy</Link>{" "}
            for processing details.
          </li>
          <li>External links and webhook destinations are the responsibility of the user configuring them.</li>
        </ul>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">Contact</h2>
        <p className="text-muted-foreground">
          For questions about these terms, contact{" "}
          <a className="underline" href="mailto:admin@oswaaaald.be">
            admin@oswaaaald.be
          </a>.
        </p>
      </section>
    </div>
  );
}
