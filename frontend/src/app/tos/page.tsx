import Link from "next/link"
import { LegalPageLayout, LegalSection } from "@/components/legal/page-layout"

export default function TermsOfService() {
  return (
    <LegalPageLayout
      title="Terms of Service & Legal Notice"
      updatedAt="24 Feb 2026"
      subtitle="By creating an account or using SkinBaron Tracker you agree to these terms. If you do not agree, please do not use the service."
    >
      <LegalSection title="1. Nature of the service">
        <p>
          SkinBaron Tracker is a personal, non-commercial hobby project. It monitors public CS2 item listings on
          SkinBaron and sends notifications based on rules you configure. It does not facilitate purchases,
          handle payments, or act as a marketplace.
        </p>
      </LegalSection>

      <LegalSection title="2. Eligibility">
        <p>
          You must be at least 16 years old to create an account. By registering you confirm that you meet this
          age requirement.
        </p>
      </LegalSection>

      <LegalSection title="3. Account responsibilities">
        <ul className="list-disc space-y-1 pl-5">
          <li>You are responsible for keeping your credentials secure.</li>
          <li>You must not share accounts or create multiple accounts.</li>
          <li>You must not use the service for any unlawful purpose.</li>
          <li>You must not attempt to abuse, disrupt, or overload the service.</li>
        </ul>
      </LegalSection>

      <LegalSection title="4. Acceptable use">
        <ul className="list-disc space-y-1 pl-5">
          <li>Do not scrape, spider, or programmatically access the service outside the provided interface.</li>
          <li>Do not attempt to reverse-engineer or tamper with backend systems.</li>
          <li>Webhook destinations you configure must comply with applicable laws.</li>
        </ul>
      </LegalSection>

      <LegalSection title="5. Data and privacy">
        <p>
          Your data is processed in accordance with our <Link className="underline" href="/privacy">Privacy Policy</Link>.
          You may export or request deletion of your data at any time.
        </p>
        <ul className="list-disc space-y-1 pl-5">
          <li>You can view and revoke your active sessions from the settings page.</li>
          <li>IP addresses and user-agent strings are recorded for each session and in audit logs for security purposes.</li>
        </ul>
      </LegalSection>

      <LegalSection title="6. Availability and warranty">
        <ul className="list-disc space-y-1 pl-5">
          <li>The service is provided &quot;as is&quot; without warranty of any kind.</li>
          <li>Uptime, accuracy, or timeliness of notifications are not guaranteed.</li>
          <li>The operator may suspend or discontinue the service at any time without prior notice.</li>
        </ul>
      </LegalSection>

      <LegalSection title="7. Limitation of liability">
        <p>
          To the maximum extent permitted by law, the operator shall not be liable for any indirect, incidental,
          or consequential damages arising from the use of this service, including missed alerts, delayed
          notifications, or data loss.
        </p>
      </LegalSection>

      <LegalSection title="8. Intellectual property">
        <p>
          The project branding, user interface, and code are provided for personal use only.
          Redistribution or commercial use is not permitted without written consent.
        </p>
      </LegalSection>

      <LegalSection title="9. Moderation and termination">
        <ul className="list-disc space-y-1 pl-5">
          <li>
            The operator may temporarily or permanently restrict your account for violation of these terms, abuse,
            or any other reason, with or without prior notice.
          </li>
          <li>
            Restricted accounts lose access to all service features, including creating rules, receiving alerts,
            sending notifications, exporting data, and deleting the account. Permanent restrictions also ban the
            associated email address(es) from future registration.
          </li>
          <li>
            The specific reason for a restriction is not disclosed to the user. If you believe your restriction is in
            error, contact the operator at <a className="underline" href="mailto:admin@oswaaaald.be">admin@oswaaaald.be</a>.
          </li>
          <li>Restriction decisions and reasons are recorded internally for administrative and audit purposes.</li>
          <li>
            The operator may delete your account at any time. You may also delete your account at any time through
            the settings page (while your account is not restricted).
          </li>
        </ul>
      </LegalSection>

      <LegalSection title="10. Disclaimer">
        <p>
          This project is not affiliated with, endorsed by, or sponsored by SkinBaron, Valve, or Counter-Strike 2.
          All trademarks belong to their respective owners.
        </p>
      </LegalSection>

      <LegalSection title="11. Changes to these terms">
        <p>
          These terms may be updated from time to time. Continued use of the service after changes constitutes
          acceptance of the revised terms.
        </p>
      </LegalSection>

      <LegalSection title="12. Governing law">
        <p>
          These terms are governed by the laws of Belgium. Any disputes will be resolved in the courts of Belgium.
        </p>
      </LegalSection>

      <div className="pt-3">
        <p className="text-xs font-medium uppercase tracking-[0.12em] text-muted-foreground">Legal notice</p>
      </div>

      <LegalSection title="Publisher">
        <ul className="list-disc space-y-1 pl-5">
          <li>Operator: Personal project (individual, not ASBL/company).</li>
          <li>
            Contact email: <a className="underline" href="mailto:admin@oswaaaald.be">admin@oswaaaald.be</a>
          </li>
          <li>Country: Belgium.</li>
          <li>Purpose: hobby project providing non-commercial alerts.</li>
        </ul>
      </LegalSection>

      <LegalSection title="Hosting">
        <p>Hosting provider: OVHcloud (EU infrastructure).</p>
      </LegalSection>

      <LegalSection title="Content and liability">
        <ul className="list-disc space-y-1 pl-5">
          <li>Service offered as-is without commercial guarantees.</li>
          <li>
            No resale of data; see the <Link className="underline" href="/privacy">Privacy Policy</Link> for processing details.
          </li>
          <li>External links and webhook destinations are the responsibility of the user configuring them.</li>
        </ul>
      </LegalSection>

      <LegalSection title="Contact">
        <p>
          For questions about these terms, contact <a className="underline" href="mailto:admin@oswaaaald.be">admin@oswaaaald.be</a>.
        </p>
      </LegalSection>
    </LegalPageLayout>
  )
}
