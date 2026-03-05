import { LegalPageLayout, LegalSection } from "@/components/legal/page-layout"

export default function PrivacyPolicy() {
  return (
    <LegalPageLayout
      title="Privacy Policy"
      updatedAt="24 Feb 2026"
      subtitle="This personal, non-commercial project collects limited data to provide alerting features and platform security."
    >
      <LegalSection title="Data collected">
        <ul className="list-disc space-y-1 pl-5">
          <li>Account data: username, email, password hash, terms-of-service acceptance timestamp.</li>
          <li>
            Security data: TOTP secrets, recovery codes, passkey/WebAuthn credentials (encrypted at rest),
            authentication audit logs with IP addresses and user-agent strings for security and anti-abuse.
          </li>
          <li>
            Session data: active session records (IP address + user-agent), used to show active sessions and
            allow individual revocation. Session metadata is deleted when sessions expire or are revoked.
          </li>
          <li>OAuth data: linked provider accounts (Google, GitHub, Discord) and associated provider emails.</li>
          <li>Alert configuration: rules, price/wear filters, StatTrak/Souvenir filters, sticker preference.</li>
          <li>Notifications: webhook URLs (stored encrypted) and related metadata.</li>
          <li>Avatar data: custom uploaded avatars and Gravatar display preferences.</li>
          <li>
            Moderation data: account restriction history (sanctions, reasons, durations). Banned email addresses
            may be retained to prevent re-registration after permanent restrictions.
          </li>
          <li>System logs: technical logs used to monitor performance and reliability.</li>
        </ul>
      </LegalSection>

      <LegalSection title="Purposes and legal bases">
        <ul className="list-disc space-y-1 pl-5">
          <li>Provide the alerting service and notifications (user request).</li>
          <li>Security, fraud/abuse prevention, and audit trail (legitimate interest).</li>
          <li>Account management and support (user request).</li>
        </ul>
      </LegalSection>

      <LegalSection title="Retention">
        <p>
          Data is kept only as long as needed for the purposes above. Authentication and audit logs are retained
          for a limited period necessary for security. Alerts and rules are kept while your account is active.
        </p>
      </LegalSection>

      <LegalSection title="Cookies and tracking">
        <p>
          Only strictly necessary technical cookies are used. No advertising, analytics, or third-party tracking
          cookies are present.
        </p>
        <ul className="list-disc space-y-1 pl-5">
          <li><strong>Authentication cookies</strong> (access token, refresh token): HttpOnly, Secure.</li>
          <li><strong>CSRF cookie</strong>: protects against cross-site request forgery attacks.</li>
          <li><strong>OAuth state cookies</strong> (temporary): used during OAuth flows and cleared afterward.</li>
          <li><strong>Cookie consent</strong>: stores your acknowledgement of the cookie banner.</li>
        </ul>
      </LegalSection>

      <LegalSection title="Data sharing and hosting">
        <p>
          Data is hosted in the European Union and is not sold. Webhook payloads are sent to destinations you
          configure. Infrastructure providers (hosting, email, notification services) act as sub-processors where applicable.
        </p>
      </LegalSection>

      <LegalSection title="Your rights (GDPR)">
        <ul className="list-disc space-y-1 pl-5">
          <li>Access, rectification, deletion, restriction, and portability of your personal data.</li>
          <li>Objection to processing based on legitimate interest.</li>
          <li>Withdraw consent (where applicable) without affecting prior processing.</li>
          <li>View and revoke active sessions at any time from the settings page.</li>
          <li>Export your personal data in machine-readable JSON format.</li>
          <li>
            Lodge a complaint with your supervisory authority (Belgian Data Protection Authority -
            Autorite de protection des donnees).
          </li>
        </ul>
        <p>
          <strong>Note:</strong> If your account is restricted, self-service export/deletion may be unavailable.
          You can still exercise your GDPR rights by contacting <a className="underline" href="mailto:admin@oswaaaald.be">admin@oswaaaald.be</a>.
        </p>
      </LegalSection>

      <LegalSection title="Contact">
        <p>
          For privacy requests (access, deletion, questions), contact the operator at
          <a className="underline" href="mailto:admin@oswaaaald.be"> admin@oswaaaald.be</a>. This is a personal,
          non-commercial project operated from Belgium.
        </p>
      </LegalSection>
    </LegalPageLayout>
  )
}
