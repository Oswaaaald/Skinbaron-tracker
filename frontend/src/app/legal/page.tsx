export default function LegalNotice() {
  return (
    <div className="container mx-auto p-6 space-y-8">
      <div className="space-y-2">
        <p className="text-sm text-muted-foreground">Last updated: 12 Jan 2026</p>
        <h1 className="text-3xl font-bold">Legal Notice</h1>
        <p className="text-muted-foreground">
          This site is a personal, non-commercial project operated from Belgium. It provides CS2 SkinBaron alerting and related utilities. Below you will find the required publisher and hosting details.
        </p>
      </div>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">Publisher</h2>
        <ul className="list-disc pl-6 space-y-1 text-muted-foreground">
          <li>Operator: Personal project (individual, not ASBL/company).</li>
          <li>Contact email: <a className="underline" href="mailto:contact@example.com">contact@example.com</a> (replace with your real contact).</li>
          <li>Country: Belgium.</li>
          <li>Purpose: hobby project providing non-commercial alerts.</li>
        </ul>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">Hosting</h2>
        <p className="text-muted-foreground">
          Infrastructure is hosted in the EU. Fill in your hosting provider details here (name, address/URL) once finalized.
        </p>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">Content and liability</h2>
        <ul className="list-disc pl-6 space-y-1 text-muted-foreground">
          <li>Service offered as-is without commercial guarantees.</li>
          <li>No resale of data; see the Privacy Policy for processing details.</li>
          <li>External links and webhook destinations are the responsibility of the user configuring them.</li>
        </ul>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">Intellectual property</h2>
        <p className="text-muted-foreground">
          The project branding and UI are provided for personal use. Do not reuse or redistribute without permission.
        </p>
      </section>

      <section className="space-y-2">
        <h2 className="text-xl font-semibold">Contact</h2>
        <p className="text-muted-foreground">
          For any legal or privacy questions, reach out via the contact email above. For privacy-specific requests, see the Privacy Policy.
        </p>
      </section>
    </div>
  );
}
