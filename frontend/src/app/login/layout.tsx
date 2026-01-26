export default function LoginLayout({
  children,
}: {
  children: React.ReactNode
}) {
  // This layout wraps the login page and prevents the footer from showing
  return (
    <div className="fixed inset-0 w-full h-full">
      {children}
    </div>
  )
}
