export default function RegisterLayout({
  children,
}: {
  children: React.ReactNode
}) {
  // This layout wraps the register page and prevents the footer from showing
  return (
    <div className="fixed inset-0 w-full h-full">
      {children}
    </div>
  )
}
