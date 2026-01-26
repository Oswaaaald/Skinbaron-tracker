import { ProtectedRoute } from "@/components/protected-route"

export default function WebhooksLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <ProtectedRoute>
      {children}
    </ProtectedRoute>
  )
}
