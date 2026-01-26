import { ProtectedRoute } from "@/components/protected-route"

export default function RulesLayout({
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
