import { Suspense } from "react"
import { Dashboard } from "@/components/dashboard"
import { LoadingSpinner } from "@/components/ui/loading-spinner"
import { ProtectedRoute } from "@/components/protected-route"

export default function Home() {
  return (
    <ProtectedRoute>
      <div className="container mx-auto p-4">
        <Suspense fallback={<LoadingSpinner />}>
          <Dashboard />
        </Suspense>
      </div>
    </ProtectedRoute>
  )
}
