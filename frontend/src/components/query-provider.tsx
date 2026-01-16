"use client"

import { QueryClient, QueryClientProvider } from "@tanstack/react-query"
import { ReactQueryDevtools } from "@tanstack/react-query-devtools"
import { useState } from "react"

export function QueryProvider({ children }: { children: React.ReactNode }) {
  const [queryClient] = useState(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            // With SSR, we usually want to set some default staleTime
            // above 0 to avoid refetching immediately on the client
            staleTime: 60 * 1000, // 1 minute
            refetchOnWindowFocus: true,
            refetchOnReconnect: true,
            retry: (failureCount, error: any) => {
              // Don't retry on 4xx errors (client errors)
              if (error?.status >= 400 && error?.status < 500) {
                return false;
              }
              // Retry up to 3 times for other errors
              return failureCount < 3;
            },
          },
          mutations: {
            retry: false,
          },
        },
      })
  )

  return (
    <QueryClientProvider client={queryClient}>
      {children}
      {process.env['NODE_ENV'] === 'development' && (
        <ReactQueryDevtools initialIsOpen={false} />
      )}
    </QueryClientProvider>
  )
}