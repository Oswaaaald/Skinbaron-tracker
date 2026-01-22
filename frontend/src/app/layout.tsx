import type { Metadata } from "next";
import { Inter } from "next/font/google";
import Link from "next/link";
import "./globals.css";
import { ThemeProvider } from "@/components/theme-provider";
import { Toaster } from "@/components/ui/toaster";
import { QueryProvider } from "@/components/query-provider";
import { AuthProvider } from "@/contexts/auth-context";

const inter = Inter({ 
  subsets: ["latin"],
  display: 'swap',
  preload: true,
});

export const metadata: Metadata = {
  title: "SkinBaron-Tracker",
  description: "Monitor CS2 skins on SkinBaron with custom alerts and Discord notifications",
};

export default async function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  // Skip SSR session check - cookies are cross-subdomain and client will handle auth
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        {/* Preconnect hints removed - next/image uses its own proxy /_next/image */}
      </head>
      <body className={inter.className}>
        <script
          dangerouslySetInnerHTML={{
            __html: `
              (function() {
                try {
                  var path = window.location.pathname;
                  var normalized = path.replace(/\\/+/g, '/');
                  if (normalized !== path) {
                    window.location.replace(normalized + window.location.search + window.location.hash);
                  }
                } catch(e) {}
              })();
            `,
          }}
        />
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
        >
          <AuthProvider initialAuth={undefined}>
            <QueryProvider>
              <div className="min-h-screen bg-background flex flex-col" style={{ minHeight: '100vh' }}>
                <main className="flex-1">
                  {children}
                </main>
                <footer className="border-t border-border/50 bg-muted/30 h-auto min-h-[120px] sm:min-h-[88px]">
                  <div className="container mx-auto px-4 py-6 text-sm text-muted-foreground flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between sm:py-4">
                    <span>© 2026 SkinBaron Tracker</span>
                    <div className="flex gap-4">
                      <Link className="underline" href="/privacy">Privacy Policy</Link>
                      <Link className="underline" href="/legal">Legal Notice</Link>
                    </div>
                  </div>
                </footer>
              </div>
              <Toaster />
            </QueryProvider>
          </AuthProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
