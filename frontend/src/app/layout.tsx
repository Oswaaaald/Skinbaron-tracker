import type { Metadata } from "next";
import { Inter } from "next/font/google";
import Link from "next/link";
import { Github } from "lucide-react";
import "./globals.css";
import { ThemeProvider } from "@/components/theme-provider";
import { Toaster } from "@/components/ui/toaster";
import { QueryProvider } from "@/components/query-provider";
import { AuthProvider } from "@/contexts/auth-context";

const inter = Inter({ 
  subsets: ["latin"],
  display: 'swap',
  weight: ['400', '500', '600', '700'],
  preload: true,
});

export const metadata: Metadata = {
  title: "SkinBaron-Tracker",
  description: "Monitor CS2 skins on SkinBaron with custom alerts and Discord notifications",
};

export const viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 5,
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
                <footer className="border-t border-border/50 bg-muted/30 min-h-[120px] sm:min-h-[72px] flex items-center">
                  <div className="container mx-auto px-4 text-sm text-muted-foreground flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                    <span>© 2026 SkinBaron Tracker. Personal non-commercial project.</span>
                    <div className="flex gap-4">
                      <Link className="hover:text-foreground transition-colors" href="/legal">Legal Notice</Link>
                      <Link className="hover:text-foreground transition-colors" href="/privacy">Privacy Policy</Link>
                      <a 
                        href="https://github.com/Oswaaaald" 
                        target="_blank" 
                        rel="noopener noreferrer" 
                        className="hover:text-foreground transition-colors flex items-center gap-1"
                      >
                        <Github className="h-4 w-4" />
                        GitHub
                      </a>
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
