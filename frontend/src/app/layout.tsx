import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { ThemeProvider } from "@/components/theme-provider";
import { Toaster } from "sonner";
import { QueryProvider } from "@/components/query-provider";
import { AuthProvider } from "@/contexts/auth-context";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "SkinBaron-Tracker",
  description: "Monitor CS2 skins on SkinBaron with custom alerts and Discord notifications",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
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
          <AuthProvider>
            <QueryProvider>
              <div className="min-h-screen bg-background flex flex-col">
                <main className="flex-1">
                  {children}
                </main>
                <footer className="border-t border-border/50 bg-muted/30">
                  <div className="container mx-auto px-4 py-4 text-sm text-muted-foreground flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                    <span>© 2026 SkinBaron Tracker</span>
                    <div className="flex gap-4">
                      <a className="underline" href="/privacy">Privacy Policy</a>
                      <a className="underline" href="/legal">Legal Notice</a>
                    </div>
                  </div>
                </footer>
              </div>
              <Toaster position="bottom-right" />
            </QueryProvider>
          </AuthProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
