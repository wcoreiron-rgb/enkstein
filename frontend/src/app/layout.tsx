import type { Metadata } from 'next';
import { Inter } from 'next/font/google';
import './globals.css';
import { ThemeProvider } from '@/components/ThemeProvider';
import AuthBoundary from '@/components/AuthBoundary';

// Self-hosted at build time by Next, so there is no runtime request to Google
// and no flash of unstyled text. Exposed as a CSS variable that globals.css
// lists first in --rc-font-sans, ahead of the native system fallbacks.
const inter = Inter({
  subsets: ['latin'],
  display: 'swap',
  variable: '--rc-font-inter',
});

export const metadata: Metadata = {
  title: 'Enkstein Architecture Lab',
  description: 'Distributed Zero Trust security architecture with Cortex, Hearts, Arms, and Capability Nodes',
  icons: {
    icon: [
      { url: '/enkstein-icon.png', type: 'image/png', sizes: '1024x1024' },
    ],
    shortcut: '/enkstein-icon.png',
    apple: '/enkstein-icon.png',
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className={inter.variable}>
      <head>
        <link rel="icon"             type="image/png" sizes="1024x1024" href="/enkstein-icon.png" />
        <link rel="icon"             type="image/png" sizes="192x192"  href="/enkstein-icon.png" />
        <link rel="icon"             type="image/png" sizes="64x64"    href="/enkstein-icon.png" />
        <link rel="icon"             type="image/png" sizes="32x32"    href="/enkstein-icon.png" />
        <link rel="shortcut icon"    type="image/png"                  href="/enkstein-icon.png" />
        <link rel="apple-touch-icon" sizes="180x180"                   href="/enkstein-icon.png" />
      </head>
      <body className="min-h-screen" style={{ background: 'var(--rc-bg-base)', color: 'var(--rc-text-1)' }}>
        <ThemeProvider>
          <AuthBoundary>{children}</AuthBoundary>
        </ThemeProvider>
      </body>
    </html>
  );
}
