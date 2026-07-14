import type { Metadata } from 'next';
import './globals.css';
import { ThemeProvider } from '@/components/ThemeProvider';
import AuthBoundary from '@/components/AuthBoundary';

export const metadata: Metadata = {
  title: 'Marcellus Architecture Lab',
  description: 'Distributed Zero Trust security architecture with Cortex, Hearts, Arms, and Capability Nodes',
  icons: {
    icon: [
      { url: '/favicon.png', type: 'image/png', sizes: '512x512' },
    ],
    shortcut: '/favicon.png',
    apple: '/favicon.png',
  },
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <link rel="icon"             type="image/png" sizes="512x512" href="/favicon.png" />
        <link rel="icon"             type="image/png" sizes="192x192" href="/favicon.png" />
        <link rel="icon"             type="image/png" sizes="64x64"   href="/favicon.png" />
        <link rel="icon"             type="image/png" sizes="32x32"   href="/favicon.png" />
        <link rel="shortcut icon"    type="image/png"                 href="/favicon.png" />
        <link rel="apple-touch-icon" sizes="180x180"                  href="/favicon.png" />
      </head>
      <body className="min-h-screen" style={{ background: 'var(--rc-bg-base)', color: 'var(--rc-text-1)' }}>
        <ThemeProvider>
          <AuthBoundary>{children}</AuthBoundary>
        </ThemeProvider>
      </body>
    </html>
  );
}
