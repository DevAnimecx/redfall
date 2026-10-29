import type { ReactNode } from 'react';

export const metadata = {
  title: 'Redfall',
  description: 'Autonomous vulnerability discovery and verified repair',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body
        style={{
          margin: 0,
          background: '#0b0f14',
          color: '#e6edf3',
          fontFamily:
            'ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif',
          fontSize: 14,
          lineHeight: 1.5,
        }}
      >
        <header
          style={{
            borderBottom: '1px solid #21262d',
            padding: '14px 24px',
            display: 'flex',
            alignItems: 'baseline',
            gap: 12,
          }}
        >
          <strong style={{ fontSize: 16, letterSpacing: 0.4 }}>REDFALL</strong>
          <span style={{ color: '#8b949e', fontSize: 12 }}>
            Redfall 0.2.0 · autonomous discovery and verified repair
          </span>
        </header>
        <main style={{ padding: 24, maxWidth: 1240, margin: '0 auto' }}>{children}</main>
      </body>
    </html>
  );
}
