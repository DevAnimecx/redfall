import type { ReactNode } from 'react';
import './globals.css';
import SiteHeader from '../components/SiteHeader';

export const metadata = {
  title: 'RedFall Console',
  description:
    'Redfall 0.3.0 · live, execution-verified vulnerability findings, evidence and verified fixes.',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <SiteHeader />
        <main className="main">{children}</main>
      </body>
    </html>
  );
}
