import type { ReactNode } from 'react';

import './globals.css';

import { GeistSans } from 'geist/font/sans';
import { GeistMono } from 'geist/font/mono';
import { SidebarProvider } from '@/components/ui/sidebar';
import { TooltipProvider } from '@/components/ui/tooltip';
import { Toaster } from '@/components/ui/sonner';
import { AppSidebar } from '@/components/app-sidebar';

export const metadata = {
  title: 'RedFall Console',
  description:
    'Redfall 0.3.0 · live, execution-verified vulnerability findings, evidence and verified fixes.',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className={`${GeistSans.variable} ${GeistMono.variable} dark`}>
      <body className="font-sans antialiased">
        <TooltipProvider delayDuration={200}>
          <SidebarProvider>
            <AppSidebar />
            <main className="flex-1 overflow-x-hidden">{children}</main>
          </SidebarProvider>
        </TooltipProvider>
        <Toaster richColors position="bottom-right" />
      </body>
    </html>
  );
}
