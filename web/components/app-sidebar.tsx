'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Activity, Crosshair, LayoutDashboard, ShieldAlert, Bot, FileBarChart } from 'lucide-react';

import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
} from '@/components/ui/sidebar';

const NAV = [
  { href: '/', label: 'Overview', icon: LayoutDashboard },
  { href: '/live', label: 'Live scan', icon: Activity },
  { href: '/findings', label: 'Findings', icon: ShieldAlert, match: 'findings' },
  { href: '/agents', label: 'Agents', icon: Bot },
  { href: '/results', label: 'Results', icon: FileBarChart },
];

export function AppSidebar({ installedAgents }: { installedAgents?: number }) {
  const pathname = usePathname();

  return (
    <Sidebar collapsible="icon">
      <SidebarHeader>
        <SidebarMenu>
          <SidebarMenuItem>
            <SidebarMenuButton size="lg" asChild tooltip="RedFall">
              <Link href="/">
                <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground shadow-[0_0_18px_-4px] shadow-primary/70">
                  <Crosshair className="size-4.5" />
                </span>
                <span className="flex flex-col gap-0.5 leading-none">
                  <span className="font-semibold tracking-tight">RedFall</span>
                  <span className="text-[10px] text-muted-foreground">
                    execution-verified scanning
                  </span>
                </span>
              </Link>
            </SidebarMenuButton>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarHeader>

      <SidebarContent>
        <SidebarGroup>
          <SidebarGroupLabel>Console</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {NAV.map(({ href, label, icon: Icon }) => {
                const active =
                  href === '/' ? pathname === '/' : pathname.startsWith(href);
                return (
                  <SidebarMenuItem key={href}>
                    <SidebarMenuButton asChild isActive={active} tooltip={label}>
                      <Link href={href}>
                        <Icon />
                        <span>{label}</span>
                      </Link>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                );
              })}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>

        <SidebarGroup>
          <SidebarGroupLabel>Reasoning</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              <SidebarMenuItem>
                <SidebarMenuButton asChild tooltip="Which agents RedFall can borrow">
                  <Link href="/agents">
                    <Bot />
                    <span>Agent drivers</span>
                  </Link>
                </SidebarMenuButton>
                {typeof installedAgents === 'number' ? (
                  <SidebarMenuBadge>{installedAgents}</SidebarMenuBadge>
                ) : null}
              </SidebarMenuItem>
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
      </SidebarContent>

      <SidebarFooter>
        <div className="px-2 py-1 text-[10px] leading-relaxed text-muted-foreground group-data-[collapsible=icon]:hidden">
          Findings only exist once the exploit has run in the sandbox.
        </div>
      </SidebarFooter>
    </Sidebar>
  );
}
