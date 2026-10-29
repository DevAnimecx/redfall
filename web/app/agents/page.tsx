'use client';

import { Bot, CheckCircle2, CircleDashed, FolderGit2 } from 'lucide-react';

import { api } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { PageShell } from '@/components/page-shell';
import { ApiDown } from '@/components/api-down';
import { Stat } from '@/components/stat';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Skeleton } from '@/components/ui/skeleton';

export default function AgentsPage() {
  const agents = useApi(() => api.agents());
  const reasoning = useApi(() => api.reasoning());
  const projects = useApi(() => api.projects());

  if (agents.error) {
    return (
      <PageShell title="Agents">
        <ApiDown error={agents.error} onRetry={agents.reload} />
      </PageShell>
    );
  }

  const list = agents.data?.agents || [];
  const installed = list.filter((a) => a.installed);
  const missing = list.filter((a) => !a.installed);

  return (
    <PageShell
      title="Agents"
      subtitle="RedFall borrows the agent you already run. Detection is a real probe of the executable, not a configuration claim — and certification makes the agent answer a real prompt before it is trusted."
      actions={
        <Badge variant="outline" className="border-sev-ok/40 bg-sev-ok/10 text-sev-ok">
          {installed.length} ready
        </Badge>
      }
    >
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="Supported" value={agents.loading ? <Skeleton className="h-7 w-10" /> : agents.data?.supported ?? 0} />
        <Stat label="Installed" value={installed.length} tone="var(--sev-ok)" />
        <Stat label="Missing" value={missing.length} tone="var(--muted-foreground)" />
        <Stat
          label="Repos exposed"
          value={projects.loading ? <Skeleton className="h-7 w-10" /> : projects.data?.projects?.length ?? 0}
          sub="scan targets"
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Bot className="size-4 text-primary" /> Detected on this machine
            </CardTitle>
            <CardDescription>Probed just now, cached per session.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-1">
            {agents.loading ? (
              <div className="space-y-2">
                <Skeleton className="h-12 w-full" />
                <Skeleton className="h-12 w-full" />
              </div>
            ) : installed.length ? (
              installed.map((a) => (
                <div key={a.name} className="flex items-center gap-3 rounded-lg px-2 py-2.5 hover:bg-accent">
                  <CheckCircle2 className="size-4 shrink-0 text-sev-ok" />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-medium">{a.title}</div>
                    <div className="truncate font-mono text-[11px] text-muted-foreground">
                      {a.executable || a.name}
                    </div>
                  </div>
                  {a.version ? (
                    <Badge variant="secondary" className="shrink-0 font-mono text-[10px]">
                      {a.version}
                    </Badge>
                  ) : null}
                </div>
              ))
            ) : (
              <div className="flex flex-col items-center gap-1 rounded-xl border border-dashed py-10 text-center">
                <p className="text-sm font-semibold">No agent detected</p>
                <p className="max-w-sm text-xs text-muted-foreground">
                  Install one — or set a provider key and RedFall uses a hosted model instead.
                </p>
              </div>
            )}
          </CardContent>
        </Card>

        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Reasoning backend</CardTitle>
              <CardDescription>The effective config, as the server resolved it.</CardDescription>
            </CardHeader>
            <CardContent>
              {reasoning.loading ? (
                <Skeleton className="h-16 w-full" />
              ) : reasoning.error ? (
                <p className="text-sm text-muted-foreground">{reasoning.error}</p>
              ) : (
                <pre className="max-h-44 overflow-auto rounded-lg bg-muted/40 p-3 font-mono text-[11px] leading-relaxed">
                  {JSON.stringify(reasoning.data?.backend ?? reasoning.data?.config ?? {}, null, 2)}
                </pre>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FolderGit2 className="size-4 text-primary" /> Repositories
              </CardTitle>
              <CardDescription>
                Targets the server may scan — set with --project.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-1.5">
              {projects.data?.projects?.length ? (
                projects.data.projects.map((p) => (
                  <div key={p} className="flex items-center gap-2 text-sm">
                    <FolderGit2 className="size-3.5 shrink-0 text-muted-foreground" />
                    <span className="truncate font-mono text-xs">{p}</span>
                  </div>
                ))
              ) : (
                <p className="text-xs text-muted-foreground">
                  None exposed. Start with{' '}
                  <code className="rounded bg-muted px-1 font-mono text-[10px]">
                    redfall dashboard --project /path
                  </code>
                  .
                </p>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      {missing.length ? (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <CircleDashed className="size-4 text-muted-foreground" /> Not installed
            </CardTitle>
            <CardDescription>Shipped drivers without a binary on this host.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            {missing.map((a) => (
              <Badge key={a.name} variant="secondary" className="gap-1.5">
                <CircleDashed className="size-3" />
                {a.title}
              </Badge>
            ))}
          </CardContent>
        </Card>
      ) : null}
    </PageShell>
  );
}
