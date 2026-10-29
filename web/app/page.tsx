'use client';

import Link from 'next/link';
import { ArrowRight, Bot, ShieldCheck, Zap, Wrench } from 'lucide-react';
import { api, bySeverity, SEVERITY_HEX } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { PageShell } from '@/components/page-shell';
import { ApiDown } from '@/components/api-down';
import { SevBadge } from '@/components/sev-badge';
import { SeverityBar } from '@/components/severity-bar';
import { Stat } from '@/components/stat';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { Skeleton } from '@/components/ui/skeleton';
import { EmptyBlock } from '@/components/empty-block';

export default function OverviewPage() {
  const version = useApi(() => api.version());
  const agents = useApi(() => api.agents());
  const scans = useApi(() => api.scans(6));
  const findings = useApi(() => api.findings({ limit: '200' }));

  if (version.error) {
    return (
      <PageShell title="Overview">
        <ApiDown error={version.error} onRetry={version.reload} />
      </PageShell>
    );
  }

  const counts = findings.data ? bySeverity(findings.data.findings) : {};
  const reproduced = (findings.data?.findings || []).filter((f) => f.reproduced).length;

  return (
    <PageShell
      title="Overview"
      subtitle="Findings that ran, not findings that were guessed. RedFall drives an agent you already have and proves every result by execution."
      actions={
        <>
          <Badge variant="outline" className="font-mono text-[11px]">
            v{version.data?.version ?? '…'}
          </Badge>
        </>
      }
    >
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Stat
          label="Findings"
          value={findings.loading ? <Skeleton className="h-7 w-12" /> : findings.data?.total ?? 0}
          sub={findings.data ? `${findings.data.returned} loaded` : 'loading'}
          tone={SEVERITY_HEX.critical}
        />
        <Stat
          label="Reproduced"
          value={findings.loading ? <Skeleton className="h-7 w-12" /> : reproduced}
          sub="proven by execution"
          tone={SEVERITY_HEX.low}
        />
        <Stat
          label="Agents ready"
          value={agents.loading ? <Skeleton className="h-7 w-12" /> : agents.data?.installed.length ?? 0}
          sub={agents.data ? `of ${agents.data.supported} supported` : 'detecting'}
          tone={SEVERITY_HEX.high}
        />
        <Stat
          label="Tools"
          value={version.data?.tools ?? <Skeleton className="h-7 w-12" />}
          sub="one registry, every surface"
          tone={SEVERITY_HEX.medium}
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-5">
        <Card className="lg:col-span-3">
          <CardHeader className="flex-row items-center justify-between space-y-0">
            <div>
              <CardTitle>Recent scans</CardTitle>
              <CardDescription>Newest first — open one to read its report.</CardDescription>
            </div>
            <Button asChild size="sm">
              <Link href="/live">
                New scan <ArrowRight />
              </Link>
            </Button>
          </CardHeader>
          <CardContent className="flex flex-col gap-1">
            {scans.loading ? (
              <div className="space-y-2">
                <Skeleton className="h-10 w-full" />
                <Skeleton className="h-10 w-full" />
                <Skeleton className="h-10 w-full" />
              </div>
            ) : scans.data?.campaigns.length ? (
              scans.data.campaigns.map((c) => (
                <Link
                  key={c.id}
                  href={`/results?scan=${c.id}`}
                  className="flex items-center gap-3 rounded-lg px-2 py-2.5 transition-colors hover:bg-accent"
                >
                  <span className="font-mono text-xs text-muted-foreground">
                    {c.id.slice(0, 10)}
                  </span>
                  <span className="min-w-0 flex-1 truncate text-sm">
                    {c.repo || c.objective || 'untitled target'}
                  </span>
                  <Badge variant="outline" className="shrink-0 text-[11px]">
                    {c.status || c.state || 'unknown'}
                  </Badge>
                </Link>
              ))
            ) : (
              <EmptyBlock
                title="No scans yet"
                body="Point the console at a repository and start one. A scan needs a sandbox runtime, not an API key."
              />
            )}
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader>
            <CardTitle>Reasoning backend</CardTitle>
            <CardDescription>What answers when the engine asks a question.</CardDescription>
          </CardHeader>
          <CardContent>
            <ReasoningCard />
            <Separator className="my-4" />
            <SeverityOverview counts={counts} />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>How RedFall works while you are not looking</CardTitle>
          <CardDescription>
            One registry of 46 tools serves the CLI, MCP, A2A and this console — the
            operations cannot drift apart.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Feature
            icon={<Bot className="size-4 text-primary" />}
            title="Your agent, borrowed"
            body="Twelve drivers ship today; a custom command covers the rest. No provider key required."
            href="/agents"
          />
          <Feature
            icon={<ShieldCheck className="size-4 text-sev-ok" />}
            title="Executed proofs"
            body="Nothing is a finding until its exploit ran against the live target in the sandbox."
            href="/findings"
          />
          <Feature
            icon={<Wrench className="size-4 text-sev-high" />}
            title="Fixes with receipts"
            body="The fixer works in a throwaway worktree, runs your tests and replays the PoC. Your checkout is untouched."
            href="/findings"
          />
          <Feature
            icon={<Zap className="size-4 text-sev-medium" />}
            title="Live while it hunts"
            body="Branches, findings and spend stream over SSE as the scan works."
            href="/live"
          />
        </CardContent>
      </Card>
    </PageShell>
  );
}

function Feature({
  icon,
  title,
  body,
  href,
}: {
  icon: React.ReactNode;
  title: string;
  body: string;
  href: string;
}) {
  return (
    <Link
      href={href}
      className="group rounded-lg border bg-card/40 p-4 transition-colors hover:border-primary/40 hover:bg-accent"
    >
      <div className="flex items-center gap-2 font-medium">
        {icon}
        {title}
        <ArrowRight className="ml-auto size-3.5 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
      </div>
      <p className="mt-1.5 text-[12.5px] leading-relaxed text-muted-foreground">{body}</p>
    </Link>
  );
}

function SeverityOverview({ counts }: { counts: Record<string, number> }) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  return (
    <div>
      <div className="mb-2 flex items-center justify-between text-xs text-muted-foreground">
        <span>Severity mix</span>
        <span className="font-mono">{total} total</span>
      </div>
      <SeverityBar counts={counts} />
      <div className="mt-3 flex flex-wrap gap-1.5">
        {(['critical', 'high', 'medium', 'low'] as const).map((sev) => (
          <SevBadge key={sev} severity={`${sev} · ${counts[sev] || 0}`} />
        ))}
      </div>
    </div>
  );
}

function ReasoningCard() {
  const reasoning = useApi(() => api.reasoning());
  if (reasoning.loading) return <Skeleton className="h-16 w-full" />;
  if (reasoning.error)
    return (
      <p className="text-sm text-muted-foreground">
        Configure a backend in <code className="font-mono text-xs">redfall.toml</code>.
      </p>
    );
  const backend = (reasoning.data?.backend || {}) as Record<string, unknown>;
  const config = (reasoning.data?.config || {}) as Record<string, unknown>;
  return (
    <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
      {([
        ['backend', backend.name ?? config.kind ?? 'auto'],
        ['model', backend.model ?? config.model ?? '—'],
        ['source', backend.source ?? config.source ?? 'auto-detected'],
      ] as [string, string][]).map(([k, v]) => (
        <div key={String(k)} className="contents">
          <dt className="text-muted-foreground">{k}</dt>
          <dd className="truncate font-mono text-xs">{String(v)}</dd>
        </div>
      ))}
    </dl>
  );
}

