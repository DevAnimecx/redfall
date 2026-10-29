'use client';

import { Suspense, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { FileDown } from 'lucide-react';

import { api, bySeverity, type Finding } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { PageShell } from '@/components/page-shell';
import { ApiDown } from '@/components/api-down';
import { SevBadge } from '@/components/sev-badge';
import { SeverityBar } from '@/components/severity-bar';
import { Stat } from '@/components/stat';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';

export default function ResultsPage() {
  return (
    <Suspense fallback={<Skeleton className="h-40 w-full" />}>
      <ResultsInner />
    </Suspense>
  );
}

function ResultsInner() {
  const params = useSearchParams();
  const initial = params.get('scan') || '';
  return <ResultsBody initialScan={initial} />;
}

function ResultsBody({ initialScan }: { initialScan: string }) {
  const scans = useApi(() => api.scans(25));
  const campaigns = scans.data?.campaigns || [];
  const [picked, setPicked] = useState(initialScan);
  const active = picked || campaigns[0]?.id || '';

  const report = useApi(() => (active ? api.report(active) : Promise.resolve(null)), [active]);
  const detail = useApi(() => (active ? api.scan(active) : Promise.resolve(null)), [active]);

  if (scans.error) {
    return (
      <PageShell title="Results">
        <ApiDown error={scans.error} onRetry={scans.reload} />
      </PageShell>
    );
  }

  const findings = (report.data?.findings || detail.data?.findings || []) as Finding[];
  const counts = bySeverity(findings);
  const reproduced = findings.filter((f) => f.reproduced).length;
  const rate = findings.length ? Math.round((reproduced / findings.length) * 100) : 0;

  return (
    <PageShell
      title="Results"
      subtitle="The finished report for a scan, read live from the server rather than a file written to disk."
      actions={
        campaigns.length ? (
          <Select
            value={active}
            onValueChange={(v) => {
              setPicked(v);
            }}
          >
            <SelectTrigger className="w-[240px]">
              <SelectValue placeholder="choose a scan" />
            </SelectTrigger>
            <SelectContent>
              {campaigns.map((c) => (
                <SelectItem key={c.id} value={c.id}>
                  <span className="font-mono text-xs">{c.id.slice(0, 8)}</span>
                  {' · '}
                  {c.repo?.split(/[\\/]/).pop() || c.objective || 'scan'}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        ) : null
      }
    >
      {!campaigns.length && !scans.loading ? (
        <div className="flex flex-col items-center gap-1 rounded-xl border border-dashed py-16 text-center">
          <p className="text-sm font-semibold">No reports yet</p>
          <p className="max-w-sm text-xs text-muted-foreground">
            Run a scan, then come back — the report is generated from what the sandbox proved.
          </p>
        </div>
      ) : null}

      {active ? (
        <>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            <Stat label="Findings" value={findings.length} />
            <Stat label="Reproduced" value={reproduced} tone="var(--sev-ok)" />
            <Stat label="Repro rate" value={`${rate}%`} tone="var(--sev-low)" />
            <Stat
              label="Scan state"
              value={detail.data?.status || detail.data?.state || '—'}
            />
          </div>

          <div className="grid gap-4 lg:grid-cols-5">
            <Card className="lg:col-span-3">
              <CardHeader>
                <CardTitle>Findings in this report</CardTitle>
                <CardDescription>
                  Scan <span className="font-mono">{active.slice(0, 12)}</span>
                </CardDescription>
              </CardHeader>
              <CardContent>
                {report.loading || detail.loading ? (
                  <div className="space-y-2">
                    <Skeleton className="h-9 w-full" />
                    <Skeleton className="h-9 w-full" />
                  </div>
                ) : findings.length ? (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead className="w-28">Severity</TableHead>
                        <TableHead>Finding</TableHead>
                        <TableHead className="hidden md:table-cell">Location</TableHead>
                        <TableHead className="w-20">Proof</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {findings.map((f) => (
                        <TableRow key={f.id}>
                          <TableCell>
                            <SevBadge severity={f.severity} />
                          </TableCell>
                          <TableCell className="font-medium">
                            {f.title || f.category}
                          </TableCell>
                          <TableCell className="hidden font-mono text-xs md:table-cell">
                            {f.file || '—'}
                            {f.line ? `:${f.line}` : ''}
                          </TableCell>
                          <TableCell>
                            {f.reproduced ? (
                              <Badge
                                variant="outline"
                                className="border-sev-ok/40 bg-sev-ok/10 text-sev-ok"
                              >
                                ran
                              </Badge>
                            ) : (
                              <Badge variant="secondary" className="text-[10px]">
                                static
                              </Badge>
                            )}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                ) : (
                  <div className="flex flex-col items-center gap-1 rounded-xl border border-dashed py-10 text-center">
                    <p className="text-sm font-semibold">Nothing was proven</p>
                    <p className="max-w-xs text-xs text-muted-foreground">
                      This scan completed without a finding that survived execution. That is a
                      result, not a failure.
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>

            <div className="space-y-4 lg:col-span-2">
              <Card>
                <CardHeader>
                  <CardTitle>Severity mix</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <SeverityBar counts={counts} />
                  <div className="flex flex-wrap gap-1.5">
                    {(['critical', 'high', 'medium', 'low'] as const).map((sev) => (
                      <SevBadge key={sev} severity={`${sev} · ${counts[sev] || 0}`} />
                    ))}
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Export</CardTitle>
                  <CardDescription>
                    The same bundle CI reads — nothing is formatted for the console alone.
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <pre className="overflow-x-auto rounded-lg bg-muted/40 p-3 font-mono text-[11px] leading-relaxed">
{`curl -s http://127.0.0.1:8787/api/reports/${active}`}
                  </pre>
                  <Button variant="outline" size="sm" asChild>
                    <a
                      href={`${process.env.NEXT_PUBLIC_REDFALL_API || 'http://127.0.0.1:8787'}/api/reports/${active}`}
                      target="_blank"
                      rel="noreferrer"
                    >
                      <FileDown /> Open report JSON
                    </a>
                  </Button>
                </CardContent>
              </Card>
            </div>
          </div>
        </>
      ) : null}
    </PageShell>
  );
}
