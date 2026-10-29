'use client';

import { Suspense, useCallback, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { toast } from 'sonner';
import { FlaskConical, PlayCircle, Wrench } from 'lucide-react';

import { api, type Finding, type FixProposal } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { PageShell } from '@/components/page-shell';
import { ApiDown } from '@/components/api-down';
import { SevBadge } from '@/components/sev-badge';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Separator } from '@/components/ui/separator';
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';

export default function FindingsPage() {
  return (
    <Suspense fallback={<Skeleton className="h-40 w-full" />}>
      <FindingsInner />
    </Suspense>
  );
}

function FindingsInner() {
  const params = useSearchParams();
  const scanParam = params.get('scan') || '';

  const [severity, setSeverity] = useState('all');
  const [category, setCategory] = useState('');
  const [reproduced, setReproduced] = useState('all');
  const [selected, setSelected] = useState<string | null>(null);

  const findings = useApi(() => {
    const query: Record<string, string> = { limit: '200' };
    if (scanParam) query.scan_id = scanParam;
    if (severity !== 'all') query.severity = severity;
    if (category.trim()) query.category = category.trim();
    if (reproduced !== 'all') query.reproduced = reproduced;
    return api.findings(query);
  }, [scanParam, severity, category, reproduced]);

  const rows = findings.data?.findings || [];

  return (
    <PageShell
      title="Findings"
      subtitle="Every result carries the evidence that produced it. Nothing appears here unless it was executed against the running target."
      actions={<Badge variant="outline" className="font-mono">{findings.data?.total ?? 0} total</Badge>}
    >
      {findings.error ? <ApiDown error={findings.error} onRetry={findings.reload} /> : null}

      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm">Filters</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-3 sm:grid-cols-3">
          <div className="space-y-1.5">
            <Label>Severity</Label>
            <Select value={severity} onValueChange={setSeverity}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">any</SelectItem>
                <SelectItem value="critical">critical</SelectItem>
                <SelectItem value="high">high</SelectItem>
                <SelectItem value="medium">medium</SelectItem>
                <SelectItem value="low">low</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="f-cat">Category</Label>
            <Input
              id="f-cat"
              value={category}
              placeholder="e.g. sqli"
              onChange={(e) => setCategory(e.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label>Reproduced</Label>
            <Select value={reproduced} onValueChange={setReproduced}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">any</SelectItem>
                <SelectItem value="true">ran — proven</SelectItem>
                <SelectItem value="false">static only</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardContent>
          {findings.loading ? (
            <div className="space-y-2 py-2">
              <Skeleton className="h-9 w-full" />
              <Skeleton className="h-9 w-full" />
              <Skeleton className="h-9 w-full" />
            </div>
          ) : rows.length ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-28">Severity</TableHead>
                  <TableHead>Finding</TableHead>
                  <TableHead className="hidden md:table-cell">Location</TableHead>
                  <TableHead className="w-24">Proof</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((f) => (
                  <TableRow
                    key={f.id}
                    className="cursor-pointer"
                    onClick={() => setSelected(f.id)}
                  >
                    <TableCell>
                      <SevBadge severity={f.severity} />
                    </TableCell>
                    <TableCell>
                      <div className="font-medium">{f.title || f.category}</div>
                      <div className="text-xs text-muted-foreground">{f.category}</div>
                    </TableCell>
                    <TableCell className="hidden font-mono text-xs md:table-cell">
                      {f.file || '—'}
                      {f.line ? `:${f.line}` : ''}
                    </TableCell>
                    <TableCell>
                      {f.reproduced ? (
                        <Badge className="gap-1 border-sev-ok/40 bg-sev-ok/10 text-sev-ok" variant="outline">
                          ran
                        </Badge>
                      ) : (
                        <Badge variant="secondary" className="text-[10px]">static</Badge>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="flex flex-col items-center gap-1 rounded-xl border border-dashed py-12 text-center">
              <p className="text-sm font-semibold">No findings match</p>
              <p className="max-w-sm text-xs text-muted-foreground">
                Widen the filters, or run a scan from the live view.
              </p>
            </div>
          )}
        </CardContent>
      </Card>

      <ProofSheet
        findingId={selected}
        onClose={() => setSelected(null)}
        fallback={rows.find((r) => r.id === selected) || null}
      />
    </PageShell>
  );
}

function ProofSheet({
  findingId,
  fallback,
  onClose,
}: {
  findingId: string | null;
  fallback: Finding | null;
  onClose: () => void;
}) {
  const finding = useApi(
    () => (findingId ? api.finding(findingId) : Promise.resolve(null)),
    [findingId],
  );
  const current = (finding.data as Finding | null) || fallback;

  return (
    <Sheet open={Boolean(findingId)} onOpenChange={(open) => (open ? null : onClose())}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-lg">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2">
            {current ? <SevBadge severity={current.severity} /> : null}
            <span className="truncate">{current?.title || current?.category || 'Finding'}</span>
          </SheetTitle>
          <SheetDescription className="font-mono text-[11px]">
            {findingId}
          </SheetDescription>
        </SheetHeader>

        {current ? (
          <div className="space-y-6 px-4 pb-8">
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 text-sm">
              <dt className="text-muted-foreground">location</dt>
              <dd className="truncate font-mono text-xs">
                {current.file || '—'}
                {current.line ? `:${current.line}` : ''}
              </dd>
              {current.symbol ? (
                <>
                  <dt className="text-muted-foreground">symbol</dt>
                  <dd className="truncate font-mono text-xs">{current.symbol}</dd>
                </>
              ) : null}
              <dt className="text-muted-foreground">status</dt>
              <dd className="font-mono text-xs">{current.status || 'open'}</dd>
            </dl>

            {current.description ? (
              <section>
                <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  Description
                </h3>
                <p className="text-sm leading-relaxed">{current.description}</p>
              </section>
            ) : null}

            <section>
              <h3 className="mb-2 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                <FlaskConical className="size-3.5" /> Evidence
              </h3>
              {current.evidence ? (
                <blockquote className="border-l-2 border-primary/50 pl-3 text-sm text-muted-foreground">
                  {current.evidence}
                </blockquote>
              ) : current.evidence_ids?.length ? (
                <ol className="space-y-1.5">
                  {current.evidence_ids.map((eid, i) => (
                    <li key={eid} className="flex items-center gap-2 text-xs">
                      <span className="font-mono text-muted-foreground">{i + 1}.</span>
                      <span className="font-mono">{eid}</span>
                    </li>
                  ))}
                </ol>
              ) : (
                <p className="text-xs text-muted-foreground">
                  No evidence recorded — treat this as unproven and re-run the scan.
                </p>
              )}
            </section>

            {current.remediation ? (
              <section>
                <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                  Remediation
                </h3>
                <pre className="overflow-x-auto rounded-lg bg-muted/50 p-3 font-mono text-xs leading-relaxed">
                  {current.remediation}
                </pre>
              </section>
            ) : null}

            <Separator />

            <ReproduceRow findingId={findingId!} />
            <FixPanel findingId={findingId!} reproduced={Boolean(current.reproduced)} />
          </div>
        ) : (
          <div className="px-4 text-sm text-muted-foreground">Loading…</div>
        )}
      </SheetContent>
    </Sheet>
  );
}

function ReproduceRow({ findingId }: { findingId: string }) {
  const [busy, setBusy] = useState(false);

  const run = useCallback(async () => {
    setBusy(true);
    try {
      const out = await api.reproduce(findingId);
      const ok = Boolean(out.ok ?? out.reproduced ?? out.success);
      if (ok) {
        toast.success('Reproduced in the sandbox');
      } else {
        toast.warning('Not reproduced', { description: JSON.stringify(out).slice(0, 140) });
      }
    } catch (err) {
      toast.error('Reproduce failed', {
        description: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusy(false);
    }
  }, [findingId]);

  return (
    <div className="flex items-center justify-between gap-3">
      <div>
        <p className="text-sm font-medium">Re-run the proof</p>
        <p className="text-xs text-muted-foreground">
          Replays the stored PoC in the gVisor sandbox.
        </p>
      </div>
      <Button variant="outline" size="sm" onClick={run} disabled={busy}>
        <PlayCircle /> {busy ? 'Running…' : 'Run PoC'}
      </Button>
    </div>
  );
}

function FixPanel({ findingId, reproduced }: { findingId: string; reproduced: boolean }) {
  const [busy, setBusy] = useState(false);
  const [proposal, setProposal] = useState<FixProposal | null>(null);

  const propose = useCallback(async () => {
    setBusy(true);
    setProposal(null);
    try {
      const out = await api.fix(findingId);
      if (out.refused) {
        toast.warning(`Refused: ${out.refused}`, { description: out.reason });
      } else if (out.verified) {
        toast.success('Fix verified by execution');
      } else {
        toast('Fix proposed — not verified', { description: out.blocker || out.status });
      }
      setProposal(out);
    } catch (err) {
      toast.error('Fix attempt failed', {
        description: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusy(false);
    }
  }, [findingId]);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="flex items-center gap-1.5 text-sm font-medium">
            <Wrench className="size-3.5" /> One-click fix
          </p>
          <p className="text-xs text-muted-foreground">
            Attempted in a throwaway git worktree — your checkout is never written to.
          </p>
        </div>
        <Button size="sm" onClick={propose} disabled={busy}>
          {busy ? 'Attempting…' : 'Propose fix'}
        </Button>
      </div>

      {!reproduced ? (
        <p className="text-[11px] text-muted-foreground">
          Unproven findings are refused by default — a fix for a bug that never reproduced
          cannot be shown to work.
        </p>
      ) : null}

      {proposal && !proposal.refused ? (
        <div className="space-y-2 rounded-lg bg-muted/40 p-3">
          <div className="flex flex-wrap items-center gap-2">
            {proposal.verified ? (
              <Badge className="border-sev-ok/40 bg-sev-ok/10 text-sev-ok" variant="outline">
                verified by execution
              </Badge>
            ) : (
              <Badge variant="outline">{proposal.status || 'not verified'}</Badge>
            )}
            {proposal.strategy ? (
              <span className="font-mono text-[11px] text-muted-foreground">
                {proposal.strategy}
              </span>
            ) : null}
            {proposal.attempts ? (
              <span className="text-[11px] text-muted-foreground">
                {proposal.attempts} attempt{proposal.attempts === 1 ? '' : 's'}
              </span>
            ) : null}
          </div>
          <pre className="max-h-64 overflow-auto rounded-md bg-background p-2.5 font-mono text-[11px] leading-relaxed">
            {proposal.patch || '(no patch produced)'}
          </pre>
          {proposal.verify_log ? (
            <details>
              <summary className="cursor-pointer text-[11px] text-muted-foreground">
                verification log
              </summary>
              <pre className="mt-1.5 max-h-40 overflow-auto rounded-md bg-background p-2.5 font-mono text-[11px]">
                {proposal.verify_log}
              </pre>
            </details>
          ) : null}
          <p className="text-[11px] text-muted-foreground">{proposal.applied_note}</p>
        </div>
      ) : null}
    </div>
  );
}
