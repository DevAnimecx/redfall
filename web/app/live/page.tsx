'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { toast } from 'sonner';
import { CircleStop, Radar } from 'lucide-react';

import { api, bySeverity, streamScan, type CampaignStatus, type Finding } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { PageShell } from '@/components/page-shell';
import { ApiDown } from '@/components/api-down';
import { SevBadge } from '@/components/sev-badge';
import { SeverityBar } from '@/components/severity-bar';
import { Stat } from '@/components/stat';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import { Skeleton } from '@/components/ui/skeleton';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';

interface StreamEvent {
  seq: number;
  kind: string;
  payload: Record<string, unknown>;
  at: string;
}

interface BranchProgress {
  name: string;
  status: string;
  findings: number;
}

export default function LivePage() {
  const projects = useApi(() => api.projects());
  const scans = useApi(() => api.scans(12));

  const [target, setTarget] = useState('');
  const [objective, setObjective] = useState('');
  const [budget, setBudget] = useState('');
  const [activeScan, setActiveScan] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [events, setEvents] = useState<StreamEvent[]>([]);
  const [branches, setBranches] = useState<BranchProgress[]>([]);
  const [liveFindings, setLiveFindings] = useState<Finding[]>([]);
  const [spend, setSpend] = useState({ calls: 0, usd: 0 });
  const [streaming, setStreaming] = useState(false);
  const [detail, setDetail] = useState<CampaignStatus | null>(null);
  const sourceRef = useRef<EventSource | null>(null);
  const logRef = useRef<HTMLDivElement>(null);

  const defaultTarget = useMemo(() => projects.data?.projects?.[0] ?? '', [projects.data]);
  useEffect(() => {
    if (!target && defaultTarget) setTarget(defaultTarget);
  }, [defaultTarget, target]);

  const closeStream = useCallback(() => {
    sourceRef.current?.close();
    sourceRef.current = null;
    setStreaming(false);
  }, []);
  useEffect(() => () => closeStream(), [closeStream]);

  const start = useCallback(async () => {
    if (!target.trim()) {
      toast.warning('Choose a repository first');
      return;
    }
    setBusy(true);
    setEvents([]);
    setBranches([]);
    setLiveFindings([]);
    setSpend({ calls: 0, usd: 0 });
    setDetail(null);
    closeStream();
    try {
      const body: Record<string, unknown> = { target: target.trim() };
      if (objective.trim()) body.objective = objective.trim();
      if (budget.trim() && Number(budget) > 0) body.budget_usd = Number(budget);

      const accepted = await api.startScan(target.trim(), body);
      setActiveScan(accepted.scan_id);
      toast.success('Scan accepted', {
        description: 'Progress streams below — branch, findings and spend.',
      });

      const source = streamScan(accepted.scan_id, {
        onEvent: (kind, payload) => {
          setEvents((prev) => [
            ...prev.slice(-400),
            { seq: prev.length + 1, kind, payload, at: new Date().toISOString() },
          ]);
          if (kind === 'branch') {
            const name = String(payload.branch ?? payload.name ?? 'branch');
            setBranches((prev) => [
              ...prev.filter((b) => b.name !== name),
              {
                name,
                status: String(payload.status ?? 'running'),
                findings: Number(payload.findings ?? 0),
              },
            ]);
          }
          if (kind === 'finding') {
            setLiveFindings((prev) => [...prev, payload as unknown as Finding]);
            toast(`Finding: ${String(payload.title || payload.category || 'un categorised')}`, {
              description: String(payload.severity || 'severity unknown'),
            });
          }
          if (kind === 'spend') {
            setSpend({ calls: Number(payload.calls ?? 0), usd: Number(payload.usd ?? 0) });
          }
          if (kind === 'scan:done' || kind === 'scan:error') {
            if (kind === 'scan:done') {
              toast.success(`Scan finished — ${Number(payload.findings ?? 0)} findings`);
            } else {
              toast.error('Scan failed', { description: String(payload.error ?? '') });
            }
            setStreaming(false);
            closeStream();
            scans.reload();
          }
        },
        onError: () => {
          setStreaming(false);
          toast.error('Stream dropped', { description: 'The browser will retry.' });
        },
      });
      sourceRef.current = source;
      setStreaming(true);
      scans.reload();
    } catch (err) {
      toast.error('Could not start the scan', {
        description: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setBusy(false);
    }
  }, [target, objective, budget, closeStream, scans]);

  const cancel = useCallback(async () => {
    if (!activeScan) return;
    try {
      await api.cancelScan(activeScan);
      toast('Cancellation requested');
      closeStream();
    } catch (err) {
      toast.error('Cancel failed', {
        description: err instanceof Error ? err.message : String(err),
      });
    }
  }, [activeScan, closeStream]);

  const loadDetail = useCallback(async (id: string) => {
    try {
      setDetail(await api.scan(id));
    } catch {
      setDetail(null);
    }
  }, []);

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight });
  }, [events.length]);

  const counts = bySeverity(liveFindings);
  const budgetLimit = Number(budget) || 0;

  return (
    <PageShell
      title="Live scan"
      subtitle="Watch a scan as it works: which branch is running, what it found, what it spent."
      actions={
        <Badge variant="outline" className={streaming ? 'border-sev-ok/40 bg-sev-ok/10 text-sev-ok' : ''}>
          <span className={`size-1.5 rounded-full ${streaming ? 'bg-sev-ok live-dot' : 'bg-muted-foreground'}`} />
          {streaming ? 'streaming' : 'idle'}
        </Badge>
      }
    >
      {projects.error ? <ApiDown error={projects.error} onRetry={projects.reload} /> : null}

      <div className="grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Radar className="size-4 text-primary" /> Scan a repository
            </CardTitle>
            <CardDescription>
              The target must be inside the server's project roots — the same gate the
              agent gateways use.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="target">Repository</Label>
                {projects.data?.projects?.length ? (
                  <Select value={target} onValueChange={setTarget}>
                    <SelectTrigger id="target" className="w-full">
                      <SelectValue placeholder="choose a project" />
                    </SelectTrigger>
                    <SelectContent>
                      {projects.data.projects.map((p) => (
                        <SelectItem key={p} value={p}>
                          <span className="font-mono text-xs">{p}</span>
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                ) : (
                  <Input
                    id="target"
                    value={target}
                    placeholder="/absolute/path/to/repo"
                    onChange={(e) => setTarget(e.target.value)}
                    className="font-mono text-xs"
                  />
                )}
              </div>
              <div className="space-y-2">
                <Label htmlFor="budget">Budget (USD)</Label>
                <Input
                  id="budget"
                  value={budget}
                  inputMode="decimal"
                  placeholder="unlimited"
                  onChange={(e) => setBudget(e.target.value)}
                />
              </div>
            </div>
            <div className="space-y-2">
              <Label htmlFor="objective">Objective (optional)</Label>
              <Input
                id="objective"
                value={objective}
                placeholder="e.g. focus on the authentication surface"
                onChange={(e) => setObjective(e.target.value)}
              />
            </div>
            <div className="flex gap-2">
              <Button onClick={start} disabled={busy || streaming}>
                {busy ? 'Starting…' : 'Start scan'}
              </Button>
              <Button variant="outline" onClick={cancel} disabled={!activeScan || !streaming}>
                <CircleStop /> Cancel
              </Button>
            </div>
          </CardContent>
        </Card>

        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <Stat label="Findings" value={liveFindings.length} />
            <Stat label="Agent calls" value={spend.calls} />
          </div>
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Spend</CardTitle>
            </CardHeader>
            <CardContent>
              {budgetLimit > 0 ? (
                <>
                  <Progress value={Math.min(100, (spend.usd / budgetLimit) * 100)} />
                  <p className="mt-2 font-mono text-xs text-muted-foreground">
                    ${spend.usd.toFixed(4)} of ${budgetLimit.toFixed(2)}
                  </p>
                </>
              ) : (
                <>
                  <p className="font-mono text-xs">${spend.usd.toFixed(4)} spent</p>
                  <p className="mt-1 text-[11px] text-muted-foreground">
                    no budget set — the scan runs to completion
                  </p>
                </>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      <div className="grid gap-4 xl:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Branch tree</CardTitle>
            <CardDescription>{branches.length} branches seen</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {branches.length ? (
              branches.map((b) => (
                <div key={b.name} className="flex items-center gap-3 text-sm">
                  <span
                    className={`size-2 rounded-full ${
                      b.status === 'done' || b.status === 'complete'
                        ? 'bg-sev-ok'
                        : 'bg-primary live-dot'
                    }`}
                  />
                  <span className="min-w-0 flex-1 truncate font-medium">{b.name}</span>
                  <Badge variant="secondary" className="shrink-0 text-[10px]">
                    {b.findings} found
                  </Badge>
                </div>
              ))
            ) : (
              <p className="text-xs text-muted-foreground">
                Nothing running. Start a scan and each explorer branch appears as it works.
              </p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Live findings</CardTitle>
            <CardDescription>As they are proven, in order.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2.5">
            {liveFindings.length ? (
              liveFindings.slice(-8).map((f, i) => (
                <div key={`${f.id}-${i}`} className="flex items-center gap-2 text-sm">
                  <SevBadge severity={f.severity} />
                  <span className="min-w-0 flex-1 truncate">{f.title || f.category}</span>
                </div>
              ))
            ) : (
              <p className="text-xs text-muted-foreground">No findings yet.</p>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Event log</CardTitle>
            <CardDescription>{events.length} events</CardDescription>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-40">
              <div ref={logRef} className="font-mono text-[11px] leading-relaxed text-muted-foreground">
                {events.length ? (
                  events.slice(-80).map((e) => (
                    <div key={e.seq} className="truncate">
                      <span className="text-primary">{e.kind}</span>{' '}
                      {JSON.stringify(e.payload).slice(0, 120)}
                    </div>
                  ))
                ) : (
                  <p>No events yet.</p>
                )}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      </div>

      {scans.data?.campaigns.length ? (
        <Card>
          <CardHeader>
            <CardTitle>Past scans</CardTitle>
            <CardDescription>Pick one to inspect its stored state.</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-wrap gap-2">
            {scans.data.campaigns.slice(0, 10).map((c) => (
              <Button
                key={c.id}
                variant="outline"
                size="sm"
                onClick={() => {
                  setActiveScan(c.id);
                  loadDetail(c.id);
                }}
              >
                <span className="font-mono">{c.id.slice(0, 8)}</span>
                <Separator orientation="vertical" className="!h-3.5" />
                {c.repo?.split(/[\\/]/).pop() || 'scan'}
              </Button>
            ))}
          </CardContent>
        </Card>
      ) : null}

      {detail ? (
        <Card>
          <CardHeader>
            <CardTitle>Scan {detail.id.slice(0, 12)}</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-[auto_1fr] gap-x-5 gap-y-1.5 text-sm">
              <dt className="text-muted-foreground">status</dt>
              <dd className="font-mono text-xs">{detail.status || detail.state || '—'}</dd>
              <dt className="text-muted-foreground">findings</dt>
              <dd className="font-mono text-xs">{detail.findings?.length ?? 0}</dd>
            </dl>
          </CardContent>
        </Card>
      ) : null}
    </PageShell>
  );
}
