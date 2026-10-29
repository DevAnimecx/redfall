'use client';

import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  api,
  streamScan,
  SEVERITY_COLOR,
  type CampaignStatus,
  type Finding,
} from '../../lib/api';
import { useApi } from '../../lib/useApi';
import { Card, Meter, Offline, SevPill, SeverityBar, Stat } from '../../components/ui';
import { bySeverity } from '../../lib/api';

interface StreamEvent {
  seq: number;
  kind: string;
  scan_id: string | null;
  payload: Record<string, unknown>;
  at: string;
}

interface BranchProgress {
  name: string;
  status: string;
  findings: number;
  at: string;
}

export default function LivePage() {
  const projects = useApi(() => api.projects());
  const scans = useApi(() => api.scans(20));

  const [target, setTarget] = useState('');
  const [objective, setObjective] = useState('');
  const [budget, setBudget] = useState('');
  const [activeScan, setActiveScan] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);
  const [events, setEvents] = useState<StreamEvent[]>([]);
  const [branches, setBranches] = useState<BranchProgress[]>([]);
  const [liveFindings, setLiveFindings] = useState<Finding[]>([]);
  const [spend, setSpend] = useState<{ calls: number; usd: number }>({ calls: 0, usd: 0 });
  const [streaming, setStreaming] = useState(false);
  const [detail, setDetail] = useState<CampaignStatus | null>(null);
  const sourceRef = useRef<EventSource | null>(null);

  const defaultTarget = useMemo(() => {
    const list = projects.data?.projects || [];
    return list[0] || '';
  }, [projects.data]);

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
      setNotice('Choose a repository path first.');
      return;
    }
    setBusy(true);
    setNotice(null);
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
      setNotice(
        'Scan accepted. The server runs it on a worker thread; progress arrives below.',
      );

      const source = streamScan(accepted.scan_id, {
        onEvent: (kind, payload) => {
          setEvents((prev) => [
            ...prev.slice(-400),
            {
              seq: prev.length + 1,
              kind,
              scan_id: null,
              payload,
              at: new Date().toISOString(),
            },
          ]);
          if (kind === 'branch') {
            const name = String(payload.branch ?? payload.name ?? 'branch');
            setBranches((prev) => {
              const rest = prev.filter((b) => b.name !== name);
              return [
                ...rest,
                {
                  name,
                  status: String(payload.status ?? 'running'),
                  findings: Number(payload.findings ?? 0),
                  at: new Date().toISOString(),
                },
              ];
            });
          }
          if (kind === 'finding') {
            setLiveFindings((prev) => [...prev, payload as unknown as Finding]);
          }
          if (kind === 'spend') {
            setSpend({
              calls: Number(payload.calls ?? 0),
              usd: Number(payload.usd ?? 0),
            });
          }
          if (kind === 'scan:done' || kind === 'scan:error') {
            setStreaming(false);
            closeStream();
          }
        },
        onError: () => setStreaming(false),
      });
      sourceRef.current = source;
      setStreaming(true);
      scans.reload();
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }, [target, objective, budget, closeStream, scans]);

  const cancel = useCallback(async () => {
    if (!activeScan) return;
    try {
      await api.cancelScan(activeScan);
      setNotice('Cancellation requested.');
      closeStream();
    } catch (err) {
      setNotice(err instanceof Error ? err.message : String(err));
    }
  }, [activeScan, closeStream]);

  const loadDetail = useCallback(
    async (id: string) => {
      try {
        setDetail(await api.scan(id));
      } catch (err) {
        setNotice(err instanceof Error ? err.message : String(err));
      }
    },
    [],
  );

  const counts = bySeverity(liveFindings);
  const budgetLimit = Number(budget) || 0;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Live scan</h1>
          <p className="subtitle">
            Watch a scan as it runs: which branch is working, what it found, what it spent.
          </p>
        </div>
        <span className="live">
          <span className={`live-dot${streaming ? '' : ' offline'}`} />
          {streaming ? 'streaming' : 'idle'}
        </span>
      </div>

      {projects.error ? (
        <Offline
          error={projects.error}
          hint={
            <>
              Run <code className="mono">redfall dashboard --project .</code> to expose a
              repo, then reload.
            </>
          }
        />
      ) : null}

      {notice ? <div className="error-box">{notice}</div> : null}

      <div className="split">
        <div>
          <Card title="Scan a repository">
            <div className="grid grid-2" style={{ gap: 12 }}>
              <div>
                <label htmlFor="target">Repository</label>
                {projects.data && projects.data.projects.length ? (
                  <select
                    id="target"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                  >
                    {projects.data.projects.map((p) => (
                      <option key={p} value={p}>
                        {p}
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    id="target"
                    value={target}
                    placeholder="/absolute/path/to/repo"
                    onChange={(e) => setTarget(e.target.value)}
                  />
                )}
              </div>
              <div>
                <label htmlFor="budget">Budget (USD, optional)</label>
                <input
                  id="budget"
                  value={budget}
                  inputMode="decimal"
                  placeholder="unlimited"
                  onChange={(e) => setBudget(e.target.value)}
                />
              </div>
            </div>
            <div className="mt-16">
              <label htmlFor="objective">Objective (optional)</label>
              <input
                id="objective"
                value={objective}
                placeholder="e.g. focus on the authentication surface"
                onChange={(e) => setObjective(e.target.value)}
              />
            </div>
            <div className="row mt-16">
              <button className="btn btn-primary" onClick={start} disabled={busy || streaming}>
                {busy ? 'Starting…' : 'Start scan'}
              </button>
              <button className="btn" onClick={cancel} disabled={!activeScan || !streaming}>
                Cancel
              </button>
            </div>
          </Card>

          <Card
            title="Branch tree"
            right={<span className="faint mono">{branches.length} branches</span>}
          >
            {branches.length ? (
              <ul className="timeline">
                {branches.map((b) => (
                  <li
                    key={b.name}
                    className={b.status === 'done' || b.status === 'complete' ? 'done' : 'active'}
                  >
                    <div className="row" style={{ justifyContent: 'space-between' }}>
                      <span className="tl-title">{b.name}</span>
                      <span className="pill">
                        <span className="pill-dot" />
                        {b.status}
                      </span>
                    </div>
                    <div className="tl-body">
                      {b.findings} finding{b.findings === 1 ? '' : 's'} so far
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="empty">
                <h3>Nothing running</h3>
                <p>Start a scan and each explorer branch appears here as it works.</p>
              </div>
            )}
          </Card>

          <Card title="Event stream" right={<span className="faint mono">{events.length}</span>}>
            {events.length ? (
              <pre className="code-block">
                {events
                  .slice(-40)
                  .map((e) => `[${e.kind}] ${JSON.stringify(e.payload)}`)
                  .join('\n')}
              </pre>
            ) : (
              <p className="dim">No events yet.</p>
            )}
          </Card>
        </div>

        <div>
          <div className="grid grid-2" style={{ gap: 12 }}>
            <Stat label="Findings" value={liveFindings.length} tone={SEVERITY_COLOR.critical} />
            <Stat label="Agent calls" value={spend.calls} tone={SEVERITY_COLOR.medium} />
          </div>

          <Card title="Spend">
            {budgetLimit > 0 ? (
              <Meter
                label="budget used"
                value={Math.round((spend.usd / budgetLimit) * 100)}
                max={100}
                tone={spend.usd >= budgetLimit ? SEVERITY_COLOR.critical : undefined}
              />
            ) : (
              <p className="dim">No budget set — the scan runs to completion.</p>
            )}
            <p className="mono mt-16" style={{ marginBottom: 0 }}>
              ${spend.usd.toFixed(4)} spent
            </p>
          </Card>

          <Card title="Severity mix">
            <SeverityBar counts={counts} />
            <div className="row mt-16" style={{ gap: 6 }}>
              {Object.entries(counts).map(([sev, n]) => (
                <SevPill key={sev} severity={`${sev} ${n}`} />
              ))}
            </div>
          </Card>

          <Card title="Past scans">
            {scans.data?.campaigns.length ? (
              <ul className="timeline">
                {scans.data.campaigns.slice(0, 8).map((c) => (
                  <li key={c.id} className={c.status === 'running' ? 'active' : 'done'}>
                    <button
                      className="btn btn-sm"
                      onClick={() => {
                        setActiveScan(c.id);
                        loadDetail(c.id);
                      }}
                    >
                      {c.id.slice(0, 8)}
                    </button>
                    <div className="tl-body">{c.repo || c.objective || '—'}</div>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="dim">No scans recorded yet.</p>
            )}
          </Card>

          {detail ? (
            <Card title="Scan detail">
              <dl className="kv">
                <dt>id</dt>
                <dd>{detail.id}</dd>
                <dt>status</dt>
                <dd>{detail.status || detail.state || '—'}</dd>
                <dt>findings</dt>
                <dd>{detail.findings?.length ?? 0}</dd>
              </dl>
            </Card>
          ) : null}
        </div>
      </div>
    </>
  );
}
