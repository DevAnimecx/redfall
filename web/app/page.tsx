'use client';

import Link from 'next/link';
import { api, SEVERITY_COLOR, bySeverity } from '../lib/api';
import { useApi } from '../lib/useApi';
import { Card, Offline, RelativeTime, SevPill, SeverityBar, Stat } from '../components/ui';

export default function OverviewPage() {
  const version = useApi(() => api.version());
  const agents = useApi(() => api.agents());
  const scans = useApi(() => api.scans(8));
  const findings = useApi(() => api.findings({ limit: '200' }));

  const offline = version.error;
  const counts = findings.data ? bySeverity(findings.data.findings) : {};
  const total = findings.data?.total ?? 0;
  const reproduced = (findings.data?.findings || []).filter((f) => f.reproduced).length;

  return (
    <>
      <div className="hero">
        <h1>Findings that ran, not findings that were guessed.</h1>
        <p>
          RedFall drives an AI agent you already have — Claude Code, Codex, Gemini CLI and
          nine more — to hunt a repository, then proves each result by executing it in a
          sandbox. No provider key required. Nothing lands in a report until it has been
          shown to happen.
        </p>
        <div className="hero-actions">
          <Link href="/live" className="btn btn-primary">
            Start a scan
          </Link>
          <Link href="/findings" className="btn">
            Browse findings
          </Link>
          <Link href="/agents" className="btn">
            Check agents
          </Link>
        </div>
      </div>

      {offline ? (
        <Offline
          error={offline}
          hint={
            <>
              Start it with <code className="mono">redfall dashboard</code>, then reload.
            </>
          }
        />
      ) : null}

      <div className="grid grid-4">
        <Stat
          label="Findings"
          value={version.loading ? '—' : total}
          sub={findings.data ? `${findings.data.returned} loaded` : 'loading'}
          tone={SEVERITY_COLOR.critical}
        />
        <Stat
          label="Reproduced"
          value={findings.data ? reproduced : '—'}
          sub="proven by execution"
          tone={SEVERITY_COLOR.low}
        />
        <Stat
          label="Agents ready"
          value={agents.data ? agents.data.installed.length : '—'}
          sub={agents.data ? `of ${agents.data.supported} supported` : 'detecting'}
          tone={SEVERITY_COLOR.high}
        />
        <Stat
          label="Tools"
          value={version.data?.tools ?? '—'}
          sub={version.data ? `server ${version.data.version}` : 'loading'}
          tone={SEVERITY_COLOR.medium}
        />
      </div>

      <div className="split mt-16">
        <Card
          title="Recent scans"
          right={
            <Link href="/live" className="btn btn-sm">
              New scan
            </Link>
          }
        >
          {scans.loading ? (
            <p className="dim">Loading recent scans…</p>
          ) : scans.data && scans.data.campaigns.length ? (
            <table>
              <thead>
                <tr>
                  <th>Scan</th>
                  <th>Target</th>
                  <th>State</th>
                  <th>Started</th>
                </tr>
              </thead>
              <tbody>
                {scans.data.campaigns.map((c) => (
                  <tr key={c.id}>
                    <td className="mono">{c.id.slice(0, 10)}</td>
                    <td>{c.repo || c.objective || '—'}</td>
                    <td>
                      <span className="pill">
                        <span className="pill-dot" />
                        {c.status || c.state || 'unknown'}
                      </span>
                    </td>
                    <td>
                      <RelativeTime iso={c.created_at} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="empty">
              <h3>No scans yet</h3>
              <p>
                Point the console at a repository and start one. A scan needs a sandbox
                runtime, not an API key.
              </p>
            </div>
          )}
        </Card>

        <div>
          <Card title="Severity mix">
            <SeverityBar counts={counts} />
            <div className="mt-16 grid grid-2" style={{ gap: 8 }}>
              {['critical', 'high', 'medium', 'low'].map((sev) => (
                <div key={sev} className="row" style={{ justifyContent: 'space-between' }}>
                  <SevPill severity={sev} />
                  <span className="mono">{counts[sev] || 0}</span>
                </div>
              ))}
            </div>
          </Card>

          <Card title="Reasoning backend">
            <ReasoningSummary />
          </Card>
        </div>
      </div>
    </>
  );
}

function ReasoningSummary() {
  const reasoning = useApi(() => api.reasoning());
  if (reasoning.loading) return <p className="dim">Reading configuration…</p>;
  if (reasoning.error) return <p className="dim">{reasoning.error}</p>;
  const backend = (reasoning.data?.backend || {}) as Record<string, unknown>;
  const config = (reasoning.data?.config || {}) as Record<string, unknown>;
  return (
    <>
      <dl className="kv">
        <dt>backend</dt>
        <dd>{String(backend.name ?? config.kind ?? 'auto')}</dd>
        <dt>model</dt>
        <dd>{String(backend.model ?? config.model ?? '—')}</dd>
        <dt>source</dt>
        <dd>{String(backend.source ?? config.source ?? 'auto-detected')}</dd>
      </dl>
      <p className="dim mt-16" style={{ fontSize: 12.5, marginBottom: 0 }}>
        With no provider key set, RedFall borrows an installed agent. Configure a
        different backend in <code className="mono">redfall.toml</code>.
      </p>
    </>
  );
}
