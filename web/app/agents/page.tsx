'use client';

import { api } from '../../lib/api';
import { useApi } from '../../lib/useApi';
import { Card, Offline, Stat } from '../../components/ui';

export default function AgentsPage() {
  const agents = useApi(() => api.agents());
  const reasoning = useApi(() => api.reasoning());
  const projects = useApi(() => api.projects());

  const list = agents.data?.agents || [];
  const installed = list.filter((a) => a.installed);
  const missing = list.filter((a) => !a.installed);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Agents</h1>
          <p className="subtitle">
            RedFall borrows the agent you already run. Detection is a real probe of the
            executable, not a configuration claim.
          </p>
        </div>
        <span className="pill">{agents.data?.installed.length ?? 0} ready</span>
      </div>

      {agents.error ? (
        <Offline
          error={agents.error}
          hint={
            <>
              Start the API with <code className="mono">redfall dashboard</code>.
            </>
          }
        />
      ) : null}

      <div className="grid grid-4">
        <Stat label="Supported" value={agents.data?.supported ?? '—'} />
        <Stat label="Installed" value={installed.length} tone="#2ecc71" />
        <Stat label="Missing" value={missing.length} tone="#5d6b7c" />
        <Stat label="Repos exposed" value={projects.data?.projects.length ?? '—'} />
      </div>

      <div className="split mt-16">
        <Card title="Detected on this machine">
          {agents.loading ? (
            <p className="dim">Probing each agent…</p>
          ) : installed.length ? (
            installed.map((a) => (
              <div className="agent-row" key={a.name}>
                <div>
                  <div className="agent-name">{a.title}</div>
                  <div className="agent-meta">{a.executable || a.name}</div>
                </div>
                <div className="row">
                  {a.version ? <span className="agent-meta">{a.version}</span> : null}
                  <span className="pill ok">
                    <span className="pill-dot" />
                    ready
                  </span>
                </div>
              </div>
            ))
          ) : (
            <div className="empty">
              <h3>No agent detected</h3>
              <p>
                Install one — or set a provider key and RedFall will use a hosted model
                instead.
              </p>
            </div>
          )}
        </Card>

        <div>
          <Card title="Reasoning backend">
            {reasoning.loading ? (
              <p className="dim">Reading…</p>
            ) : reasoning.error ? (
              <p className="dim">{reasoning.error}</p>
            ) : (
              <pre className="code-block">
                {JSON.stringify(reasoning.data?.backend ?? reasoning.data?.config ?? {}, null, 2)}
              </pre>
            )}
          </Card>

          <Card title="Not installed">
            {missing.length ? (
              missing.map((a) => (
                <div className="agent-row" key={a.name}>
                  <div className="agent-name">{a.title}</div>
                  <span className="faint mono" style={{ fontSize: 11.5 }}>
                    not found
                  </span>
                </div>
              ))
            ) : (
              <p className="dim">Every supported agent is present.</p>
            )}
          </Card>

          <Card title="Repositories">
            {projects.data?.projects.length ? (
              <ul className="timeline">
                {projects.data.projects.map((p) => (
                  <li key={p} className="done">
                    <div className="tl-title mono" style={{ fontSize: 12.5 }}>
                      {p}
                    </div>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="dim">
                None exposed. Start with{' '}
                <code className="mono">redfall dashboard --project /path</code>.
              </p>
            )}
          </Card>
        </div>
      </div>
    </>
  );
}
