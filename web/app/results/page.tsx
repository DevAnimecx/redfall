'use client';

import { useState } from 'react';
import { api, bySeverity, type Finding } from '../../lib/api';
import { useApi } from '../../lib/useApi';
import { Card, Offline, SevPill, SeverityBar, Stat } from '../../components/ui';

export default function ResultsPage() {
  const scans = useApi(() => api.scans(25));
  const [selected, setSelected] = useState('');

  const campaigns = scans.data?.campaigns || [];
  const active = selected || campaigns[0]?.id || '';

  const report = useApi(
    () => (active ? api.report(active) : Promise.resolve(null)),
    [active],
  );
  const detail = useApi(
    () => (active ? api.scan(active) : Promise.resolve(null)),
    [active],
  );

  const findings = (report.data?.findings || detail.data?.findings || []) as Finding[];
  const counts = bySeverity(findings);
  const reproduced = findings.filter((f) => f.reproduced).length;
  const rate = findings.length ? Math.round((reproduced / findings.length) * 100) : 0;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Results</h1>
          <p className="subtitle">
            The finished report for a scan, read live from the server rather than a file
            written to disk.
          </p>
        </div>
        {campaigns.length ? (
          <select
            value={active}
            onChange={(e) => setSelected(e.target.value)}
            style={{ width: 'auto', minWidth: 220 }}
          >
            {campaigns.map((c) => (
              <option key={c.id} value={c.id}>
                {c.id.slice(0, 8)} · {c.repo || c.objective || 'scan'}
              </option>
            ))}
          </select>
        ) : null}
      </div>

      {scans.error ? <Offline error={scans.error} /> : null}

      {!campaigns.length && !scans.loading ? (
        <div className="empty">
          <h3>No reports yet</h3>
          <p>Run a scan, then come back — the report is generated from what it proved.</p>
        </div>
      ) : null}

      {active ? (
        <>
          <div className="grid grid-4">
            <Stat label="Findings" value={findings.length} />
            <Stat label="Reproduced" value={reproduced} tone="#2ecc71" />
            <Stat label="Repro rate" value={`${rate}%`} tone="#4dabf7" />
            <Stat
              label="Scan state"
              value={detail.data?.status || detail.data?.state || '—'}
            />
          </div>

          <div className="split mt-16">
            <Card title="Findings in this report">
              {report.loading || detail.loading ? (
                <p className="dim">Loading report…</p>
              ) : findings.length ? (
                <table>
                  <thead>
                    <tr>
                      <th>Severity</th>
                      <th>Finding</th>
                      <th>Location</th>
                      <th>Proof</th>
                    </tr>
                  </thead>
                  <tbody>
                    {findings.map((f) => (
                      <tr key={f.id}>
                        <td>
                          <SevPill severity={f.severity} />
                        </td>
                        <td style={{ fontWeight: 600 }}>{f.title || f.category}</td>
                        <td className="mono" style={{ fontSize: 12 }}>
                          {f.file || '—'}
                          {f.line ? `:${f.line}` : ''}
                        </td>
                        <td>
                          {f.reproduced ? (
                            <span className="pill ok">
                              <span className="pill-dot" />
                              ran
                            </span>
                          ) : (
                            <span className="pill">static</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="empty">
                  <h3>Nothing was proven</h3>
                  <p>
                    This scan completed without a finding that survived execution. That is
                    a result, not a failure.
                  </p>
                </div>
              )}
            </Card>

            <div>
              <Card title="Severity mix">
                <SeverityBar counts={counts} />
                <div className="mt-16 grid grid-2" style={{ gap: 8 }}>
                  {['critical', 'high', 'medium', 'low'].map((sev) => (
                    <div
                      key={sev}
                      className="row"
                      style={{ justifyContent: 'space-between' }}
                    >
                      <SevPill severity={sev} />
                      <span className="mono">{counts[sev] || 0}</span>
                    </div>
                  ))}
                </div>
              </Card>

              <Card title="Export">
                <p className="dim" style={{ marginTop: 0 }}>
                  The bundle is available over the API; wire it into CI with the same
                  endpoint the console reads.
                </p>
                <pre className="code-block">
                  {`curl -s ${typeof window === 'undefined' ? '' : window.location.origin ? '' : ''}/api/reports/${active}`}
                </pre>
                <p className="faint" style={{ fontSize: 12 }}>
                  Replace the host with your dashboard address (default
                  http://127.0.0.1:8787).
                </p>
              </Card>
            </div>
          </div>
        </>
      ) : null}
    </>
  );
}
