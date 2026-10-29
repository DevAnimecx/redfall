'use client';

import { Suspense, useCallback, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import { api, type Finding, type FixProposal } from '../../lib/api';
import { useApi } from '../../lib/useApi';
import { Card, Offline, RelativeTime, SevPill } from '../../components/ui';

export default function FindingsPage() {
  return (
    <Suspense fallback={<p className="dim">Loading…</p>}>
      <FindingsInner />
    </Suspense>
  );
}

function FindingsInner() {
  const params = useSearchParams();
  const initialScan = params.get('scan') || '';

  const [severity, setSeverity] = useState('');
  const [category, setCategory] = useState('');
  const [reproduced, setReproduced] = useState('');
  const [selected, setSelected] = useState<string | null>(null);

  const findings = useApi(
    () => {
      const query: Record<string, string> = { limit: '200' };
      if (initialScan) query.scan_id = initialScan;
      if (severity) query.severity = severity;
      if (category) query.category = category;
      if (reproduced) query.reproduced = reproduced;
      return api.findings(query);
    },
    [initialScan, severity, category, reproduced],
  );

  const rows = findings.data?.findings || [];

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Findings</h1>
          <p className="subtitle">
            Every result carries the evidence that produced it. Nothing appears here
            unless it was executed.
          </p>
        </div>
        <span className="pill">{findings.data?.total ?? 0} total</span>
      </div>

      {findings.error ? <Offline error={findings.error} /> : null}

      <Card title="Filters">
        <div className="grid grid-4" style={{ gap: 12 }}>
          <div>
            <label htmlFor="f-sev">Severity</label>
            <select id="f-sev" value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="">any</option>
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
            </select>
          </div>
          <div>
            <label htmlFor="f-cat">Category</label>
            <input
              id="f-cat"
              value={category}
              placeholder="e.g. sqli"
              onChange={(e) => setCategory(e.target.value)}
            />
          </div>
          <div>
            <label htmlFor="f-rep">Reproduced</label>
            <select
              id="f-rep"
              value={reproduced}
              onChange={(e) => setReproduced(e.target.value)}
            >
              <option value="">any</option>
              <option value="true">yes</option>
              <option value="false">no</option>
            </select>
          </div>
          <div>
            <label htmlFor="f-scan">Scan</label>
            <input
              id="f-scan"
              value={initialScan}
              readOnly
              placeholder="any"
              className="mono"
            />
          </div>
        </div>
      </Card>

      <div className="split">
        <Card title="Results" right={<span className="faint mono">{rows.length} shown</span>}>
          {findings.loading ? (
            <p className="dim">Loading findings…</p>
          ) : rows.length ? (
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
                {rows.map((f) => (
                  <tr
                    key={f.id}
                    onClick={() => setSelected(f.id)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td>
                      <SevPill severity={f.severity} />
                    </td>
                    <td>
                      <div style={{ fontWeight: 600 }}>{f.title || f.category}</div>
                      <div className="faint" style={{ fontSize: 12 }}>
                        {f.category}
                      </div>
                    </td>
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
                        <span className="pill">
                          <span className="pill-dot" />
                          static
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="empty">
              <h3>No findings match</h3>
              <p>Widen the filters, or run a scan from the live view.</p>
            </div>
          )}
        </Card>

        <ProofPanel
          id={selected}
          fallback={rows[0] || null}
          onClose={() => setSelected(null)}
        />
      </div>
    </>
  );
}

function ProofPanel({
  id,
  fallback,
  onClose,
}: {
  id: string | null;
  fallback: Finding | null;
  onClose: () => void;
}) {
  const target = id || fallback?.id || null;
  const detail = useApi(() => (target ? api.finding(target) : Promise.resolve(null)), [target]);
  const [reproducing, setReproducing] = useState(false);
  const [result, setResult] = useState<string | null>(null);

  const finding = (detail.data as Finding | null) || (target === fallback?.id ? fallback : null);

  const reproduce = useCallback(async () => {
    if (!target) return;
    setReproducing(true);
    setResult(null);
    try {
      const out = await api.reproduce(target);
      const ok = Boolean(out.ok ?? out.reproduced ?? out.success);
      setResult(ok ? 'Reproduced in the sandbox.' : `Not reproduced: ${JSON.stringify(out)}`);
    } catch (err) {
      setResult(err instanceof Error ? err.message : String(err));
    } finally {
      setReproducing(false);
    }
  }, [target]);

  if (!finding) {
    return (
      <Card title="Proof">
        <div className="empty">
          <h3>Select a finding</h3>
          <p>
            The proof panel shows the evidence chain, the PoC that was executed, and the
            agent transcript behind the result.
          </p>
        </div>
      </Card>
    );
  }

  return (
    <Card
      title="Proof"
      right={
        onClose ? (
          <button className="btn btn-sm" onClick={onClose}>
            Clear
          </button>
        ) : null
      }
    >
      <div className="row" style={{ marginBottom: 12 }}>
        <SevPill severity={finding.severity} />
        <strong>{finding.title || finding.category}</strong>
      </div>

      <dl className="kv">
        <dt>id</dt>
        <dd>{finding.id}</dd>
        <dt>location</dt>
        <dd>
          {finding.file || '—'}
          {finding.line ? `:${finding.line}` : ''}
        </dd>
        {finding.symbol ? (
          <>
            <dt>symbol</dt>
            <dd>{finding.symbol}</dd>
          </>
        ) : null}
        <dt>status</dt>
        <dd>{finding.status || 'open'}</dd>
      </dl>

      {finding.description ? (
        <>
          <h3 className="card-title mt-16">Description</h3>
          <p className="dim" style={{ marginTop: 0 }}>
            {finding.description}
          </p>
        </>
      ) : null}

      <h3 className="card-title mt-16">Evidence chain</h3>
      {finding.evidence ? (
        <div className="evidence">{finding.evidence}</div>
      ) : finding.evidence_ids?.length ? (
        <ul className="timeline">
          {finding.evidence_ids.map((eid, i) => (
            <li key={eid} className="done">
              <span className="tl-time">step {i + 1}</span>
              <div className="tl-title mono">{eid}</div>
            </li>
          ))}
        </ul>
      ) : (
        <p className="dim">
          No evidence recorded — treat this as unproven and re-run the scan.
        </p>
      )}

      {finding.remediation ? (
        <>
          <h3 className="card-title mt-16">Remediation</h3>
          <pre className="code-block">{finding.remediation}</pre>
        </>
      ) : null}

      <div className="row mt-16">
        <button className="btn" onClick={reproduce} disabled={reproducing}>
          {reproducing ? 'Running PoC…' : 'Re-run PoC'}
        </button>
        {finding.verified_by_evidence ? (
          <span className="pill ok">
            <span className="pill-dot" />
            evidence-verified
          </span>
        ) : null}
      </div>

      {result ? (
        <p className="mono mt-16" style={{ marginBottom: 0 }}>
          {result}
        </p>
      ) : null}

      <FixPanel findingId={target} reproduced={Boolean(finding.reproduced)} />
    </Card>
  );
}

function FixPanel({
  findingId,
  reproduced,
}: {
  findingId: string | null;
  reproduced: boolean;
}) {
  const [proposal, setProposal] = useState<FixProposal | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const propose = useCallback(async () => {
    if (!findingId) return;
    setBusy(true);
    setError(null);
    setProposal(null);
    try {
      setProposal(await api.fix(findingId));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }, [findingId]);

  return (
    <>
      <h3 className="card-title mt-16">One-click fix</h3>
      <p className="dim" style={{ marginTop: 0, fontSize: 12.5 }}>
        The fixer works inside a throwaway git worktree, runs the tests and replays the
        PoC, then hands back the patch. Your checkout is never written to — review the
        diff and apply it yourself.
      </p>
      <div className="row mt-16">
        <button className="btn" onClick={propose} disabled={busy || !findingId}>
          {busy ? 'Attempting fix…' : 'Propose a fix'}
        </button>
        {!reproduced ? (
          <span className="faint" style={{ fontSize: 12 }}>
            unproven findings are refused by default
          </span>
        ) : null}
      </div>

      {error ? (
        <p className="mono mt-16" style={{ color: 'var(--critical)', marginBottom: 0 }}>
          {error}
        </p>
      ) : null}

      {proposal ? (
        <div className="mt-16">
          {proposal.refused ? (
            <div className="error-box" style={{ marginBottom: 0 }}>
              <strong>Refused: {proposal.refused}</strong>
              <div className="mt-16 dim">{proposal.reason}</div>
            </div>
          ) : (
            <>
              <div className="row" style={{ marginBottom: 10 }}>
                {proposal.verified ? (
                  <span className="pill ok">
                    <span className="pill-dot" />
                    verified by execution
                  </span>
                ) : (
                  <span className="pill sev-medium">
                    <span className="pill-dot" />
                    {proposal.status || 'not verified'}
                  </span>
                )}
                {proposal.strategy ? (
                  <span className="faint mono" style={{ fontSize: 12 }}>
                    {proposal.strategy}
                  </span>
                ) : null}
                {proposal.attempts ? (
                  <span className="faint" style={{ fontSize: 12 }}>
                    {proposal.attempts} attempt{proposal.attempts === 1 ? '' : 's'}
                  </span>
                ) : null}
              </div>
              {proposal.blocker ? (
                <p className="dim" style={{ fontSize: 12.5 }}>
                  Blocker: {proposal.blocker}
                </p>
              ) : null}
              <p className="faint" style={{ fontSize: 12 }}>
                {proposal.applied_note}
              </p>
              <pre className="code-block">{proposal.patch || '(no patch produced)'}</pre>
              {proposal.verify_log ? (
                <details className="mt-16">
                  <summary className="dim" style={{ cursor: 'pointer', fontSize: 12.5 }}>
                    verification log
                  </summary>
                  <pre className="code-block mt-16">{proposal.verify_log}</pre>
                </details>
              ) : null}
            </>
          )}
        </div>
      ) : null}
    </>
  );
}
