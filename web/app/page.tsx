import {
  bySeverity,
  loadDashboardData,
  SEVERITY_COLOR,
  SEVERITY_ORDER,
  type ChainEntry,
  type ChainScore,
  type GateReport,
  type LoadError,
  type ScanReport,
} from '../lib/data';

export const dynamic = 'force-dynamic';

const card: React.CSSProperties = {
  background: '#11161c',
  border: '1px solid #21262d',
  borderRadius: 8,
  padding: 16,
  marginBottom: 16,
};

const th: React.CSSProperties = {
  textAlign: 'left',
  padding: '6px 10px',
  borderBottom: '1px solid #21262d',
  color: '#8b949e',
  fontWeight: 600,
  fontSize: 12,
  textTransform: 'uppercase',
  letterSpacing: 0.4,
};

const td: React.CSSProperties = {
  padding: '7px 10px',
  borderBottom: '1px solid #161b22',
  verticalAlign: 'top',
};

function Pill({ label, value, tone }: { label: string; value: string | number; tone?: string }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 120 }}>
      <span style={{ color: '#8b949e', fontSize: 11, textTransform: 'uppercase', letterSpacing: 0.4 }}>
        {label}
      </span>
      <span style={{ fontSize: 20, fontWeight: 600, color: tone || '#e6edf3' }}>{value}</span>
    </div>
  );
}

function Missing({ label, path, error }: { label: string; path: string; error: LoadError | null }) {
  return (
    <div style={{ ...card, borderStyle: 'dashed' }}>
      <strong>{label} not available</strong>
      <div style={{ color: '#8b949e', marginTop: 6, fontSize: 13 }}>
        Expected at <code style={{ color: '#79c0ff' }}>{path}</code>
        {error ? ` — ${error.detail}` : ''}.
      </div>
      <div style={{ color: '#8b949e', marginTop: 4, fontSize: 13 }}>
        Nothing is displayed in its place. The dashboard does not invent data.
      </div>
    </div>
  );
}

function GateCard({ gate }: { gate: GateReport }) {
  const m = gate.metrics;
  const rows: [string, number, string][] = [
    ['recall', m.recall, gate.thresholds.recall || ''],
    ['precision', m.precision, gate.thresholds.precision || ''],
    ['repro_rate', m.repro_rate, gate.thresholds.repro_rate || ''],
    ['fix_rate', m.fix_rate, gate.thresholds.fix_rate || ''],
    ['duration_ms', m.duration_ms, gate.thresholds.duration_ms || ''],
  ];
  if (gate.chain_score) {
    rows.push(
      ['chain_recall', gate.chain_score.chain_recall, gate.thresholds.chain_recall || ''],
      ['chain_link_rate', gate.chain_score.chain_link_rate, gate.thresholds.chain_link_rate || ''],
      [
        'chain_narrative_rate',
        gate.chain_score.chain_narrative_rate,
        gate.thresholds.chain_narrative_rate || '',
      ],
    );
  }
  return (
    <div style={card}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <h2 style={{ margin: 0, fontSize: 15 }}>range gate</h2>
        <span
          style={{
            padding: '3px 10px',
            borderRadius: 999,
            fontSize: 12,
            fontWeight: 700,
            background: gate.passed ? '#12351f' : '#3d1414',
            color: gate.passed ? '#4ade80' : '#f87171',
            border: `1px solid ${gate.passed ? '#1f6f3f' : '#7f1d1d'}`,
          }}
        >
          {gate.passed ? 'PASS' : 'FAIL'}
        </span>
      </div>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            <th style={th}>metric</th>
            <th style={th}>value</th>
            <th style={th}>required</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(([name, value, required]) => (
            <tr key={name}>
              <td style={td}>
                <code>{name}</code>
              </td>
              <td style={{ ...td, fontVariantNumeric: 'tabular-nums' }}>{value}</td>
              <td style={{ ...td, color: '#8b949e' }}>{required}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {(gate.failures || []).length > 0 && (
        <ul style={{ margin: '12px 0 0', paddingLeft: 18, color: '#f87171' }}>
          {(gate.failures || []).map((failure) => (
            <li key={failure}>{failure}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

function ScanCard({ scan }: { scan: ScanReport }) {
  const findings = scan.findings || [];
  const branches = scan.branches || [];
  const errors = scan.errors || [];
  const counts = bySeverity(findings);
  return (
    <div style={card}>
      <h2 style={{ margin: '0 0 12px', fontSize: 15 }}>Scan {scan.scan_id}</h2>
      <div style={{ display: 'flex', gap: 28, flexWrap: 'wrap', marginBottom: 12 }}>
        <Pill label="status" value={scan.status} />
        <Pill label="findings" value={findings.length} />
        <Pill label="branches" value={branches.length} />
        <Pill label="sandbox runs" value={scan.sandbox_runs} />
        <Pill label="llm calls" value={scan.llm?.calls ?? 0} />
        <Pill label="tokens" value={scan.llm?.tokens_used ?? 0} />
        <Pill label="cost (usd)" value={(scan.llm?.cost_usd ?? 0).toFixed(4)} />
        <Pill label="duration" value={`${Math.round((scan.duration_ms || 0) / 1000)}s`} />
      </div>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 10 }}>
        {SEVERITY_ORDER.map((severity) => (
          <span
            key={severity}
            style={{
              padding: '2px 9px',
              borderRadius: 999,
              fontSize: 12,
              border: `1px solid ${SEVERITY_COLOR[severity]}`,
              color: SEVERITY_COLOR[severity] === '#475569' ? '#cbd5e1' : SEVERITY_COLOR[severity],
            }}
          >
            {severity} {counts[severity] || 0}
          </span>
        ))}
      </div>
      <div style={{ color: '#8b949e', fontSize: 12 }}>
        {scan.target} @ {scan.commit || 'unknown commit'}
      </div>
      {errors.length > 0 && (
        <ul style={{ margin: '10px 0 0', paddingLeft: 18, color: '#f0b429' }}>
          {errors.map((error) => (
            <li key={error}>{error}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

function ChainScoreCard({ score }: { score: ChainScore }) {
  return (
    <div style={card}>
      <h2 style={{ margin: '0 0 12px', fontSize: 15 }}>Chains scored ({score.chains_total})</h2>
      <div style={{ display: 'flex', gap: 28, flexWrap: 'wrap', marginBottom: 12 }}>
        <Pill label="recalled" value={`${score.chains_recalled}/${score.chains_total}`} />
        <Pill label="joins made" value={`${score.joins_made}/${score.joins_required}`} />
        <Pill label="narratives ok" value={`${score.narratives_ok}/${score.chains_total}`} />
        <Pill label="link rate" value={score.chain_link_rate} />
      </div>
      {(score.results || []).length > 0 && (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <th style={th}>chain</th>
              <th style={th}>steps</th>
              <th style={th}>joins</th>
              <th style={th}>linked</th>
              <th style={th}>narrative</th>
              <th style={th}>compound cvss</th>
            </tr>
          </thead>
          <tbody>
            {(score.results || []).map((result) => (
              <tr key={result.chain_id}>
                <td style={td}>
                  <code>{result.chain_id}</code>
                  <div style={{ color: '#8b949e', fontSize: 12 }}>{result.name}</div>
                </td>
                <td style={td}>
                  {result.steps_reported}/{result.steps_total}
                  {result.missing_steps.length > 0 && (
                    <div style={{ color: '#f87171', fontSize: 12 }}>
                      missing {result.missing_steps.join(', ')}
                    </div>
                  )}
                </td>
                <td style={td}>
                  {result.joins_made}/{result.joins_required}
                  {result.missing_joins.length > 0 && (
                    <div style={{ color: '#f87171', fontSize: 12 }}>
                      {result.missing_joins.map((join) => join.join('→')).join(', ')}
                    </div>
                  )}
                </td>
                <td style={td}>{result.linked ? 'yes' : 'no'}</td>
                <td style={td}>
                  {result.narrative_ok ? 'ok' : 'no'}
                  {result.narrative_missing.length > 0 && (
                    <div style={{ color: '#f0b429', fontSize: 12 }}>
                      missing {result.narrative_missing.join(', ')}
                    </div>
                  )}
                </td>
                <td style={td}>
                  {result.reported_cvss_compound ?? '—'}
                  {result.reported_cvss_compound != null && !result.cvss_compound_ok && (
                    <span style={{ color: '#f0b429', fontSize: 12 }}> rejected</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

const STATUS_COLOR: Record<string, string> = {
  reproduced: '#4ade80',
  partial: '#f0b429',
  refused: '#f87171',
};

function ChainsCard({ scan }: { scan: ScanReport }) {
  const chains = scan.chains || [];
  const edges = scan.edges || [];
  const stage = scan.chain;
  const refusals = stage?.refusals || [];
  const strongest = stage?.strongest_paths || [];
  return (
    <div style={card}>
      <h2 style={{ margin: '0 0 12px', fontSize: 15 }}>
        Attack chains ({chains.length} reproduced or partial)
      </h2>
      {stage && (
        <div style={{ display: 'flex', gap: 28, flexWrap: 'wrap', marginBottom: 12 }}>
          <Pill label="proposed" value={stage.proposed} />
          <Pill label="reviewed out" value={stage.reviewed_out} />
          <Pill label="reproduced" value={stage.reproduced} />
          <Pill label="partial" value={stage.partial} />
          <Pill label="edges proven" value={edges.length} />
          <Pill label="max candidates" value={stage.max_candidates} />
        </div>
      )}
      {chains.length === 0 ? (
        <div style={{ color: '#8b949e' }}>No chain was reproduced in this scan.</div>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <th style={th}>status</th>
              <th style={th}>title</th>
              <th style={th}>severity</th>
              <th style={th}>steps</th>
              <th style={th}>findings</th>
              <th style={th}>compound cvss</th>
            </tr>
          </thead>
          <tbody>
            {chains.map((chain) => (
              <tr key={chain.id}>
                <td style={{ ...td, color: STATUS_COLOR[chain.status] || '#e6edf3' }}>{chain.status}</td>
                <td style={td}>
                  {chain.title}
                  {chain.narrative ? (
                    <div style={{ color: '#8b949e', fontSize: 12, marginTop: 4 }}>{chain.narrative}</div>
                  ) : null}
                </td>
                <td style={{ ...td, color: SEVERITY_COLOR[chain.severity || ''] || '#e6edf3' }}>
                  {chain.severity || '—'}
                </td>
                <td style={td}>
                  {chain.steps_passed}/{chain.steps.length}
                </td>
                <td style={{ ...td, fontSize: 12 }}>
                  {(chain.finding_ids || []).map((findingId) => (
                    <div key={findingId}>
                      <code>{findingId}</code>
                    </div>
                  ))}
                </td>
                <td style={td}>{chain.cvss_compound ?? '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {edges.length > 0 && (
        <>
          <h3 style={{ margin: '18px 0 8px', fontSize: 13, color: '#8b949e', textTransform: 'uppercase' }}>
            Proven edges
          </h3>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={th}>hop</th>
                <th style={th}>finding pair</th>
                <th style={th}>source kind</th>
                <th style={th}>chain</th>
              </tr>
            </thead>
            <tbody>
              {edges.map((edge) => (
                <tr key={edge.id}>
                  <td style={td}>
                    {edge.source} → {edge.target}
                  </td>
                  <td style={{ ...td, fontSize: 12 }}>
                    {(edge.finding_ids || []).map((findingId) => (
                      <div key={findingId}>
                        <code>{findingId}</code>
                      </div>
                    ))}
                  </td>
                  <td style={{ ...td, color: '#8b949e' }}>{edge.source_kind}</td>
                  <td style={{ ...td, color: '#8b949e', fontSize: 12 }}>{edge.chain_id || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
      {refusals.length > 0 && (
        <>
          <h3 style={{ margin: '18px 0 8px', fontSize: 13, color: '#8b949e', textTransform: 'uppercase' }}>
            Refused proposals ({refusals.length})
          </h3>
          <ul style={{ margin: 0, paddingLeft: 18, color: '#8b949e', fontSize: 13 }}>
            {refusals.map((refusal, index) => (
              <li key={`${refusal.title}-${index}`}>
                {refusal.title} — {(refusal.problems || []).join('; ')}
              </li>
            ))}
          </ul>
        </>
      )}
      {strongest.length > 0 && (
        <>
          <h3 style={{ margin: '18px 0 8px', fontSize: 13, color: '#8b949e', textTransform: 'uppercase' }}>
            Strongest paths
          </h3>
          <ul style={{ margin: 0, paddingLeft: 18, fontSize: 13 }}>
            {strongest.map((path, index) => (
              <li key={`${path.steps.join('>')}-${index}`}>
                {(path.steps || []).join(' → ')}{' '}
                <span style={{ color: '#8b949e' }}>
                  ({path.severity}, cvss {path.cvss_compound})
                </span>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}

function SeverityBreakdownCard({ scan, gate }: { scan: ScanReport | null; gate: GateReport }) {
  const reported = scan ? bySeverity(scan.findings || []) : {};
  const matched: Record<string, number> = {};
  for (const match of gate.matches || []) {
    const severity = match.severity || 'unknown';
    matched[severity] = (matched[severity] || 0) + 1;
  }
  const severities = Array.from(
    new Set([
      ...SEVERITY_ORDER,
      ...Object.keys(gate.manifest_severity || {}),
      ...Object.keys(matched),
      ...Object.keys(reported),
    ]),
  );
  return (
    <div style={card}>
      <h2 style={{ margin: '0 0 12px', fontSize: 15 }}>Severity breakdown</h2>
      <table style={{ width: '100%', borderCollapse: 'collapse' }}>
        <thead>
          <tr>
            <th style={th}>severity</th>
            <th style={th}>manifest</th>
            <th style={th}>matched</th>
            <th style={th}>missed</th>
            <th style={th}>reported</th>
          </tr>
        </thead>
        <tbody>
          {severities.map((severity) => {
            const inManifest = gate.manifest_severity?.[severity] || 0;
            const hit = matched[severity] || 0;
            const missed = Math.max(0, inManifest - hit);
            return (
              <tr key={severity}>
                <td style={{ ...td, color: SEVERITY_COLOR[severity] || '#e6edf3' }}>{severity}</td>
                <td style={td}>{inManifest}</td>
                <td style={td}>{hit}</td>
                <td style={{ ...td, color: missed > 0 ? '#f87171' : '#8b949e' }}>{missed}</td>
                <td style={{ ...td, color: '#8b949e' }}>{reported[severity] || 0}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function MissedCard({ gate }: { gate: GateReport }) {
  const missed = gate.missed_vulns || [];
  return (
    <div style={{ ...card, borderColor: missed.length > 0 ? '#7f1d1d' : '#21262d' }}>
      <h2 style={{ margin: '0 0 12px', fontSize: 15 }}>Missed vulnerabilities ({missed.length})</h2>
      {missed.length === 0 ? (
        <div style={{ color: '#8b949e' }}>Every manifest entry was matched by this scan.</div>
      ) : (
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          {missed.map((vulnId) => (
            <code
              key={vulnId}
              style={{
                padding: '2px 9px',
                borderRadius: 999,
                fontSize: 12,
                color: '#f87171',
                border: '1px solid #7f1d1d',
              }}
            >
              {vulnId}
            </code>
          ))}
        </div>
      )}
    </div>
  );
}

function FalsePositivesCard({ gate }: { gate: GateReport }) {
  const falsePositives = gate.false_positives || [];
  return (
    <div style={card}>
      <h2 style={{ margin: '0 0 12px', fontSize: 15 }}>
        False positives ({falsePositives.length})
      </h2>
      {falsePositives.length === 0 ? (
        <div style={{ color: '#8b949e' }}>
          Every reported finding matched a manifest entry.
        </div>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <th style={th}>finding</th>
              <th style={th}>category</th>
              <th style={th}>location</th>
            </tr>
          </thead>
          <tbody>
            {falsePositives.map((entry) => (
              <tr key={entry.id}>
                <td style={td}>
                  <code>{entry.id}</code>
                </td>
                <td style={td}>{entry.category}</td>
                <td style={td}>
                  {entry.location?.file}:{entry.location?.line}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default function Page() {
  const data = loadDashboardData();

  return (
    <>
      {data.scan ? <ScanCard scan={data.scan} /> : <Missing label="Scan report" path={data.scanPath} error={data.scanError} />}
      {data.gate ? <GateCard gate={data.gate} /> : <Missing label="Gate report" path={data.gatePath} error={data.gateError} />}

      {data.gate?.chain_score && <ChainScoreCard score={data.gate.chain_score} />}

      {data.scan && <ChainsCard scan={data.scan} />}

      {data.gate && <SeverityBreakdownCard scan={data.scan} gate={data.gate} />}

      {data.gate && <MissedCard gate={data.gate} />}

      {data.gate && <FalsePositivesCard gate={data.gate} />}

      {data.gate && (
        <div style={card}>
          <h2 style={{ margin: '0 0 12px', fontSize: 15 }}>
            Matched vulnerabilities ({(data.gate.matches || []).length})
          </h2>
          {(data.gate.matches || []).length === 0 ? (
            <div style={{ color: '#8b949e' }}>No manifest entry was matched by this scan.</div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th style={th}>vuln</th>
                  <th style={th}>category</th>
                  <th style={th}>location</th>
                  <th style={th}>matched by</th>
                </tr>
              </thead>
              <tbody>
                {(data.gate.matches || []).map((match) => (
                  <tr key={match.vuln_id}>
                    <td style={td}>
                      <code>{match.vuln_id}</code>
                    </td>
                    <td style={td}>{match.category}</td>
                    <td style={td}>
                      {match.file}:{match.manifest_line}
                    </td>
                    <td style={{ ...td, color: '#8b949e' }}>{match.how}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {data.scan && (
        <div style={card}>
          <h2 style={{ margin: '0 0 12px', fontSize: 15 }}>
            Findings ({(data.scan.findings || []).length})
          </h2>
          {(data.scan.findings || []).length === 0 ? (
            <div style={{ color: '#8b949e' }}>No reproduced findings in this scan.</div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  <th style={th}>severity</th>
                  <th style={th}>category</th>
                  <th style={th}>location</th>
                  <th style={th}>title</th>
                  <th style={th}>reproduced</th>
                  <th style={th}>status</th>
                </tr>
              </thead>
              <tbody>
                {(data.scan.findings || []).map((finding) => (
                  <tr key={finding.id}>
                    <td style={{ ...td, color: SEVERITY_COLOR[finding.severity] || '#e6edf3' }}>
                      {finding.severity}
                    </td>
                    <td style={td}>
                      <code>{finding.category}</code>
                    </td>
                    <td style={td}>
                      {finding.location?.file}:{finding.location?.line}
                    </td>
                    <td style={td}>{finding.title || '—'}</td>
                    <td style={td}>{finding.reproduced ? 'yes' : 'no'}</td>
                    <td style={{ ...td, color: '#8b949e' }}>{finding.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {data.scan && (data.scan.branches || []).length > 0 && (
        <div style={card}>
          <h2 style={{ margin: '0 0 12px', fontSize: 15 }}>
            Branches ({(data.scan.branches || []).length})
          </h2>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                <th style={th}>branch</th>
                <th style={th}>status</th>
                <th style={th}>tier</th>
                <th style={th}>candidates</th>
                <th style={th}>reproduced</th>
                <th style={th}>scope</th>
              </tr>
            </thead>
            <tbody>
              {(data.scan.branches || []).map((branch) => (
                <tr key={branch.id}>
                  <td style={td}>{branch.name}</td>
                  <td style={td}>{branch.status}</td>
                  <td style={{ ...td, color: '#8b949e' }}>{branch.model_tier}</td>
                  <td style={td}>{branch.candidates}</td>
                  <td style={td}>{branch.reproduced}</td>
                  <td style={{ ...td, color: '#8b949e', fontSize: 12 }}>
                    {(branch.scope_files || []).join(', ')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div style={{ color: '#484f58', fontSize: 11, marginTop: 8 }}>
        read at {data.loadedAt} · scan {data.scanPath} · gate {data.gatePath}
      </div>
    </>
  );
}
