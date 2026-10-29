import type { ReactNode } from 'react';
import { SEVERITY_COLOR, SEVERITY_ORDER } from '../lib/api';

export function SevPill({ severity }: { severity: string }) {
  const key = SEVERITY_ORDER.includes(severity as (typeof SEVERITY_ORDER)[number])
    ? severity
    : 'unknown';
  return (
    <span className={`pill sev-${key}`}>
      <span className="pill-dot" />
      {severity || 'unknown'}
    </span>
  );
}

export function Stat({
  label,
  value,
  sub,
  tone,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  tone?: string;
}) {
  return (
    <div className="stat" style={tone ? ({ ['--tone' as string]: tone } as never) : undefined}>
      <div className="stat-label">{label}</div>
      <div className="stat-value">{value}</div>
      {sub ? <div className="stat-sub">{sub}</div> : null}
    </div>
  );
}

export function SeverityBar({ counts }: { counts: Record<string, number> }) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (!total) return <div className="bar" />;
  return (
    <div className="bar">
      {SEVERITY_ORDER.map((sev) => {
        const n = counts[sev] || 0;
        if (!n) return null;
        return (
          <div
            key={sev}
            className="bar-seg"
            style={{ width: `${(n / total) * 100}%`, background: SEVERITY_COLOR[sev] }}
            title={`${n} ${sev}`}
          />
        );
      })}
    </div>
  );
}

export function Meter({
  label,
  value,
  max,
  tone,
}: {
  label: string;
  value: number;
  max: number;
  tone?: string;
}) {
  const pct = max > 0 ? Math.min(100, (value / max) * 100) : 0;
  return (
    <div className="meter">
      <span style={{ minWidth: 96 }}>{label}</span>
      <div className="bar">
        <div
          className="bar-seg"
          style={{ width: `${pct}%`, background: tone || 'var(--accent)' }}
        />
      </div>
      <span className="meter-val">{value}</span>
    </div>
  );
}

export function Card({
  title,
  right,
  children,
}: {
  title?: ReactNode;
  right?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="card">
      {title ? (
        <h2 className="card-title">
          <span>{title}</span>
          {right}
        </h2>
      ) : null}
      {children}
    </section>
  );
}

export function Offline({ error, hint }: { error: string; hint?: ReactNode }) {
  return (
    <div className="error-box">
      <strong>Dashboard API unreachable.</strong>
      <div className="mt-16 mono">{error}</div>
      {hint ? <div className="mt-16 dim">{hint}</div> : null}
    </div>
  );
}

export function RelativeTime({ iso }: { iso?: string }) {
  if (!iso) return <span className="faint">—</span>;
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return <span className="faint">{iso}</span>;
  const seconds = Math.max(0, Math.round((Date.now() - then) / 1000));
  const text =
    seconds < 60
      ? `${seconds}s ago`
      : seconds < 3600
        ? `${Math.round(seconds / 60)}m ago`
        : seconds < 86400
          ? `${Math.round(seconds / 3600)}h ago`
          : `${Math.round(seconds / 86400)}d ago`;
  return <span className="faint" title={iso}>{text}</span>;
}
