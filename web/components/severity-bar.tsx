import { cn } from '@/lib/utils';
import { SEVERITY_ORDER, SEVERITY_HEX } from '@/lib/api';

/** Stacked severity bar over the API's own counts. Zero total renders empty. */
export function SeverityBar({
  counts,
  className,
}: {
  counts: Record<string, number>;
  className?: string;
}) {
  const total = SEVERITY_ORDER.reduce((sum, sev) => sum + (counts[sev] || 0), 0);
  return (
    <div
      className={cn('flex h-2 w-full overflow-hidden rounded-full bg-muted', className)}
      role="img"
      aria-label={
        total
          ? SEVERITY_ORDER.map((s) => `${counts[s] || 0} ${s}`).join(', ')
          : 'no findings'
      }
    >
      {total > 0 &&
        SEVERITY_ORDER.map((sev) => {
          const n = counts[sev] || 0;
          if (!n) return null;
          return (
            <span
              key={sev}
              title={`${n} ${sev}`}
              style={{ width: `${(n / total) * 100}%`, background: SEVERITY_HEX[sev] }}
            />
          );
        })}
    </div>
  );
}
