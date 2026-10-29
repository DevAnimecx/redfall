import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { cn } from '@/lib/utils';

/** The stat tile: a tone stripe sets severity context, the number stays calm. */
export function Stat({
  label,
  value,
  sub,
  tone,
  className,
}: {
  label: string;
  value: React.ReactNode;
  sub?: React.ReactNode;
  tone?: string;
  className?: string;
}) {
  return (
    <Card className={cn('relative overflow-hidden py-4', className)}>
      <span
        aria-hidden
        className="absolute inset-y-0 left-0 w-[3px]"
        style={{ background: tone ?? 'var(--border)' }}
      />
      <CardHeader className="px-4">
        <CardTitle className="text-[10.5px] font-semibold uppercase tracking-[0.08em] text-muted-foreground">
          {label}
        </CardTitle>
      </CardHeader>
      <CardContent className="px-4">
        <div className="text-2xl font-bold tabular-nums tracking-tight">{value}</div>
        {sub ? <div className="mt-0.5 text-[11.5px] text-muted-foreground">{sub}</div> : null}
      </CardContent>
    </Card>
  );
}
