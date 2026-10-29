import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import { SEVERITY_COLOR } from '@/lib/api';

const UNKNOWN =
  'border-border bg-transparent text-muted-foreground';

/** Severity is the loudest colour on screen — one badge component, no drift. */
export function SevBadge({ severity, className }: { severity: string; className?: string }) {
  const key = severity.toLowerCase();
  return (
    <Badge
      variant="outline"
      className={cn(
        'gap-1.5 font-semibold uppercase tracking-wide',
        SEVERITY_COLOR[key] ?? UNKNOWN,
        className,
      )}
    >
      <span className="size-1.5 rounded-full bg-current" aria-hidden />
      {key || 'unknown'}
    </Badge>
  );
}
