import { Button } from '@/components/ui/button';

/** The one empty state: dashed border, title, one line of honest context. */
export function EmptyBlock({
  title,
  body,
  action,
}: {
  title: string;
  body: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center gap-1 rounded-xl border border-dashed py-10 text-center">
      <p className="text-sm font-semibold">{title}</p>
      <p className="max-w-sm text-xs text-muted-foreground">{body}</p>
      {action ?? null}
    </div>
  );
}
