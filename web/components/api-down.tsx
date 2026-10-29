'use client';

import { Button } from '@/components/ui/button';
import {
  Alert,
  AlertDescription,
  AlertTitle,
} from '@/components/ui/alert';
import { Terminal } from 'lucide-react';

/** The one error surface: says the API is unreachable and how to start it. */
export function ApiDown({ error, onRetry }: { error: string; onRetry?: () => void }) {
  return (
    <Alert variant="destructive">
      <Terminal className="size-4" />
      <AlertTitle>Dashboard API unreachable</AlertTitle>
      <AlertDescription className="flex flex-col gap-3">
        <span>
          {error} — start it with{' '}
          <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
            redfall dashboard
          </code>
          , then retry.
        </span>
        {onRetry ? (
          <Button variant="outline" size="sm" className="w-fit" onClick={onRetry}>
            Retry
          </Button>
        ) : null}
      </AlertDescription>
    </Alert>
  );
}
