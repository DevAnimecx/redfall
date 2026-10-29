'use client';

import { useCallback, useEffect, useRef, useState } from 'react';
import { ApiError } from './api';

interface State<T> {
  data: T | null;
  error: string | null;
  loading: boolean;
}

/**
 * One fetch, with loading and error state, and a `reload` the UI can call.
 *
 * Deliberately not a cache: the console shows live state, so a stale value is
 * worse than a spinner. Every page owns its own request.
 */
export function useApi<T>(fn: () => Promise<T>, deps: unknown[] = []): State<T> & {
  reload: () => void;
} {
  const [state, setState] = useState<State<T>>({ data: null, error: null, loading: true });
  const [nonce, setNonce] = useState(0);
  const alive = useRef(true);
  const fnRef = useRef(fn);
  fnRef.current = fn;

  useEffect(() => {
    alive.current = true;
    setState((prev) => ({ ...prev, loading: true }));
    fnRef
      .current()
      .then((data) => {
        if (alive.current) setState({ data, error: null, loading: false });
      })
      .catch((err: unknown) => {
        if (!alive.current) return;
        const message =
          err instanceof ApiError
            ? err.message
            : err instanceof Error
              ? err.message
              : String(err);
        setState({ data: null, error: message, loading: false });
      });
    return () => {
      alive.current = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [nonce, ...deps]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  return { ...state, reload };
}
