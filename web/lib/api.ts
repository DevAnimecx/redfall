/**
 * Typed client for the RedFall dashboard API (0.3.x).
 *
 * The console talks to the Python dashboard server, never to a JSON file on
 * disk. That is the whole point of 0.3.0: the old page re-read a saved report
 * and could only ever show a finished scan. This talks to a live server, so a
 * running scan streams.
 *
 * The server address comes from NEXT_PUBLIC_REDFALL_API, defaulting to the
 * loopback address `redfall dashboard` binds.
 */

export const API_BASE =
  process.env.NEXT_PUBLIC_REDFALL_API || 'http://127.0.0.1:8787';

/** A refusal from the API, carrying the server's stable `kind`. */
export class ApiError extends Error {
  readonly status: number;
  readonly kind: string;

  constructor(status: number, kind: string, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.kind = kind;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: { 'Content-Type': 'application/json', ...(init?.headers || {}) },
      cache: 'no-store',
    });
  } catch (err) {
    throw new ApiError(
      0,
      'unreachable',
      `Cannot reach the RedFall API at ${API_BASE}. Is \`redfall dashboard\` running? (${
        err instanceof Error ? err.message : String(err)
      })`,
    );
  }
  const text = await response.text();
  const body = text ? JSON.parse(text) : {};
  if (!response.ok) {
    const detail = body?.error || {};
    throw new ApiError(
      response.status,
      detail.kind || 'error',
      detail.message || `HTTP ${response.status}`,
    );
  }
  return body as T;
}

// ----------------------------------------------------------------- types

export interface Agent {
  name: string;
  title: string;
  installed: boolean;
  executable: string | null;
  version: string | null;
  homepage: string;
}

export interface AgentsResponse {
  supported: number;
  installed: string[];
  agents: Agent[];
}

export interface ReasoningResponse {
  config: Record<string, unknown>;
  backend: Record<string, unknown> | null;
  error?: string;
}

export interface Finding {
  id: string;
  scan_id?: string;
  category: string;
  severity: string;
  title?: string;
  description?: string;
  file?: string;
  line?: number;
  symbol?: string;
  reproduced?: boolean;
  status?: string;
  evidence?: string;
  remediation?: string;
  verified_by_evidence?: boolean;
  evidence_ids?: string[];
}

export interface FindingsResponse {
  findings: Finding[];
  returned: number;
  total: number;
  truncated: boolean;
}

export interface Campaign {
  id: string;
  repo?: string;
  objective?: string;
  status?: string;
  created_at?: string;
  state?: string;
  scan_id?: string | null;
}

export interface CampaignList {
  campaigns: Campaign[];
  returned?: number;
  total?: number;
}

export interface CampaignStatus extends Campaign {
  findings?: Finding[];
  budget?: Record<string, number>;
  tasks?: unknown[];
}

export interface FixProposal {
  ok: boolean;
  /** Always false: a proposal is never written to the operator's checkout. */
  applied?: boolean;
  applied_note?: string;
  refused?: string;
  reason?: string;
  patch?: string;
  strategy?: string;
  verify_log?: string;
  blocker?: string | null;
  status?: string;
  verified?: boolean;
  test_result?: string;
  poc_neutralized?: boolean;
  attempts?: number;
  history?: { attempt: number; stage: string; [key: string]: unknown }[];
}

export interface ReportBundle {
  scan_id?: string;
  findings?: Finding[];
  [key: string]: unknown;
}

// ----------------------------------------------------------------- calls

export const api = {
  version: () => request<{ version: string; tools: number }>('/api/version'),
  health: () => request<Record<string, unknown>>('/healthz'),
  agents: () => request<AgentsResponse>('/api/agents'),
  reasoning: () => request<ReasoningResponse>('/api/reasoning'),
  projects: () => request<{ projects: string[] }>('/api/projects'),
  scans: (limit = 50) => request<CampaignList>(`/api/scans?limit=${limit}`),
  scan: (id: string) => request<CampaignStatus>(`/api/scans/${encodeURIComponent(id)}`),
  startScan: (target: string, extra: Record<string, unknown> = {}) =>
    request<{ accepted: boolean; target: string; scan_id: string; events: string }>(
      '/api/scans',
      {
        method: 'POST',
        body: JSON.stringify({ target, ...extra }),
      },
    ),
  cancelScan: (id: string) =>
    request<Record<string, unknown>>(`/api/scans/${encodeURIComponent(id)}/cancel`, {
      method: 'POST',
    }),
  findings: (params: Record<string, string> = {}) => {
    const query = new URLSearchParams(params).toString();
    return request<FindingsResponse>(`/api/findings${query ? `?${query}` : ''}`);
  },
  finding: (id: string) => request<Finding>(`/api/findings/${encodeURIComponent(id)}`),
  reproduce: (id: string) =>
    request<Record<string, unknown>>(`/api/findings/${encodeURIComponent(id)}/reproduce`, {
      method: 'POST',
    }),
  fix: (id: string, extra: Record<string, unknown> = {}) =>
    request<FixProposal>(`/api/findings/${encodeURIComponent(id)}/fix`, {
      method: 'POST',
      body: JSON.stringify(extra),
    }),
  report: (id: string) => request<ReportBundle>(`/api/reports/${encodeURIComponent(id)}`),
};

/** Subscribe to a scan's event stream. Returns the EventSource so the caller
 *  can close it. The browser reconnects on its own if the server restarts. */
export function streamScan(
  scanId: string,
  handlers: {
    onEvent?: (kind: string, payload: Record<string, unknown>) => void;
    onError?: (err: Event) => void;
  },
): EventSource {
  const source = new EventSource(`${API_BASE}/api/scans/${encodeURIComponent(scanId)}/events`);
  const kinds = [
    'scan:start',
    'scan:done',
    'scan:error',
    'branch',
    'finding',
    'spend',
    'ingest',
  ];
  for (const kind of kinds) {
    source.addEventListener(kind, (event) => {
      try {
        const data = JSON.parse((event as MessageEvent).data);
        handlers.onEvent?.(kind, data);
      } catch {
        handlers.onEvent?.(kind, {});
      }
    });
  }
  if (handlers.onError) source.onerror = handlers.onError;
  return source;
}

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'] as const;

/** Raw hues for meters and bars; badges use the token classes in SEVERITY_COLOR. */
export const SEVERITY_HEX: Record<string, string> = {
  critical: 'var(--sev-critical)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-medium)',
  low: 'var(--sev-low)',
};

/** Badge classes per severity — kept next to the hues they echo. */
export const SEVERITY_COLOR: Record<string, string> = {
  critical: 'text-sev-critical border-sev-critical/40 bg-sev-critical/10',
  high: 'text-sev-high border-sev-high/40 bg-sev-high/10',
  medium: 'text-sev-medium border-sev-medium/40 bg-sev-medium/10',
  low: 'text-sev-low border-sev-low/40 bg-sev-low/10',
};

export function bySeverity(findings: Finding[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const finding of findings) {
    counts[finding.severity] = (counts[finding.severity] || 0) + 1;
  }
  return counts;
}
