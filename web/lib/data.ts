import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

export interface FindingLocation {
  file: string;
  line: number;
  symbol: string;
}

export interface Finding {
  id: string;
  category: string;
  severity: string;
  title?: string;
  description?: string;
  location: FindingLocation;
  reproduced: boolean;
  status: string;
  evidence?: string;
  remediation?: string;
  poc?: Record<string, unknown>;
}

export interface BranchSummary {
  id: string;
  name: string;
  type: string;
  status: string;
  priority: number;
  model_tier: string;
  scope_files: string[];
  candidates: number;
  reproduced: number;
  duration_ms: number;
  errors: string[];
}

export interface ChainStepRecord {
  n: number;
  finding_id: string;
  description?: string;
  state_before?: string;
  state_after?: string;
  ran?: boolean;
  ok?: boolean;
  status?: string | null;
  body?: string;
  extract?: string[];
}

export interface ChainEntry {
  id: string;
  scan_id: string;
  title: string;
  rationale?: string;
  status: string;
  reason?: string;
  finding_ids: string[];
  states: string[];
  steps: ChainStepRecord[];
  steps_passed: number;
  edges: string[];
  narrative?: string;
  cvss_compound?: number | null;
  severity?: string;
  run_id?: string | null;
  created_at?: string;
}

export interface EdgeEntry {
  id: string;
  scan_id: string;
  chain_id?: string | null;
  source: string;
  target: string;
  finding_ids: string[];
  description?: string;
  source_kind: string;
  reproduced: boolean;
  branch_id?: string;
  discovered_at?: string;
}

export interface ChainRefusal {
  title: string;
  problems: string[];
  run?: boolean;
  steps_passed?: number;
}

export interface StrongestPath {
  steps: string[];
  finding_ids: string[];
  states: string[];
  cvss_compound: number;
  severity: string;
}

export interface ChainStageSummary {
  proposed: number;
  reviewed_out: number;
  reproduced: number;
  partial: number;
  refused: number;
  refusals: ChainRefusal[];
  graph: Record<string, unknown>;
  strongest_paths: StrongestPath[];
  max_candidates: number;
}

export interface ScanReport {
  scan_id: string;
  target: string;
  commit: string;
  status: string;
  started_at: string;
  completed_at: string;
  duration_ms: number;
  branches: BranchSummary[];
  findings: Finding[];
  chains?: ChainEntry[];
  edges?: EdgeEntry[];
  chain?: ChainStageSummary;
  sandbox_runs: number;
  llm: Record<string, number>;
  environment: Record<string, unknown>;
  errors: string[];
}

export interface GateMetrics {
  manifest_total: number;
  findings_total: number;
  matched: number;
  unmatched_findings: number;
  missed: number;
  recall: number;
  precision: number;
  repro_rate: number;
  fix_rate: number;
  duration_ms: number;
}

export interface GateMatch {
  vuln_id: string;
  finding_id: string;
  category: string;
  file: string;
  manifest_line: number;
  finding_line: number;
  how: string;
  severity?: string;
}

export interface ChainResult {
  chain_id: string;
  name: string;
  steps_total: number;
  steps_reported: number;
  missing_steps: string[];
  joins_required: number;
  joins_made: number;
  missing_joins: string[][];
  complete: boolean;
  linked: boolean;
  narrative_ok: boolean;
  narrative_missing: string[];
  reported_cvss_compound: number | null;
  cvss_compound_ok: boolean;
}

export interface ChainScore {
  chains_total: number;
  chains_recalled: number;
  chain_recall: number;
  joins_required: number;
  joins_made: number;
  chain_link_rate: number;
  narratives_ok: number;
  chain_narrative_rate: number;
  results: ChainResult[];
}

export interface GateReport {
  target: string;
  scan_id: string;
  metrics: GateMetrics;
  chain_score?: ChainScore | null;
  matches: GateMatch[];
  missed_vulns: string[];
  false_positives: { id: string; category: string; location: FindingLocation }[];
  thresholds: Record<string, string>;
  failures: string[];
  passed: boolean;
  manifest_severity: Record<string, number>;
}

export interface LoadError {
  kind: 'missing' | 'unreadable';
  path: string;
  detail: string;
}

export interface DashboardData {
  scan: ScanReport | null;
  gate: GateReport | null;
  scanPath: string;
  gatePath: string;
  scanError: LoadError | null;
  gateError: LoadError | null;
  loadedAt: string;
}

function reportRoot(): string {
  return process.env.REDFALL_REPORT_DIR || resolve(process.cwd(), '..');
}

function load<T>(relative: string): { data: T | null; error: LoadError | null; path: string } {
  const path = resolve(reportRoot(), relative);
  if (!existsSync(path)) {
    return { data: null, error: { kind: 'missing', path, detail: 'file does not exist yet' }, path };
  }
  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as T;
    return { data: parsed, error: null, path };
  } catch (err) {
    return {
      data: null,
      error: {
        kind: 'unreadable',
        path,
        detail: err instanceof Error ? err.message : String(err),
      },
      path,
    };
  }
}

export function loadDashboardData(
  scanRel = process.env.REDFALL_SCAN_REPORT || 'scan.json',
  gateRel = process.env.REDFALL_GATE_REPORT || 'range/report.json',
): DashboardData {
  const scan = load<ScanReport>(scanRel);
  const gate = load<GateReport>(gateRel);
  return {
    scan: scan.data,
    gate: gate.data,
    scanPath: scan.path,
    gatePath: gate.path,
    scanError: scan.error,
    gateError: gate.error,
    loadedAt: new Date().toISOString(),
  };
}

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'] as const;

export const SEVERITY_COLOR: Record<string, string> = {
  critical: '#b3261e',
  high: '#d97706',
  medium: '#0f766e',
  low: '#475569',
};

export function bySeverity(findings: Finding[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const finding of findings) {
    counts[finding.severity] = (counts[finding.severity] || 0) + 1;
  }
  return counts;
}
