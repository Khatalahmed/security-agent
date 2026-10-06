// Types mirror the FastAPI responses in security-agent/webapi/app.py.
// Keep in sync with the backend; do not add fields the backend doesn't send.

export type Severity = "critical" | "high" | "medium" | "low" | "info" | "unknown";

export type FindingState =
  | "DISCOVERED" | "CANDIDATE" | "TRIAGED" | "VALIDATION_PENDING"
  | "VALIDATED" | "HUMAN_CONFIRMED" | "FALSE_POSITIVE";

export interface Finding {
  id: string;
  scan_id: string;
  source: string;
  target: string;
  vuln_class: string;
  severity: Severity;
  confidence: string;
  location: string;
  description: string;
  poc: string;
  remediation: string;
  state: FindingState;
  created_at: string;
  method: string; // "taint" | "source_audit" | "secrets" | "recon" ...
  evidence: Record<string, unknown> & {
    engine?: string;
    chain?: string[];
    crosses_files?: boolean;
    sink?: { callee: string; line: number; class: string };
    file?: string;
    validation?: { verdict?: string; confidence?: string };
    raw_item?: Record<string, unknown>;
  };
}

export interface SeverityCounts {
  critical: number; high: number; medium: number; low: number; info: number;
}

export interface Scan {
  scan_id: string;
  mode: string;
  target: string;
  model: string;
  started_at: string;
  config: string;
  severity_counts: SeverityCounts;
  state_counts: Record<string, number>;
  findings: number;
}

export interface OllamaStatus {
  online: boolean;
  endpoint: string;
  active_model: string;
  model_present?: boolean;
  models?: string[];
  inference: string;
  error?: string;
}

export interface AgentConfig {
  provider: string;
  model: string;
  local_only: boolean;
  base_url: string;
  num_ctx: number;
  skills_enabled: string[];
}

export type DataFlowRole = "source" | "transformation" | "sanitizer" | "sink" | "finding";

export interface DataFlowNode {
  id: string;
  role: DataFlowRole;
  label: string;
  file?: string;
  function?: string | null;
  detail?: string;
  severity?: string;
}

export interface DataFlow {
  available: boolean;
  reason?: string;
  message?: string;
  crosses_files?: boolean;
  sink?: { callee: string; line: number; class: string };
  nodes: DataFlowNode[];
  edges: { from: string; to: string }[];
}

export interface BenchmarkAggregate {
  fixtures: number;
  detection_rate: number;
  false_negative_rate: number;
  false_positives_total: number;
  fp_on_clean_fixtures: number;
  clean_fixtures: number;
  json_valid_rate: number;
  files_analyzed: number;
  total_seconds: number;
  avg_seconds_per_file: number;
  counts: { tp: number; fp: number; fn: number; expected: number };
}

export interface Benchmark {
  file: string;
  mode: string;
  provider: string;
  model: string | null;
  mock: boolean;
  timestamp: string;
  aggregate: BenchmarkAggregate | null;
  skills: string[] | null;
  fixtures: Array<Record<string, unknown>> | null;
  source: string;
}

export interface ReportMeta {
  name: string; scan_id: string; format: string; size: number; mtime: number;
}

export interface ScanStage { key: string; label: string; state: "pending" | "active" | "done"; }
export interface Job {
  id: string; scan_id: string;
  status: "queued" | "running" | "succeeded" | "failed";
  returncode: number | null; error: string;
  stages: ScanStage[]; log_tail: string[];
}
