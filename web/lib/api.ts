// Typed client for the local FastAPI layer. The base URL is the API endpoint
// only (not a secret); defaults to the local backend.
import type {
  AgentConfig, Benchmark, DataFlow, Finding, Job, OllamaStatus, ReportMeta, Scan,
} from "./types";

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE?.replace(/\/$/, "") || "http://127.0.0.1:8000";

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function get<T>(path: string): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, { cache: "no-store" });
  } catch {
    throw new ApiError(0, `Cannot reach the backend at ${API_BASE}. Is the API running (uvicorn webapi.app:app --port 8000)?`);
  }
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail ?? detail; } catch {}
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError(0, `Cannot reach the backend at ${API_BASE}.`);
  }
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail ?? detail; } catch {}
    throw new ApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

export const api = {
  health: () => get<{ status: string; version: string; db: string }>("/api/health"),
  config: () => get<AgentConfig>("/api/config"),
  ollama: () => get<OllamaStatus>("/api/ollama/status"),
  pipeline: () => get<{ key: string; label: string }[]>("/api/pipeline"),
  scans: () => get<Scan[]>("/api/scans"),
  scan: (id: string) => get<Scan>(`/api/scans/${encodeURIComponent(id)}`),
  scanFindings: (id: string) => get<Finding[]>(`/api/scans/${encodeURIComponent(id)}/findings`),
  findings: (state?: string) => get<Finding[]>(`/api/findings${state ? `?state=${state}` : ""}`),
  finding: (id: string) => get<Finding>(`/api/findings/${encodeURIComponent(id)}`),
  dataflow: (id: string) => get<DataFlow>(`/api/findings/${encodeURIComponent(id)}/dataflow`),
  confirm: (id: string) => post<Finding>(`/api/findings/${encodeURIComponent(id)}/confirm`),
  falsePositive: (id: string) => post<Finding>(`/api/findings/${encodeURIComponent(id)}/false-positive`),
  benchmarks: () => get<Benchmark[]>("/api/benchmarks"),
  reports: () => get<ReportMeta[]>("/api/reports"),
  report: (name: string) => get<{ name: string; format: string; content: string }>(`/api/reports/${encodeURIComponent(name)}`),
  startScan: (body: { repo: string; skills?: string[]; rag?: boolean; taint_all_chains?: boolean; scan_id?: string }) =>
    post<Job>("/api/scans", body),
  job: (id: string) => get<Job>(`/api/jobs/${encodeURIComponent(id)}`),
};
