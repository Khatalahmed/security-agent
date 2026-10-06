"""Thin FastAPI presentation/orchestration layer over the EXISTING security-agent.

This imports the real `security_agent` package and never reimplements analysis,
lifecycle, or safety. It reads the engine's SQLite store, pings local Ollama,
surfaces committed benchmark result JSONs and generated reports, applies the
engine's own lifecycle transitions, and launches real scans via the CLI (jobs.py).

Run:  uvicorn webapi.app:app --reload --port 8000   (from security-agent/)
"""
from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from security_agent.config import load_config
from security_agent.findings import FindingStore, State, VALID_TRANSITIONS
from security_agent.ai import provider_is_local
from security_agent.reporting import RENDERERS

from webapi.dataflow import build_dataflow
from webapi.jobs import JobManager, STAGES

ROOT = Path(__file__).resolve().parent.parent          # security-agent/
CFG = load_config(root=str(ROOT))
JOBS = JobManager(cwd=ROOT)

app = FastAPI(title="Local Security Agent API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["*"], allow_headers=["*"],
)

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0}


def _store() -> FindingStore:
    return FindingStore(CFG.path(CFG.storage["db_path"]))


def _row_to_finding(row) -> dict:
    d = dict(row)
    try:
        d["evidence"] = json.loads(d["evidence"]) if d.get("evidence") else {}
    except Exception:
        d["evidence"] = {}
    # expose a friendly analysis-method label from source ("taint:ollama" -> "taint")
    d["method"] = str(d.get("source", "")).split(":")[0] or "unknown"
    return d


# ---- health / system -----------------------------------------------------

@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "version": app.version,
            "db": str(CFG.path(CFG.storage["db_path"]))}


@app.get("/api/config")
def config() -> dict:
    """Sanitized config — model/provider/skills only. No keys (keys live in env,
    never in config), nothing secret."""
    m = CFG.model
    return {
        "provider": m.get("provider"),
        "model": m.get("name"),
        "local_only": provider_is_local(m),
        "base_url": m.get("base_url"),
        "num_ctx": m.get("num_ctx"),
        "skills_enabled": CFG.data.get("skills", {}).get("enabled", []),
    }


@app.get("/api/ollama/status")
def ollama_status() -> dict:
    m = CFG.model
    base = str(m.get("base_url", "http://127.0.0.1:11434/api/generate"))
    tags_url = base.rsplit("/api/", 1)[0] + "/api/tags"
    try:
        with urllib.request.urlopen(tags_url, timeout=4) as r:
            data = json.loads(r.read().decode("utf-8"))
        models = [x.get("name") for x in data.get("models", [])]
        return {"online": True, "endpoint": tags_url,
                "active_model": m.get("name"),
                "model_present": m.get("name") in models,
                "models": models, "inference": "local"}
    except Exception as e:  # noqa: BLE001
        return {"online": False, "endpoint": tags_url,
                "active_model": m.get("name"),
                "error": f"{type(e).__name__}: {e}",
                "inference": "local"}


# ---- scans ----------------------------------------------------------------

@app.get("/api/scans")
def list_scans() -> list[dict]:
    st = _store()
    try:
        rows = st.conn.execute(
            "SELECT * FROM scans ORDER BY started_at DESC").fetchall()
        out = []
        for s in rows:
            fs = [_row_to_finding(f) for f in st.list(scan_id=s["scan_id"])]
            out.append({**dict(s), **_summary(fs), "findings": len(fs)})
        return out
    finally:
        st.close()


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str) -> dict:
    st = _store()
    try:
        s = st.conn.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
        if s is None:
            raise HTTPException(404, f"no such scan: {scan_id}")
        fs = [_row_to_finding(f) for f in st.list(scan_id=scan_id)]
        return {**dict(s), **_summary(fs), "findings_count": len(fs)}
    finally:
        st.close()


@app.get("/api/scans/{scan_id}/findings")
def scan_findings(scan_id: str) -> list[dict]:
    st = _store()
    try:
        return [_row_to_finding(f) for f in st.list(scan_id=scan_id)]
    finally:
        st.close()


def _summary(findings: list[dict]) -> dict:
    sev = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    state = {}
    for f in findings:
        s = str(f.get("severity", "")).lower()
        if s in sev:
            sev[s] += 1
        stt = f.get("state", "")
        state[stt] = state.get(stt, 0) + 1
    return {"severity_counts": sev, "state_counts": state}


# ---- findings + lifecycle -------------------------------------------------

@app.get("/api/findings")
def all_findings(state: str | None = Query(None)) -> list[dict]:
    st = _store()
    try:
        return [_row_to_finding(f) for f in st.list(state=state)]
    finally:
        st.close()


@app.get("/api/findings/{finding_id}")
def get_finding(finding_id: str) -> dict:
    st = _store()
    try:
        row = st.get(finding_id)
        if row is None:
            raise HTTPException(404, f"no such finding: {finding_id}")
        return _row_to_finding(row)
    finally:
        st.close()


@app.get("/api/findings/{finding_id}/dataflow")
def finding_dataflow(finding_id: str) -> dict:
    st = _store()
    try:
        row = st.get(finding_id)
        if row is None:
            raise HTTPException(404, f"no such finding: {finding_id}")
        return build_dataflow(_row_to_finding(row))
    finally:
        st.close()


# human-only lifecycle. We walk only LEGAL transitions (engine enforces them too).
_CONFIRM_PATH = [State.CANDIDATE, State.VALIDATION_PENDING, State.VALIDATED,
                 State.HUMAN_CONFIRMED]


def _transition_to(finding_id: str, target: State) -> dict:
    st = _store()
    try:
        row = st.get(finding_id)
        if row is None:
            raise HTTPException(404, f"no such finding: {finding_id}")
        current = State(row["state"])
        if current in (State.HUMAN_CONFIRMED, State.FALSE_POSITIVE):
            raise HTTPException(409, f"finding already {current.value}")
        try:
            if target == State.HUMAN_CONFIRMED:
                start = _CONFIRM_PATH.index(current) if current in _CONFIRM_PATH else 0
                for nxt in _CONFIRM_PATH[start + 1:]:
                    st.transition(finding_id, nxt, actor="human")
            else:  # FALSE_POSITIVE is reachable directly from most states
                st.transition(finding_id, target, actor="human")
        except (ValueError, PermissionError) as e:
            raise HTTPException(409, str(e))
        return _row_to_finding(st.get(finding_id))
    finally:
        st.close()


@app.post("/api/findings/{finding_id}/confirm")
def confirm(finding_id: str) -> dict:
    return _transition_to(finding_id, State.HUMAN_CONFIRMED)


@app.post("/api/findings/{finding_id}/false-positive")
def false_positive(finding_id: str) -> dict:
    return _transition_to(finding_id, State.FALSE_POSITIVE)


# ---- benchmarks (committed result JSONs — never fabricated) ---------------

@app.get("/api/benchmarks")
def benchmarks() -> list[dict]:
    rdir = ROOT / "evaluation" / "results"
    out = []
    for p in sorted(rdir.glob("*.json"), reverse=True):
        try:
            d = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue
        run = d.get("run", {})
        out.append({
            "file": p.name,
            "mode": run.get("mode"),
            "provider": run.get("provider"),
            "model": run.get("model"),
            "mock": run.get("mock"),
            "timestamp": run.get("timestamp"),
            "aggregate": d.get("aggregate"),
            "skills": list((d.get("skills") or {}).keys()) if isinstance(d.get("skills"), dict) else None,
            "fixtures": d.get("fixtures"),
            "source": "evaluation/results (committed)",
        })
    return out


# ---- reports --------------------------------------------------------------

@app.get("/api/reports")
def reports() -> list[dict]:
    rdir = CFG.path(CFG.storage["reports_dir"])
    exts = {".md": "markdown", ".json": "json", ".html": "html", ".sarif": "sarif"}
    out = []
    if rdir.is_dir():
        for p in sorted(rdir.iterdir(), reverse=True):
            if p.suffix in exts and p.is_file():
                out.append({"name": p.name, "scan_id": p.stem, "format": exts[p.suffix],
                            "size": p.stat().st_size, "mtime": p.stat().st_mtime})
    return out


@app.get("/api/reports/{name}")
def report_content(name: str) -> dict:
    rdir = CFG.path(CFG.storage["reports_dir"])
    p = (rdir / name).resolve()
    if rdir.resolve() not in p.parents or not p.is_file():
        raise HTTPException(404, f"no such report: {name}")
    return {"name": p.name, "format": p.suffix.lstrip("."),
            "content": p.read_text(encoding="utf-8", errors="replace")}


# ---- scan trigger (real pipeline via the CLI) -----------------------------

class ScanRequest(BaseModel):
    repo: str
    skills: list[str] | None = None        # e.g. ["source_audit","taint"]
    rag: bool = False
    taint_all_chains: bool = False
    scan_id: str | None = None


@app.post("/api/scans")
def start_scan(req: ScanRequest) -> dict:
    repo = Path(req.repo).expanduser()
    if not repo.is_dir():
        raise HTTPException(400, f"repository path not found or not a directory: {req.repo}")
    job = JOBS.start_audit(
        repo=str(repo), skills=req.skills, rag=req.rag,
        taint_all_chains=req.taint_all_chains, scan_id=req.scan_id,
        config_path=os.environ.get("SECURITY_AGENT_CONFIG"))
    return job.public()


@app.get("/api/jobs/{job_id}")
def job_status(job_id: str) -> dict:
    job = JOBS.get(job_id)
    if job is None:
        raise HTTPException(404, f"no such job: {job_id}")
    return job.public()


@app.get("/api/pipeline")
def pipeline() -> list[dict]:
    """The canonical pipeline stages (for the Overview architecture card)."""
    return [{"key": k, "label": l} for k, l in STAGES]
