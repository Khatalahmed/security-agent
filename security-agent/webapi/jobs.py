"""In-process background scan jobs.

A scan runs the EXISTING CLI as a subprocess — the engine's own controlled
interface (scope guard, finding lifecycle and safety stay intact; no security
logic is reimplemented here). We parse the CLI's real stdout `on_progress` lines
into a truthful stage model. There are NO fake percentages: a stage is 'pending',
'active', or 'done' based on lines the engine actually emitted.
"""
from __future__ import annotations

import os
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# canonical pipeline stages, in order. Each maps to real CLI output markers.
STAGES = [
    ("indexed", "Repository indexed"),
    ("planned", "Skills planned"),
    ("source_audit", "Source audit (per-file)"),
    ("taint", "Cross-file taint"),
    ("authority", "Dedup / taint-authority"),
    ("report", "Report generation"),
    ("done", "Complete"),
]


def _classify(line: str) -> str | None:
    s = line.strip()
    if s.startswith("[*] languages:"):
        return "indexed"
    if s.startswith("[*] skills:"):
        return "planned"
    if s.startswith("analyzing ") or "file(s) to analyze" in s:
        return "source_audit"
    if "running skill: taint" in s or s.startswith("chain ["):
        return "taint"
    if "taint-authoritative" in s or "merged" in s and "duplicate" in s:
        return "authority"
    if s.startswith("[*] report:"):
        return "report"
    if s.startswith("[*] done:"):
        return "done"
    return None


@dataclass
class Job:
    id: str
    scan_id: str
    cmd: list[str]
    status: str = "queued"          # queued | running | succeeded | failed
    returncode: int | None = None
    error: str = ""
    stages: list[dict] = field(default_factory=list)
    log: list[str] = field(default_factory=list)

    def public(self) -> dict:
        return {
            "id": self.id, "scan_id": self.scan_id, "status": self.status,
            "returncode": self.returncode, "error": self.error,
            "stages": self.stages, "log_tail": self.log[-40:],
        }


class JobManager:
    def __init__(self, cwd: Path):
        self.cwd = cwd
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def get(self, job_id: str) -> Job | None:
        return self._jobs.get(job_id)

    def start_audit(self, repo: str, skills: list[str] | None, rag: bool,
                    taint_all_chains: bool, scan_id: str | None,
                    config_path: str | None) -> Job:
        sid = scan_id or uuid.uuid4().hex[:12]
        # -u: unbuffered stdout so the engine's progress lines STREAM to us in
        # real time (piped stdout is otherwise block-buffered -> no live stages).
        cmd = [sys.executable, "-u", "-m", "security_agent"]
        if config_path:
            cmd += ["--config", config_path]
        cmd += ["audit", "--repo", repo, "--scan-id", sid]
        if skills:
            cmd += ["--skills", ",".join(skills)]
        if rag:
            cmd += ["--rag"]
        if taint_all_chains:
            cmd += ["--taint-all-chains"]
        job = Job(id=uuid.uuid4().hex[:12], scan_id=sid, cmd=cmd,
                  stages=[{"key": k, "label": l, "state": "pending"} for k, l in STAGES])
        with self._lock:
            self._jobs[job.id] = job
        threading.Thread(target=self._run, args=(job,), daemon=True).start()
        return job

    def _mark(self, job: Job, key: str) -> None:
        hit = False
        for st in job.stages:
            if st["key"] == key:
                st["state"] = "done" if key == "done" else "active"
                hit = True
            elif not hit:
                # everything before the active stage is done
                if st["state"] != "done":
                    st["state"] = "done"
        # once a later stage activates, earlier 'active' -> 'done'
        seen_active = False
        for st in reversed(job.stages):
            if st["state"] == "active" and seen_active:
                st["state"] = "done"
            if st["state"] == "active":
                seen_active = True

    def _run(self, job: Job) -> None:
        job.status = "running"
        try:
            env = {**os.environ, "PYTHONUNBUFFERED": "1", "PYTHONIOENCODING": "utf-8"}
            proc = subprocess.Popen(
                job.cmd, cwd=str(self.cwd), stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True, bufsize=1,
                encoding="utf-8", errors="replace", env=env)
        except Exception as e:  # noqa: BLE001
            job.status, job.error = "failed", f"could not launch scan: {e}"
            return
        assert proc.stdout is not None
        for raw in proc.stdout:
            line = raw.rstrip("\n")
            job.log.append(line)
            key = _classify(line)
            if key:
                self._mark(job, key)
        proc.wait()
        job.returncode = proc.returncode
        job.status = "succeeded" if proc.returncode == 0 else "failed"
        if proc.returncode != 0 and not job.error:
            job.error = "scan process exited non-zero; see log_tail"
        # ensure all stages resolve on success
        if job.status == "succeeded":
            for st in job.stages:
                if st["state"] != "done":
                    st["state"] = "done"
