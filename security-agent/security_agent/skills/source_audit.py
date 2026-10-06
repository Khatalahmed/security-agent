"""Source-audit skill — the proven local analysis, generalized to a repo.

Strategy (honest MVP): analyze each in-scope source file with one well-formed,
JSON-enforced prompt sized to fit num_ctx. This is the integration that the
Phase 0 benchmark showed works (3/3, 0 FP, clean JSON) — unlike vulnhuntr's
broken Ollama path.

Known limitation (documented, to be addressed in a later phase): this does
per-file analysis, so it catches same-file sink bugs well but does not yet do
cross-function / cross-file taint tracing (vulnhuntr's specialty). The finding
state therefore stops at CANDIDATE and waits for human review.
"""
from __future__ import annotations

import json
import fnmatch
from pathlib import Path
from typing import Callable, TYPE_CHECKING

from security_agent.ai.base import AIProvider
from security_agent.findings.models import Finding, State
from security_agent.skillengine.validator import normalize_enums, validate_item

if TYPE_CHECKING:
    from security_agent.skillengine.base import Skill

# Fallback prompt used only when no Skill is supplied (e.g. legacy/test callers).
# The canonical prompt now lives in skills/source_audit/manifest.toml.
SYSTEM_PROMPT = (
    "You are a security code auditor. Analyze the given source file for "
    "remotely exploitable vulnerabilities (e.g. LFI/path traversal, command "
    "injection/RCE, SSRF, SQLi, XSS, IDOR, SSTI, insecure deserialization, "
    "auth/authorization flaws). Respond ONLY with JSON of the exact shape: "
    '{"findings":[{"vuln_class":str,"function":str,"line_hint":str,'
    '"severity":"low|medium|high|critical","confidence":"low|medium|high",'
    '"why":str,"poc_request":str,"remediation":str}]}. '
    "Only report real, remotely-reachable issues. If there are none, return "
    '{"findings":[]}. Do not invent issues.'
)


def discover_files(repo: Path, include_globs: list[str], skip_dirs: list[str],
                   max_file_kb: int, restrict: set[str] | None = None,
                   ) -> tuple[list[Path], list[tuple[Path, str]]]:
    """Return (files_to_analyze, skipped[(path, reason)]).

    If `restrict` is given (a set of repo-relative paths, forward-slash), only
    files in that set are considered — used for incremental/diff audits.
    """
    files: list[Path] = []
    skipped: list[tuple[Path, str]] = []
    skip = set(skip_dirs)
    for p in repo.rglob("*"):
        if not p.is_file():
            continue
        # Match skip_dirs against the path *inside* the repo only — the repo itself
        # may live under a skipped name (git URLs are cloned into .work/).
        if any(part in skip for part in p.relative_to(repo).parts):
            continue
        if not any(fnmatch.fnmatch(p.name, g) for g in include_globs):
            continue
        if restrict is not None and p.relative_to(repo).as_posix() not in restrict:
            continue
        if p.stat().st_size > max_file_kb * 1024:
            skipped.append((p, f"larger than {max_file_kb} KB (would exceed num_ctx)"))
            continue
        files.append(p)
    return files, skipped


def _parse_findings(raw: str) -> tuple[list[dict], bool]:
    """Parse model JSON. Returns (findings, json_ok)."""
    try:
        data = json.loads(raw)
        items = data.get("findings", []) if isinstance(data, dict) else []
        return (items if isinstance(items, list) else []), True
    except Exception:
        return [], False


def run_source_audit(
    repo: Path,
    scan_id: str,
    provider: AIProvider,
    include_globs: list[str],
    skip_dirs: list[str],
    max_file_kb: int,
    start_index: int = 1,
    on_progress: Callable[[str], None] = lambda m: None,
    skill: "Skill | None" = None,
    knowledge: list[str] | None = None,
    restrict_files: set[str] | None = None,
) -> tuple[list[Finding], dict]:
    """Analyze a repository. Returns (findings, stats).

    When `skill` is given, its `system_prompt` and `finding_schema` drive the
    audit and each finding is validated against that schema. When omitted, the
    built-in SYSTEM_PROMPT is used with no schema validation (legacy/test path).
    `knowledge`, if given, is a list of distilled reference patterns (RAG) that
    are prepended to each file prompt as reference context. `restrict_files`, if
    given, limits analysis to those repo-relative paths (incremental/diff audit).
    """
    system_prompt = skill.system_prompt if skill else SYSTEM_PROMPT
    schema = skill.finding_schema if skill else {}
    skill_name = skill.name if skill else "source_audit"
    kb_block = ""
    if knowledge:
        kb_block = ("Relevant disclosed-vulnerability patterns (reference only; "
                    "judge the code on its own merits, do not invent issues):\n"
                    + "\n".join(f"- {k}" for k in knowledge) + "\n\n")

    files, skipped = discover_files(repo, include_globs, skip_dirs, max_file_kb,
                                    restrict=restrict_files)
    on_progress(f"{len(files)} file(s) to analyze, {len(skipped)} skipped")

    findings: list[Finding] = []
    counter = start_index
    stats = {
        "files_analyzed": 0, "files_skipped": len(skipped),
        "json_ok": 0, "json_bad": 0, "total_seconds": 0.0,
        "skill": skill_name,
        "skipped": [{"file": str(p.relative_to(repo)), "reason": r} for p, r in skipped],
    }

    for fp in files:
        rel = fp.relative_to(repo)
        on_progress(f"analyzing {rel} ...")
        code = fp.read_text(encoding="utf-8", errors="replace")
        prompt = kb_block + f"File: {rel}\n\n```\n{code}\n```"
        try:
            result = provider.generate(system_prompt, prompt, json=True)
        except Exception as e:      # one failed call must not discard the whole run
            stats["errors"] = stats.get("errors", 0) + 1
            on_progress(f"  ! {rel}: model call failed: {e}")
            continue
        stats["total_seconds"] += result.seconds
        stats["files_analyzed"] += 1

        items, ok = _parse_findings(result.text)
        stats["json_ok" if ok else "json_bad"] += 1
        if not ok:
            on_progress(f"  ! {rel}: model returned non-JSON; recorded as evidence only")
            continue

        for item in items:
            # The model sometimes emits a findings array of bare strings instead
            # of objects (valid JSON, wrong shape). Skip those rather than crash.
            if not isinstance(item, dict):
                stats["malformed_items"] = stats.get("malformed_items", 0) + 1
                on_progress(f"  ! {rel}: non-object finding item skipped: {item!r:.80}")
                continue

            # Validate against the skill's declared finding schema (if any).
            item = normalize_enums(item, schema)
            schema_errors = validate_item(item, schema) if schema else []
            if schema_errors:
                stats["schema_invalid"] = stats.get("schema_invalid", 0) + 1
                on_progress(f"  ! {rel}: finding fails schema ({'; '.join(schema_errors)}); skipped")
                continue
            fid = f"F-{scan_id}-{counter:03d}"
            counter += 1
            func = item.get("function", "")
            line_hint = item.get("line_hint", "")
            loc = f"{rel}:{func}" if func else str(rel)
            if line_hint:
                loc += f" ({line_hint})"
            findings.append(Finding(
                id=fid,
                scan_id=scan_id,
                source=f"{skill_name}:{provider.name}",
                target=str(rel),
                vuln_class=str(item.get("vuln_class", "unknown")),
                severity=str(item.get("severity", "unknown")),
                confidence=str(item.get("confidence", "")),
                location=loc,
                description=str(item.get("why", "")),
                poc=str(item.get("poc_request", "")),
                remediation=str(item.get("remediation", "")),
                state=State.CANDIDATE,
                evidence={
                    "file": str(rel),
                    "skill": skill_name,
                    "model_seconds": round(result.seconds, 1),
                    "input_tokens": result.input_tokens,
                    "output_tokens": result.output_tokens,
                    "raw_item": item,
                },
            ))
        on_progress(f"  {rel}: {len(items)} candidate(s), {result.seconds:.0f}s")

    stats["total_seconds"] = round(stats["total_seconds"], 1)
    return findings, stats
