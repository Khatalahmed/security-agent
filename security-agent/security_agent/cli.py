"""security-agent CLI — Phase 1 spine + working local source-audit.

Commands:
  audit   --repo <path|git-url> [--scan-id ID] [--out FILE]   run source audit
  scan    --target H | --targets FILE                          (scope-guarded; target skills TBD)
  findings [--scan ID] [--state S]                             list stored findings
  confirm <FINDING_ID>                                         human gate: -> HUMAN_CONFIRMED
  reject  <FINDING_ID>                                         human gate: -> FALSE_POSITIVE
  report  --scan ID [--out FILE]                               (re)generate a Markdown report
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from security_agent.config import load_config, load_scope
from security_agent.safety import ScopeGuard
from security_agent.audit_log import AuditLog
from security_agent.ai import make_provider, provider_is_local
from security_agent.findings import FindingStore, State, dedup_findings
from security_agent.skills import run_source_audit
from security_agent.skillengine import (
    SkillRegistry, Context, plan, detect_languages, filter_enabled,
)
from security_agent.recon import (
    profile_target, surface_to_findings, surface_summary, run_target_analysis,
    enumerate_subdomains,
)
from security_agent.findings import Finding
from security_agent.analysis import run_taint_audit
from security_agent.validation import run_validation
from security_agent.rag import (
    KnowledgeBase, add_record, ingest_files, format_hits_for_prompt,
    load_knowledge, OllamaEmbedder, build_cache, EmbeddingError,
)
from security_agent.reporting import render_markdown, RENDERERS


_DIFF_WORKING = "\x00working"   # sentinel: `--diff` with no ref => uncommitted changes


def _provider_notice(cfg) -> None:
    """Warn when a hosted (non-local) backend will receive the analyzed data."""
    if not provider_is_local(cfg.model):
        print(f"[!] PRIVACY: hosted provider '{cfg.model['provider']}' "
              f"({cfg.model['name']}) selected — analyzed code/evidence is sent to that API, "
              "not kept local. Use provider='ollama' to stay fully offline.")


def _merge_stats(stats_list: list[dict]) -> dict:
    """Combine per-skill stats dicts into one summary for logging/printing."""
    merged = {
        "files_analyzed": 0, "files_skipped": 0, "json_ok": 0, "json_bad": 0,
        "total_seconds": 0.0, "malformed_items": 0, "schema_invalid": 0, "errors": 0,
        "chains": 0, "chains_analyzed": 0, "skills": [],
    }
    for st in stats_list:
        for k in ("files_analyzed", "files_skipped", "json_ok", "json_bad",
                  "malformed_items", "schema_invalid", "errors"):
            merged[k] += st.get(k, 0)
        merged["chains"] += st.get("chains", 0)
        merged["chains_analyzed"] += st.get("analyzed", 0)
        merged["total_seconds"] += st.get("total_seconds", 0.0)
        if st.get("skill"):
            merged["skills"].append(st["skill"])
    merged["total_seconds"] = round(merged["total_seconds"], 1)
    return merged


def _new_scan_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _bootstrap(args):
    cfg = load_config(getattr(args, "config", None))
    store = FindingStore(cfg.path(cfg.storage["db_path"]))
    log = AuditLog(cfg.path(cfg.storage["audit_log"]))
    return cfg, store, log


def _clone_if_url(repo_arg: str, cfg) -> tuple[Path, bool]:
    looks_url = repo_arg.startswith(("http://", "https://", "git@")) or repo_arg.endswith(".git")
    if not looks_url:
        return Path(repo_arg).resolve(), False
    name = repo_arg.rstrip("/").split("/")[-1].removesuffix(".git") or "repo"
    # Key the clone dir by the full URL: github.com/a/app and github.com/b/app
    # must not reuse each other's checkout.
    url_tag = hashlib.sha1(repo_arg.encode()).hexdigest()[:8]
    dest = cfg.path(".work") / f"{name}-{url_tag}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        print(f"[*] reusing existing clone at {dest}")
        return dest, True
    print(f"[*] cloning {repo_arg} -> {dest}")
    # "--" so a repo argument can never be parsed as a git option.
    subprocess.run(["git", "clone", "--depth", "1", "--", repo_arg, str(dest)], check=True)
    return dest, True


# ---- commands -----------------------------------------------------------

def cmd_audit(args) -> int:
    cfg, store, log = _bootstrap(args)
    repo, cloned = _clone_if_url(args.repo, cfg)
    if not repo.is_dir():
        print(f"error: repo path not found: {repo}", file=sys.stderr)
        return 2

    # Incremental/diff audit: restrict to files changed vs a git ref.
    restrict_files = None
    if getattr(args, "diff", None) is not None:
        from security_agent.vcs import changed_files
        ref = None if args.diff == _DIFF_WORKING else args.diff
        restrict_files, err = changed_files(repo, ref)
        if err:
            print(f"error: --diff: {err}", file=sys.stderr)
            store.close()
            return 2
        print(f"[*] diff mode: {len(restrict_files)} changed file(s) vs "
              f"{ref or 'HEAD (working tree)'}")
        if not restrict_files:
            print("[*] no changed files to audit; nothing to do.")
            store.close()
            return 0

    scan_id = args.scan_id or _new_scan_id()
    _provider_notice(cfg)
    try:
        provider = make_provider(cfg.model)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        store.close()
        return 2

    # Skill engine: discover skills, detect the repo's languages, plan.
    skills_dir = cfg.path(cfg.data.get("skills", {}).get("dir", "skills"))
    registry = SkillRegistry.discover(skills_dir)
    for sdir, err in registry.errors:
        print(f"[!] skill load error in {sdir}: {err}", file=sys.stderr)
    langs = detect_languages(repo, set(cfg.audit["skip_dirs"]))
    ctx = Context(mode="source_audit", languages=langs, target=str(repo))
    applicable = plan(registry, ctx)

    # Enabled filter: --skills overrides config [skills].enabled; [] = all applicable.
    cli_skills = [s.strip() for s in args.skills.split(",") if s.strip()] if getattr(args, "skills", None) else None
    enabled = cli_skills if cli_skills is not None else cfg.data.get("skills", {}).get("enabled", [])
    selected = filter_enabled(applicable, enabled)
    if enabled:
        unknown = sorted(set(enabled) - {s.name for s in applicable})
        if unknown:
            print(f"[!] requested skill(s) not applicable/known here: {', '.join(unknown)}", file=sys.stderr)
    if cli_skills and not selected:
        # Don't silently fall back to the broad built-in audit on a typo.
        print("error: none of the --skills requested can run on this repo", file=sys.stderr)
        store.close()
        return 2

    store.create_scan(scan_id, "audit", str(repo), cfg.model["name"], cfg.data)
    log.record("audit_started", scan_id=scan_id, repo=str(repo), cloned=cloned,
               model=cfg.model["name"], languages=sorted(langs),
               skills=[s.name for s in selected])
    print(f"[*] scan {scan_id}: auditing {repo} with {cfg.model['name']} "
          f"(provider={cfg.model['provider']})")
    print(f"[*] languages: {', '.join(sorted(langs)) or 'none detected'}")
    print(f"[*] skills:    {', '.join(s.name for s in selected) or '(none applicable — built-in fallback)'}")

    # RAG: optionally ground skill prompts with retrieved disclosed-vuln patterns.
    rag_cfg = cfg.data.get("rag", {})
    use_rag = bool(getattr(args, "rag", False) or rag_cfg.get("enabled"))
    kb = None
    if use_rag:
        kb, kb_mode = load_knowledge(
            cfg.path(rag_cfg.get("corpus", "knowledge/patterns.jsonl")),
            mode=rag_cfg.get("mode", "bm25"),
            cache=cfg.path(rag_cfg.get("cache", "knowledge/embeddings.json")),
            embedder=OllamaEmbedder(rag_cfg.get("embed_model", "nomic-embed-text"),
                                    rag_cfg.get("embed_base_url",
                                                "http://127.0.0.1:11434/api/embeddings")),
        )
        note = "" if kb_mode == rag_cfg.get("mode", "bm25") else " (semantic unavailable -> bm25 fallback)"
        print(f"[*] RAG: grounding with {len(kb.records)} record(s) [{kb_mode}]{note}")
    print("[*] note: candidate findings only — nothing is confirmed without your review.\n")

    def _knowledge_for(skill) -> list[str] | None:
        if not kb or skill is None:
            return None
        cls = skill.detects[0] if skill.detects else None
        query = cls or f"{skill.name} {skill.description}"
        hits = kb.retrieve(query, k=int(rag_cfg.get("k", 3)), vuln_class=cls)
        return format_hits_for_prompt(hits) or None

    findings: list = []
    stats_all: list[dict] = []
    skills_to_run = selected or [None]      # None = built-in prompt fallback
    for skill in skills_to_run:
        if skill is not None:
            print(f"[*] running skill: {skill.name} v{skill.version} (engine={skill.engine})")
        if skill is not None and skill.engine == "taint":
            f_s, st = run_taint_audit(
                repo=repo, scan_id=scan_id, provider=provider, skill=skill,
                include_globs=cfg.audit["include_globs"], skip_dirs=cfg.audit["skip_dirs"],
                start_index=store.next_index(scan_id) + len(findings),
                on_progress=lambda m: print(f"    {m}"),
            )
        else:
            f_s, st = run_source_audit(
                repo=repo, scan_id=scan_id, provider=provider,
                include_globs=cfg.audit["include_globs"], skip_dirs=cfg.audit["skip_dirs"],
                max_file_kb=cfg.audit["max_file_kb"],
                start_index=store.next_index(scan_id) + len(findings),
                on_progress=lambda m: print(f"    {m}"),
                skill=skill, knowledge=_knowledge_for(skill),
                restrict_files=restrict_files,
            )
        findings.extend(f_s)
        stats_all.append(st)

    # Cross-skill de-duplication: merge the same bug reported by >1 skill.
    raw_count = len(findings)
    findings, merges = dedup_findings(findings)
    if merges:
        print(f"[*] merged {raw_count - len(findings)} cross-skill duplicate(s):")
        for m in merges:
            print(f"    {m['kept']} <- {', '.join(m['merged'])}  "
                  f"({m['vuln_class']} in {m['target']}; sources: {', '.join(m['sources'])})")

    for f in findings:
        store.add_finding(f)
    stats = _merge_stats(stats_all)
    stats["raw_findings"] = raw_count
    stats["merged_duplicates"] = raw_count - len(findings)
    log.record("audit_finished", scan_id=scan_id, findings=len(findings),
               merges=merges, stats=stats)

    units = []
    if stats["files_analyzed"]:
        units.append(f"{stats['files_analyzed']} file(s)")
    if stats["chains_analyzed"] or stats["chains"]:
        units.append(f"{stats['chains_analyzed']}/{stats['chains']} chain(s)")
    scope_str = ", ".join(units) or "0 units"
    denom = stats["json_ok"] + stats["json_bad"]
    print(f"\n[*] done: {len(findings)} candidate finding(s) across {scope_str}; "
          f"JSON ok {stats['json_ok']}/{denom}, {stats['total_seconds']}s total")
    if stats["files_skipped"]:
        print(f"    {stats['files_skipped']} file(s) skipped (too large for num_ctx)")
    if stats["errors"]:
        print(f"[!] {stats['errors']} model call(s) failed (see messages above)", file=sys.stderr)

    out = Path(args.out) if args.out else cfg.path(cfg.storage["reports_dir"]) / f"{scan_id}.md"
    _write_report(store, scan_id, out)
    print(f"[*] report: {out}")
    print(f"[*] review:  python -m security_agent findings --scan {scan_id}")
    store.close()
    # Every model call failed (e.g. Ollama not running): don't report success.
    return 1 if stats["errors"] and not (stats["json_ok"] + stats["json_bad"]) else 0


def cmd_scan(args) -> int:
    cfg, store, log = _bootstrap(args)
    scope = ScopeGuard(load_scope(cfg.path(cfg.safety["scope_file"])))

    targets: list[str] = []
    if args.target:
        targets = [args.target]
    elif args.targets:
        targets = [l.strip() for l in Path(args.targets).read_text(encoding="utf-8").splitlines()
                   if l.strip() and not l.strip().startswith("#")]
    if not targets:
        print("error: provide --target HOST or --targets FILE", file=sys.stderr)
        return 2

    allowed, refused = [], []
    for t in targets:
        d = scope.check(t)
        log.record("scope_decision", target=d.target, host=d.host,
                   allowed=d.allowed, reason=d.reason)
        (allowed if d.allowed else refused).append(d)

    print(f"[*] scope check: {len(allowed)} allowed, {len(refused)} refused")
    for d in refused:
        print(f"    REFUSED  {d.target}  ({d.reason})")
    for d in allowed:
        print(f"    allowed  {d.target}")
    if not allowed:
        store.close()
        return 0

    scan_id = args.scan_id or _new_scan_id()
    store.create_scan(scan_id, "scan", ",".join(d.host for d in allowed),
                      cfg.model["name"], cfg.data)
    max_rps = float(cfg.safety.get("max_rps", 2))

    # Recon analysis skill (LLM step) — optional, best-effort.
    use_llm = not getattr(args, "no_llm", False)
    if use_llm:
        _provider_notice(cfg)
    recon_skill = None
    provider = None
    if use_llm:
        reg = SkillRegistry.discover(cfg.path(cfg.data.get("skills", {}).get("dir", "skills")))
        target_skills = plan(reg, Context(mode="target_scan", target="scan"))
        recon_skill = next((s for s in target_skills if s.name == "recon"), None)
        if recon_skill is not None:
            try:
                provider = make_provider(cfg.model)
            except ValueError as e:
                print(f"[!] LLM analysis disabled: {e}", file=sys.stderr)
                recon_skill = None

    all_findings: list = []
    for d in allowed:
        print(f"\n[*] profiling {d.host} (max_rps={max_rps}) ...")
        surface = profile_target(d.target, host=d.host, max_rps=max_rps,
                                 on_progress=lambda m: print(f"    {m}"))
        log.record("recon_profiled", scan_id=scan_id, host=d.host, ips=surface.ips,
                   technologies=surface.technologies,
                   paths=[p["path"] for p in surface.discovered_paths])

        det = surface_to_findings(surface, scan_id,
                                  start_index=store.next_index(scan_id) + len(all_findings))
        all_findings.extend(det)
        print(f"    deterministic recon findings: {len(det)}")

        # Passive subdomain enumeration (DNS only), scope-checked.
        if getattr(args, "subdomains", False) and "." in d.host and not d.host.replace(".", "").isdigit():
            print(f"    enumerating subdomains of {d.host} (DNS only) ...")
            subs = enumerate_subdomains(d.host)
            for s in subs:
                decision = scope.check(s["host"])
                in_scope = decision.allowed
                log.record("subdomain_found", scan_id=scan_id, host=s["host"],
                           ips=s["ips"], in_scope=in_scope)
                print(f"      {s['host']} -> {', '.join(s['ips'])}"
                      f"{'' if in_scope else '  (out of scope)'}")
                if in_scope:
                    fid = f"F-{scan_id}-{store.next_index(scan_id) + len(all_findings):03d}"
                    all_findings.append(Finding(
                        id=fid, scan_id=scan_id, source="recon:dns", target=d.host,
                        vuln_class="Discovered Subdomain", severity="info",
                        location=s["host"], description=f"Resolves to {', '.join(s['ips'])}.",
                        state=State.CANDIDATE,
                        evidence={"host": s["host"], "ips": s["ips"],
                                  "raw_item": {"line_hint": s["host"]}}))

        if recon_skill is not None:
            llm_f, _st = run_target_analysis(
                surface_summary(surface), d.host, scan_id, provider, recon_skill,
                start_index=store.next_index(scan_id) + len(all_findings),
                on_progress=lambda m: print(f"    {m}"))
            all_findings.extend(llm_f)

    raw_count = len(all_findings)
    all_findings, merges = dedup_findings(all_findings)
    for f in all_findings:
        store.add_finding(f)
    log.record("scan_finished", scan_id=scan_id, findings=len(all_findings),
               raw=raw_count, merges=merges)

    print(f"\n[*] done: {len(all_findings)} candidate finding(s) across {len(allowed)} target(s)"
          f"{f' ({raw_count - len(all_findings)} merged)' if raw_count != len(all_findings) else ''}")
    out = Path(args.out) if args.out else cfg.path(cfg.storage["reports_dir"]) / f"{scan_id}.md"
    _write_report(store, scan_id, out)
    print(f"[*] report: {out}")
    print(f"[*] review:  python -m security_agent findings --scan {scan_id}")
    print("[*] note: recon only — nothing confirmed, no active exploitation performed.")
    store.close()
    return 0


def cmd_findings(args) -> int:
    _cfg, store, _log = _bootstrap(args)
    rows = store.list(scan_id=args.scan, state=args.state)
    if not rows:
        print("no findings match.")
        store.close()
        return 0
    print(f"{'ID':<22} {'SEV':<9} {'STATE':<16} {'CLASS':<22} LOCATION")
    for r in rows:
        print(f"{r['id']:<22} {r['severity']:<9} {r['state']:<16} "
              f"{r['vuln_class']:<22} {r['location']}")
    store.close()
    return 0


def _human_transition(args, to_state: State) -> int:
    _cfg, store, log = _bootstrap(args)
    try:
        store.transition(args.finding_id, to_state, actor="human")
    except (KeyError, ValueError, PermissionError) as e:
        print(f"error: {e}", file=sys.stderr)
        store.close()
        return 2
    log.record("human_review", finding_id=args.finding_id, to_state=to_state.value)
    print(f"[*] {args.finding_id} -> {to_state.value}")
    store.close()
    return 0


# Happy-path order toward HUMAN_CONFIRMED. In Phase 1 there is no automated
# validation engine, so a human `confirm` walks these legal hops itself —
# the human IS the validation step.
_CONFIRM_PATH = [
    State.CANDIDATE, State.VALIDATION_PENDING, State.VALIDATED, State.HUMAN_CONFIRMED,
]


def cmd_confirm(args) -> int:
    _cfg, store, log = _bootstrap(args)
    row = store.get(args.finding_id)
    if row is None:
        print(f"error: no such finding: {args.finding_id}", file=sys.stderr)
        store.close()
        return 2
    current = State(row["state"])
    if current in (State.HUMAN_CONFIRMED, State.FALSE_POSITIVE):
        print(f"error: {args.finding_id} is already {current.value}", file=sys.stderr)
        store.close()
        return 2
    # Build the remaining hops from current state to HUMAN_CONFIRMED.
    try:
        start = _CONFIRM_PATH.index(current)
    except ValueError:
        start = 0
    try:
        for nxt in _CONFIRM_PATH[start + 1:]:
            store.transition(args.finding_id, nxt, actor="human")
    except (ValueError, PermissionError) as e:
        print(f"error: {e}", file=sys.stderr)
        store.close()
        return 2
    log.record("human_review", finding_id=args.finding_id, to_state=State.HUMAN_CONFIRMED.value)
    print(f"[*] {args.finding_id} -> {State.HUMAN_CONFIRMED.value}")
    store.close()
    return 0


def cmd_reject(args) -> int:
    return _human_transition(args, State.FALSE_POSITIVE)


def cmd_knowledge(args) -> int:
    cfg = load_config(getattr(args, "config", None))
    corpus = cfg.path(cfg.data.get("rag", {}).get("corpus", "knowledge/patterns.jsonl"))

    rag_cfg = cfg.data.get("rag", {})

    if args.kcmd == "search":
        kb, mode = load_knowledge(
            corpus, mode=rag_cfg.get("mode", "bm25"),
            cache=cfg.path(rag_cfg.get("cache", "knowledge/embeddings.json")),
            embedder=OllamaEmbedder(rag_cfg.get("embed_model", "nomic-embed-text"),
                                    rag_cfg.get("embed_base_url",
                                                "http://127.0.0.1:11434/api/embeddings")))
        try:
            hits = kb.retrieve(args.query, k=args.k, vuln_class=args.vuln_class)
        except EmbeddingError as e:
            print(f"[!] semantic retrieval failed ({e}); falling back to bm25", file=sys.stderr)
            kb, mode = KnowledgeBase.load(corpus), "bm25"
            hits = kb.retrieve(args.query, k=args.k, vuln_class=args.vuln_class)
        print(f"[*] {len(kb.records)} record(s) [{mode}]; top {len(hits)} for {args.query!r}:")
        for h in hits:
            print(f"  [{h.score}] ({h.record.vuln_class}) {h.record.title}")
            print(f"        {h.record.text[:160]}")
        return 0

    if args.kcmd == "embed":
        kb = KnowledgeBase.load(corpus)
        embedder = OllamaEmbedder(rag_cfg.get("embed_model", "nomic-embed-text"),
                                  rag_cfg.get("embed_base_url",
                                              "http://127.0.0.1:11434/api/embeddings"))
        cache = cfg.path(rag_cfg.get("cache", "knowledge/embeddings.json"))
        try:
            n = build_cache(kb.records, embedder, cache)
        except EmbeddingError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        print(f"[*] embedded {n} record(s) with {embedder.model} -> {cache}")
        print("[*] set [rag].mode = \"semantic\" to use it.")
        return 0

    if args.kcmd == "add":
        if not args.vuln_class or not args.title or not args.text:
            print("error: add requires --class, --title, --text", file=sys.stderr)
            return 2
        rid = args.id or f"{args.vuln_class}-{abs(hash(args.title)) % 10000}"
        add_record(corpus, {"id": rid, "vuln_class": args.vuln_class.lower(),
                            "title": args.title, "text": args.text,
                            "source": args.source or "manual"})
        print(f"[*] added record {rid} to {corpus}")
        return 0

    if args.kcmd == "ingest":
        src = Path(args.dir)
        if not src.is_dir():
            print(f"error: not a directory: {src}", file=sys.stderr)
            return 2
        n = ingest_files(corpus, src, vuln_class=args.vuln_class)
        print(f"[*] ingested {n} file(s) from {src} into {corpus}")
        return 0

    print("error: use `knowledge search|add|ingest`", file=sys.stderr)
    return 2


def _validation_context(finding_ev: dict, repo_root: Path | None, max_kb: int = 48) -> str:
    """Best-effort: read the finding's source for grounded validation. For a taint
    finding this includes EVERY file in the chain (source through sink), so the
    validator sees the full reachability picture, not just the sink file."""
    if not repo_root or not repo_root.is_dir():
        return ""
    rels: list[str] = []
    if finding_ev.get("file"):
        rels.append(finding_ev["file"])
    for c in finding_ev.get("chain") or []:
        f = c.split("::")[0]
        if f not in rels:
            rels.append(f)
    parts: list[str] = []
    for rel in rels:
        p = repo_root / rel
        try:
            if p.is_file() and p.stat().st_size <= max_kb * 1024:
                parts.append(f"# --- {rel} ---\n" + p.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            pass
    return "\n\n".join(parts)


def cmd_validate(args) -> int:
    cfg, store, log = _bootstrap(args)
    reg = SkillRegistry.discover(cfg.path(cfg.data.get("skills", {}).get("dir", "skills")))
    skill = reg.get("validation")
    if skill is None:
        print("error: validation skill not found in skills/", file=sys.stderr)
        store.close()
        return 2

    _provider_notice(cfg)
    try:
        provider = make_provider(cfg.model)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        store.close()
        return 2

    scan_row = store.conn.execute("SELECT * FROM scans WHERE scan_id=?", (args.scan,)).fetchone()
    repo_root = None
    if scan_row is not None:
        cand = Path(scan_row["target"])
        repo_root = cand if cand.is_dir() else None

    all_candidates = store.list(scan_id=args.scan, state=State.CANDIDATE.value)
    # Only re-judge MODEL-proposed findings. Deterministic findings (e.g. recon
    # probe facts like "GET /.env -> 200") are not guesses — an LLM skeptic over
    # them adds noise, not signal (observed: it wrongly rejected a real exposure).
    candidates = [r for r in all_candidates
                  if not str(r["source"]).endswith((":probe", ":dns"))]
    skipped = len(all_candidates) - len(candidates)
    if not candidates:
        print(f"[*] no model-proposed CANDIDATE findings to validate in scan {args.scan}"
              f"{f' ({skipped} deterministic finding(s) skipped)' if skipped else ''}")
        store.close()
        return 0

    print(f"[*] validating {len(candidates)} model-proposed candidate(s) in {args.scan} "
          f"with {cfg.model['name']}"
          f"{f'  ({skipped} deterministic skipped)' if skipped else ''}")
    counts = {"true_positive": 0, "false_positive": 0, "uncertain": 0}
    for row in candidates:
        finding = dict(row)
        try:
            finding["evidence"] = json.loads(row["evidence"]) if row["evidence"] else {}
        except Exception:
            finding["evidence"] = {}
        ctx = _validation_context(finding["evidence"], repo_root)
        try:
            verdict, seconds = run_validation(finding, provider, skill, code_context=ctx)
        except Exception as e:      # keep verdicts already recorded; this one stays CANDIDATE
            print(f"    {row['id']}: model call failed ({e}); stays CANDIDATE", file=sys.stderr)
            continue
        counts[verdict["verdict"]] = counts.get(verdict["verdict"], 0) + 1
        store.annotate(row["id"], {"validation": {**verdict, "seconds": round(seconds, 1),
                                                  "grounded": bool(ctx)}})
        if verdict["verdict"] == "true_positive":
            store.transition(row["id"], State.VALIDATION_PENDING, actor="validator")
            store.transition(row["id"], State.VALIDATED, actor="validator")
            tag = "-> VALIDATED"
        else:
            tag = "(stays CANDIDATE)"
        print(f"    {row['id']} [{row['vuln_class']}]: {verdict['verdict']} "
              f"{verdict['confidence']} {tag}  {seconds:.0f}s")
        log.record("validation", scan_id=args.scan, finding_id=row["id"],
                   verdict=verdict["verdict"], confidence=verdict["confidence"])

    print(f"\n[*] validated: {counts['true_positive']} -> VALIDATED, "
          f"{counts['false_positive']} likely-FP + {counts['uncertain']} uncertain stay CANDIDATE "
          "(rejection/confirmation remain human-only).")
    out = Path(args.out) if args.out else cfg.path(cfg.storage["reports_dir"]) / f"{args.scan}.md"
    _write_report(store, args.scan, out)
    print(f"[*] report: {out}")
    store.close()
    return 0


def cmd_report(args) -> int:
    cfg, store, _log = _bootstrap(args)
    scan_row = store.conn.execute("SELECT * FROM scans WHERE scan_id=?", (args.scan,)).fetchone()
    findings = store.list(scan_id=args.scan)
    fmt = getattr(args, "format", None) or "md"
    formats = list(RENDERERS) if fmt == "all" else [fmt]
    reports_dir = cfg.path(cfg.storage["reports_dir"])

    for f in formats:
        renderer, ext = RENDERERS[f]
        text = renderer(args.scan, scan_row, findings)
        path = Path(args.out) if (args.out and len(formats) == 1) else reports_dir / f"{args.scan}.{ext}"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        print(f"[*] report ({f}): {path}")
    store.close()
    return 0


def _write_report(store: FindingStore, scan_id: str, out: Path) -> None:
    """Default Markdown report written by audit/scan."""
    scan_row = store.conn.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
    findings = store.list(scan_id=scan_id)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_markdown(scan_id, scan_row, findings), encoding="utf-8")


# ---- parser -------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="security-agent",
                                description="Local, skill-driven AI security assessment platform.")
    p.add_argument("--config", help="path to config.toml")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="source-code security audit of a repo")
    a.add_argument("--repo", required=True, help="local path or git URL")
    a.add_argument("--scan-id", dest="scan_id")
    a.add_argument("--out", help="report output path (.md)")
    a.add_argument("--skills", help="comma-separated skill names to run "
                                    "(overrides config [skills].enabled; omit to use config)")
    a.add_argument("--rag", action="store_true",
                   help="ground skill prompts with retrieved disclosed-vuln patterns")
    a.add_argument("--diff", nargs="?", const=_DIFF_WORKING, metavar="REF",
                   help="audit only files changed vs REF (default: uncommitted changes); "
                        "requires --repo to be a git work tree")
    a.set_defaults(func=cmd_audit)

    s = sub.add_parser("scan", help="live target assessment (scope-guarded)")
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--target", help="single host/URL")
    g.add_argument("--targets", help="file with one target per line")
    s.add_argument("--scan-id", dest="scan_id")
    s.add_argument("--out", help="report output path (.md)")
    s.add_argument("--no-llm", action="store_true",
                   help="deterministic recon only; skip the LLM analysis step")
    s.add_argument("--subdomains", action="store_true",
                   help="passive subdomain enumeration via DNS (scope-checked)")
    s.set_defaults(func=cmd_scan)

    f = sub.add_parser("findings", help="list stored findings")
    f.add_argument("--scan")
    f.add_argument("--state")
    f.set_defaults(func=cmd_findings)

    c = sub.add_parser("confirm", help="human gate: mark a VALIDATED finding HUMAN_CONFIRMED")
    c.add_argument("finding_id")
    c.set_defaults(func=cmd_confirm)

    r = sub.add_parser("reject", help="human gate: mark a finding FALSE_POSITIVE")
    r.add_argument("finding_id")
    r.set_defaults(func=cmd_reject)

    v = sub.add_parser("validate", help="automated second-opinion over CANDIDATE findings")
    v.add_argument("--scan", required=True)
    v.add_argument("--out", help="report output path (.md)")
    v.set_defaults(func=cmd_validate)

    kn = sub.add_parser("knowledge", help="search/extend the RAG knowledge corpus")
    ksub = kn.add_subparsers(dest="kcmd", required=True)
    ks = ksub.add_parser("search", help="retrieve patterns for a query")
    ks.add_argument("query")
    ks.add_argument("--class", dest="vuln_class", help="restrict to a canonical class")
    ks.add_argument("-k", type=int, default=3)
    ka = ksub.add_parser("add", help="add one knowledge record")
    ka.add_argument("--class", dest="vuln_class", required=True)
    ka.add_argument("--title", required=True)
    ka.add_argument("--text", required=True)
    ka.add_argument("--id")
    ka.add_argument("--source")
    ki = ksub.add_parser("ingest", help="bulk-import text/markdown files as records")
    ki.add_argument("--dir", required=True)
    ki.add_argument("--class", dest="vuln_class", help="force a class (else inferred from path)")
    ksub.add_parser("embed", help="build local-embedding cache for semantic retrieval")
    kn.set_defaults(func=cmd_knowledge)

    rp = sub.add_parser("report", help="(re)generate a report for a scan")
    rp.add_argument("--scan", required=True)
    rp.add_argument("--out", help="output path (single format) or dir (with --format all)")
    rp.add_argument("--format", choices=["md", "json", "html", "sarif", "all"],
                    default="md", help="report format(s) to write (default md)")
    rp.set_defaults(func=cmd_report)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)
