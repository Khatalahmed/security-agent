"""security-agent evaluation harness (Phase 1.5 + per-skill, Phase 3).

Two modes:
  (default)      run the broad `source_audit` prompt over the corpus — precision
                 of the general skill (detection / FP-on-clean / JSON / timing).
  --per-skill    run every skill (or --skills a,b) over the corpus and score each
                 one on the classes IT is responsible for (its manifest `detects`;
                 broad skill = all expected). Prints a focused-vs-broad comparison
                 so you can see whether a focused skill actually beats the general
                 one on its target class, and at what false-positive cost.

Usage (from security-agent/):
    python -m evaluation.benchmark                      # broad run (slow, CPU)
    python -m evaluation.benchmark --mock               # instant self-test
    python -m evaluation.benchmark --per-skill --mock   # per-skill self-test
    python -m evaluation.benchmark --per-skill --skills source_audit,sqli \
            --fixtures sql_injection,safe_db            # targeted real comparison

Results go to evaluation/results/<timestamp>-<tag>.{json,md}.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent                      # security-agent/
sys.path.insert(0, str(ROOT))

from security_agent.ai.base import AIProvider, AIResult   # noqa: E402
from security_agent.config import load_config             # noqa: E402
from security_agent.skillengine import SkillRegistry       # noqa: E402
from security_agent.skills import run_source_audit        # noqa: E402

from security_agent.rag import KnowledgeBase, format_hits_for_prompt  # noqa: E402

from evaluation.metrics import score_fixture, aggregate   # noqa: E402

FIXTURES = HERE / "fixtures"
EXPECTED = HERE / "expected" / "expected.json"
RESULTS = HERE / "results"
SKILLS_DIR = ROOT / "skills"

# canonical class -> representative label the mock emits
_MOCK_LABEL = {
    "command_injection": "Command Injection", "sqli": "SQL Injection",
    "path_traversal": "Local File Inclusion", "ssrf": "SSRF", "ssti": "SSTI",
    "idor": "IDOR", "hardcoded_secret": "Hardcoded AWS access key",
}


class MockProvider(AIProvider):
    """Skill-aware deterministic stub. Infers the file's real classes from content
    and the skill's focus from the system prompt, so per-skill scoring can be
    validated in milliseconds: a focused skill reports only its class (if present),
    the broad skill reports everything present."""
    name = "mock"

    @staticmethod
    def _present(prompt: str) -> set[str]:
        p = set()
        if "subprocess" in prompt or "os.system" in prompt:
            p.add("command_injection")
        if '" % ' in prompt or "'%s'" in prompt:
            p.add("sqli")
        if "join(DOCS, name)" in prompt and "ALLOWED" not in prompt:
            p.add("path_traversal")
        if "requests.get(url" in prompt:
            p.add("ssrf")
        if "render_template_string(" in prompt and '" +' in prompt:
            p.add("ssti")
        if "invoice(invoice_id)" in prompt:
            p.add("idor")
        if "AKIA" in prompt:
            p.add("hardcoded_secret")
        return p

    @staticmethod
    def _focus(system: str) -> str | None:
        # Order matters: the broad prompt *lists* class names (SSRF, SQLi, ...) as
        # examples, so match the broad/secrets markers BEFORE focused specialists.
        if "secrets-detection auditor" in system:
            return "hardcoded_secret"
        if "security code auditor" in system:
            return None       # broad source_audit
        if "SSRF" in system:
            return "ssrf"
        if "SQL-injection specialist" in system:
            return "sqli"
        if "IDOR" in system:
            return "idor"
        if "SSTI" in system:
            return "ssti"
        return None

    def generate(self, system: str, prompt: str, *, json: bool = True) -> AIResult:
        present = self._present(prompt)
        focus = self._focus(system)
        classes = [focus] if (focus and focus in present) else ([] if focus else sorted(present))
        items = [{"vuln_class": _MOCK_LABEL.get(c, c), "severity": "high", "why": "x"}
                 for c in classes]
        text = __import__("json").dumps({"findings": items})
        return AIResult(text=text, input_tokens=400, output_tokens=60 * len(items), seconds=0.0)


def discover_fixtures(only: str | None, name_filter: list[str] | None,
                      root: Path = FIXTURES) -> list[tuple[str, Path]]:
    out: list[tuple[str, Path]] = []
    for category in sorted(p for p in root.iterdir() if p.is_dir()):
        if only and category.name != only:
            continue
        for fx in sorted(p for p in category.iterdir() if p.is_dir()):
            fid = f"{category.name}/{fx.name}"
            if name_filter and not any(f in fid for f in name_filter):
                continue
            out.append((fid, fx))
    return out


def make_eval_provider(mock: bool) -> AIProvider:
    if mock:
        return MockProvider()
    from security_agent.ai import make_provider
    return make_provider(load_config(root=str(ROOT)).model)


def _audit_fixture(fx_dir: Path, provider, cfg, skill=None, knowledge=None):
    findings, stats = run_source_audit(
        repo=fx_dir, scan_id="eval", provider=provider,
        include_globs=cfg.audit["include_globs"], skip_dirs=cfg.audit["skip_dirs"],
        max_file_kb=cfg.audit["max_file_kb"], on_progress=lambda m: None,
        skill=skill, knowledge=knowledge,
    )
    return [f.vuln_class for f in findings], stats


# ---- broad mode (original) ----------------------------------------------

def run_broad(mock: bool, only: str | None, name_filter: list[str] | None,
              fixtures_root: Path = FIXTURES, expected_path: Path = EXPECTED) -> dict:
    expected_all = json.loads(expected_path.read_text(encoding="utf-8"))["fixtures"]
    provider = make_eval_provider(mock)
    cfg = load_config(root=str(ROOT))

    scores = []
    for fid, fx_dir in discover_fixtures(only, name_filter, fixtures_root):
        expected = expected_all.get(fid, {"expected": []}).get("expected", [])
        print(f"[*] {fid}  (expect: {expected or 'clean'}) ...", flush=True)
        raw, stats = _audit_fixture(fx_dir, provider, cfg)
        s = score_fixture(fid, expected, raw, stats["json_ok"], stats["json_bad"],
                          stats["total_seconds"])
        scores.append(s)
        print(f"    -> {s.found or '[]'}  [TP={s.tp} FP={s.fp} FN={s.fn}]  {s.seconds}s", flush=True)

    return {
        "run": {"timestamp": datetime.now(timezone.utc).isoformat(),
                "mode": "broad", "provider": provider.name,
                "model": None if mock else cfg.model["name"], "mock": mock},
        "aggregate": aggregate(scores),
        "fixtures": [s.as_dict() for s in scores],
    }


# ---- per-skill mode -----------------------------------------------------

def run_per_skill(mock: bool, only: str | None, name_filter: list[str] | None,
                  skills_filter: list[str] | None,
                  fixtures_root: Path = FIXTURES, expected_path: Path = EXPECTED) -> dict:
    expected_all = json.loads(expected_path.read_text(encoding="utf-8"))["fixtures"]
    provider = make_eval_provider(mock)
    cfg = load_config(root=str(ROOT))
    registry = SkillRegistry.discover(SKILLS_DIR)

    skills = registry.all()
    if skills_filter:
        want = set(skills_filter)
        skills = [s for s in skills if s.name in want]
    fixtures = discover_fixtures(only, name_filter, fixtures_root)

    by_skill: dict[str, dict] = {}
    for skill in skills:
        detects = set(skill.detects)
        print(f"\n[*] skill: {skill.name}  (detects: {sorted(detects) or 'ALL (broad)'})", flush=True)
        scores = []
        per_fixture = {}
        for fid, fx_dir in fixtures:
            expected = expected_all.get(fid, {"expected": []}).get("expected", [])
            graded = sorted(set(expected) & detects) if detects else expected
            raw, stats = _audit_fixture(fx_dir, provider, cfg, skill=skill)
            s = score_fixture(fid, expected, raw, stats["json_ok"], stats["json_bad"],
                              stats["total_seconds"], graded_on=graded)
            scores.append(s)
            per_fixture[fid] = s
            print(f"    {fid}: graded_on={graded or '[]'} found={s.found or '[]'} "
                  f"[TP={s.tp} FP={s.fp} FN={s.fn}] {s.seconds}s", flush=True)
        by_skill[skill.name] = {
            "detects": sorted(detects),
            "aggregate": aggregate(scores),
            "by_fixture": {fid: sc.found for fid, sc in per_fixture.items()},
            "fixtures": [sc.as_dict() for sc in scores],
        }

    comparison = _build_comparison(by_skill, expected_all, fixtures)
    return {
        "run": {"timestamp": datetime.now(timezone.utc).isoformat(),
                "mode": "per_skill", "provider": provider.name,
                "model": None if mock else cfg.model["name"], "mock": mock},
        "skills": by_skill,
        "comparison": comparison,
    }


def run_rag_ab(mock: bool, only: str | None, name_filter: list[str] | None,
               skills_filter: list[str] | None,
               fixtures_root: Path = FIXTURES, expected_path: Path = EXPECTED) -> dict:
    """A/B: run each skill over each fixture WITH and WITHOUT RAG knowledge
    injection, so the delta attributable to grounding is measurable."""
    expected_all = json.loads(expected_path.read_text(encoding="utf-8"))["fixtures"]
    provider = make_eval_provider(mock)
    cfg = load_config(root=str(ROOT))
    registry = SkillRegistry.discover(SKILLS_DIR)
    kb = KnowledgeBase.load(ROOT / "knowledge" / "patterns.jsonl")

    skills = [s for s in registry.all() if s.detects]  # focused skills have a class to ground
    if skills_filter:
        want = set(skills_filter)
        skills = [s for s in skills if s.name in want]
    fixtures = discover_fixtures(only, name_filter, fixtures_root)

    def knowledge_for(skill):
        cls = skill.detects[0] if skill.detects else None
        return format_hits_for_prompt(kb.retrieve(cls or skill.name, k=3, vuln_class=cls)) or None

    rows = []
    for skill in skills:
        detects = set(skill.detects)
        kn = knowledge_for(skill)
        print(f"\n[*] RAG A/B skill: {skill.name}  (grounding with {len(kn or [])} pattern(s))", flush=True)
        base_scores, rag_scores = [], []
        for fid, fx_dir in fixtures:
            expected = expected_all.get(fid, {"expected": []}).get("expected", [])
            graded = sorted(set(expected) & detects)
            for label, knowledge, bucket in (("base", None, base_scores), ("rag", kn, rag_scores)):
                raw, stats = _audit_fixture(fx_dir, provider, cfg, skill=skill, knowledge=knowledge)
                bucket.append(score_fixture(fid, expected, raw, stats["json_ok"], stats["json_bad"],
                                            stats["total_seconds"], graded_on=graded))
            b, r = base_scores[-1], rag_scores[-1]
            print(f"    {fid}: base[TP={b.tp} FP={b.fp}] rag[TP={r.tp} FP={r.fp}]", flush=True)
        rows.append({"skill": skill.name, "class": (skill.detects or ["?"])[0],
                     "baseline": aggregate(base_scores), "rag": aggregate(rag_scores)})

    return {
        "run": {"timestamp": datetime.now(timezone.utc).isoformat(), "mode": "rag_ab",
                "provider": provider.name, "model": None if mock else cfg.model["name"],
                "mock": mock, "corpus_records": len(kb.records)},
        "skills": rows,
    }


def _build_comparison(by_skill: dict, expected_all: dict, fixtures) -> list[dict]:
    """For each focused skill, compare its detection of its target class against
    the broad source_audit skill over the fixtures that contain that class."""
    broad = by_skill.get("source_audit")
    rows = []
    for name, data in by_skill.items():
        detects = data["detects"]
        if not detects:                 # skip the broad skill itself
            continue
        cls = detects[0]
        targets = [fid for fid, _ in fixtures
                   if cls in expected_all.get(fid, {}).get("expected", [])]
        if not targets:
            continue
        focused_hits = sum(1 for fid in targets if cls in data["by_fixture"].get(fid, []))
        broad_hits = (sum(1 for fid in targets if cls in broad["by_fixture"].get(fid, []))
                      if broad else None)
        # focused FP on fixtures that do NOT contain its class
        focused_fp = sum(sc["fp"] for sc in data["fixtures"]
                         if cls not in expected_all.get(sc["fixture"], {}).get("expected", []))
        rows.append({
            "skill": name, "class": cls, "target_fixtures": len(targets),
            "focused_detected": focused_hits,
            "broad_detected": broad_hits,
            "focused_fp_elsewhere": focused_fp,
        })
    return rows


# ---- output -------------------------------------------------------------

def write_results(result: dict) -> tuple[Path, Path]:
    RESULTS.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    tag = ("mock" if result["run"]["mock"] else "ollama") + "-" + result["run"]["mode"]
    jpath = RESULTS / f"{stamp}-{tag}.json"
    mpath = RESULTS / f"{stamp}-{tag}.md"
    jpath.write_text(json.dumps(result, indent=2), encoding="utf-8")

    if result["run"]["mode"] == "broad":
        _write_broad_md(result, mpath, stamp)
    elif result["run"]["mode"] == "rag_ab":
        _write_rag_ab_md(result, mpath, stamp)
    else:
        _write_per_skill_md(result, mpath, stamp)
    return jpath, mpath


def _write_rag_ab_md(result: dict, mpath: Path, stamp: str) -> None:
    lines = [f"# Benchmark {stamp} — RAG A/B ({result['run']['provider']})",
             f"model: `{result['run']['model']}` · corpus: {result['run']['corpus_records']} records", "",
             "Detection / FP-on-non-target, without vs with retrieved grounding.", "",
             "| Skill | Class | Detect (base) | Detect (RAG) | FP (base) | FP (RAG) |",
             "|---|---|--:|--:|--:|--:|"]
    for r in result["skills"]:
        b, g = r["baseline"], r["rag"]
        lines.append(f"| {r['skill']} | {r['class']} | "
                     f"{b['detection_rate']:.0%} | {g['detection_rate']:.0%} | "
                     f"{b['fp_on_clean_fixtures']} | {g['fp_on_clean_fixtures']} |")
    mpath.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_broad_md(result: dict, mpath: Path, stamp: str) -> None:
    a = result["aggregate"]
    lines = [
        f"# Benchmark {stamp} — broad ({result['run']['provider']})", "",
        f"- model: `{result['run']['model']}`  ·  fixtures: {a['fixtures']}  ·  files: {a['files_analyzed']}",
        f"- **detection: {a['detection_rate']:.0%}** ({a['counts']['tp']}/{a['counts']['expected']})  "
        f"·  **FP on clean: {a['fp_on_clean_fixtures']}**  ·  JSON {a['json_valid_rate']:.0%}  "
        f"·  {a['avg_seconds_per_file']}s/file", "",
        "| Fixture | Expected | Found | TP | FP | FN | s |",
        "|---|---|---|--:|--:|--:|--:|",
    ]
    for s in result["fixtures"]:
        lines.append(f"| {s['fixture']} | {', '.join(s['expected']) or '—'} | "
                     f"{', '.join(s['found']) or '—'} | {s['tp']} | {s['fp']} | {s['fn']} | {s['seconds']} |")
    mpath.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_per_skill_md(result: dict, mpath: Path, stamp: str) -> None:
    lines = [f"# Benchmark {stamp} — per-skill ({result['run']['provider']})",
             f"model: `{result['run']['model']}`", "",
             "## Focused vs broad (detection of each skill's target class)", "",
             "| Skill | Class | Target fixtures | Focused detected | Broad detected | Focused FP elsewhere |",
             "|---|---|--:|--:|--:|--:|"]
    for r in result["comparison"]:
        bd = "—" if r["broad_detected"] is None else f"{r['broad_detected']}/{r['target_fixtures']}"
        lines.append(f"| {r['skill']} | {r['class']} | {r['target_fixtures']} | "
                     f"{r['focused_detected']}/{r['target_fixtures']} | {bd} | {r['focused_fp_elsewhere']} |")
    lines += ["", "## Per-skill aggregates", "",
              "| Skill | Detects | Detection | FP on non-target | JSON |",
              "|---|---|--:|--:|--:|"]
    for name, d in result["skills"].items():
        a = d["aggregate"]
        lines.append(f"| {name} | {', '.join(d['detects']) or 'ALL'} | "
                     f"{a['detection_rate']:.0%} ({a['counts']['tp']}/{a['counts']['expected']}) | "
                     f"{a['fp_on_clean_fixtures']} | {a['json_valid_rate']:.0%} |")
    mpath.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="security-agent evaluation harness")
    ap.add_argument("--mock", action="store_true", help="deterministic stub instead of the model")
    ap.add_argument("--per-skill", action="store_true", help="score every skill on its target class")
    ap.add_argument("--rag", action="store_true", help="A/B each skill with vs without RAG grounding")
    ap.add_argument("--only", help="limit to one fixture category: vulnerable | safe | mixed")
    ap.add_argument("--fixtures", help="comma-separated substrings; keep only matching fixture ids")
    ap.add_argument("--skills", help="comma-separated skill names (per-skill mode)")
    ap.add_argument("--fixtures-dir", help="fixtures root (default evaluation/fixtures)")
    ap.add_argument("--expected", help="ground-truth json (default evaluation/expected/expected.json)")
    args = ap.parse_args()

    name_filter = [s.strip() for s in args.fixtures.split(",")] if args.fixtures else None
    skills_filter = [s.strip() for s in args.skills.split(",")] if args.skills else None
    fixtures_root = Path(args.fixtures_dir).resolve() if args.fixtures_dir else FIXTURES
    expected_path = Path(args.expected).resolve() if args.expected else EXPECTED

    if args.rag:
        result = run_rag_ab(args.mock, args.only, name_filter, skills_filter,
                            fixtures_root, expected_path)
    elif args.per_skill:
        result = run_per_skill(args.mock, args.only, name_filter, skills_filter,
                               fixtures_root, expected_path)
    else:
        result = run_broad(args.mock, args.only, name_filter, fixtures_root, expected_path)

    jpath, mpath = write_results(result)
    print("\n" + "=" * 60)
    if result["run"]["mode"] == "rag_ab":
        print("RAG A/B (detection base->rag, FP base->rag):")
        for r in result["skills"]:
            b, g = r["baseline"], r["rag"]
            print(f"  {r['class']:16} detect {b['detection_rate']:.0%}->{g['detection_rate']:.0%}  "
                  f"FP {b['fp_on_clean_fixtures']}->{g['fp_on_clean_fixtures']}")
    elif result["run"]["mode"] == "broad":
        a = result["aggregate"]
        print(f"detection {a['detection_rate']:.0%} ({a['counts']['tp']}/{a['counts']['expected']})  "
              f"| FP-on-clean {a['fp_on_clean_fixtures']}  | JSON {a['json_valid_rate']:.0%}")
    else:
        print("focused vs broad (target-class detection):")
        for r in result["comparison"]:
            bd = "n/a" if r["broad_detected"] is None else f"{r['broad_detected']}/{r['target_fixtures']}"
            print(f"  {r['class']:16} focused {r['focused_detected']}/{r['target_fixtures']}  "
                  f"broad {bd}  focused-FP-elsewhere {r['focused_fp_elsewhere']}")
    print("=" * 60)
    print(f"results: {mpath}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
