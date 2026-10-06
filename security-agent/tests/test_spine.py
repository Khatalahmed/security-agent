"""Fast, dependency-free regression tests for the Phase 1 spine.

Run:  python tests/test_spine.py   (exit 0 = all passed)
Uses a stub AI provider so no Ollama/model is needed.
"""
import json
import sys
import tempfile
from pathlib import Path

# allow running from repo root
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security_agent.ai.base import AIProvider, AIResult
from security_agent.findings import FindingStore, State, dedup_findings, canonical_class
from security_agent.findings.models import Finding
from security_agent.safety import ScopeGuard
from security_agent.skills.source_audit import run_source_audit
from security_agent.skillengine import (
    Context, SkillRegistry, detect_languages, plan, filter_enabled, validate_item,
)

SKILLS_DIR = Path(__file__).resolve().parent.parent / "skills"

_PASS = 0
_FAIL = 0


def check(name, cond):
    global _PASS, _FAIL
    if cond:
        _PASS += 1
        print(f"  PASS {name}")
    else:
        _FAIL += 1
        print(f"  FAIL {name}")


class StubProvider(AIProvider):
    name = "stub"

    def generate(self, system, prompt, *, json=True):
        payload = (
            '{"findings":['
            '{"vuln_class":"SSRF","function":"fetch","line_hint":"requests.get(url)",'
            '"severity":"high","confidence":"high","why":"x","poc_request":"/fetch?url=...",'
            '"remediation":"allowlist"},'
            '{"vuln_class":"LFI","function":"download","line_hint":"send_file(path)",'
            '"severity":"high","confidence":"medium","why":"y","poc_request":"/download?name=../",'
            '"remediation":"sanitize"},'
            '{"vuln_class":"Command Injection","function":"ping","line_hint":"shell=True",'
            '"severity":"critical","confidence":"high","why":"z","poc_request":"/ping?host=;id",'
            '"remediation":"no shell"}'
            ']}'
        )
        return AIResult(text=payload, input_tokens=100, output_tokens=120, seconds=0.0)


def test_scope_guard():
    print("[scope guard]")
    g = ScopeGuard([])
    check("empty scope refuses", not g.check("example.com").allowed)
    g = ScopeGuard(["example.com", ".corp.example.org"])
    check("exact host allowed", g.check("https://example.com/x").allowed)
    check("subdomain rule allows sub", g.check("api.corp.example.org").allowed)
    check("subdomain rule base allowed", g.check("corp.example.org").allowed)
    check("unrelated host refused", not g.check("evil.com").allowed)
    check("non-listed sub refused", not g.check("example.org").allowed)


def test_id_uniqueness_and_store():
    print("[source audit id uniqueness + store]")
    with tempfile.TemporaryDirectory() as d:
        repo = Path(d) / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("print('x')\n", encoding="utf-8")
        findings, stats = run_source_audit(
            repo=repo, scan_id="t1", provider=StubProvider(),
            include_globs=["*.py"], skip_dirs=[], max_file_kb=48, start_index=1,
        )
        ids = [f.id for f in findings]
        check("three findings produced", len(findings) == 3)
        check("ids are unique", len(set(ids)) == 3)
        check("ids sequential", ids == ["F-t1-001", "F-t1-002", "F-t1-003"])
        check("json_ok counted", stats["json_ok"] == 1)

        store = FindingStore(Path(d) / "f.db")
        store.create_scan("t1", "audit", str(repo), "stub", {})
        for f in findings:
            store.add_finding(f)
        check("all three persisted", len(store.list(scan_id="t1")) == 3)
        store.close()


class MalformedStubProvider(AIProvider):
    """Returns valid JSON whose findings array mixes a proper object with a bare
    string — the shape qwen produced that crashed source_audit (regression)."""
    name = "stub-malformed"

    def generate(self, system, prompt, *, json=True):
        payload = (
            '{"findings":['
            '"SQL Injection in find_user via string formatting",'          # bad: string
            '{"vuln_class":"SQL Injection","function":"find_user",'        # good: object
            '"severity":"high","why":"x","poc_request":"\' OR 1=1"}'
            ']}'
        )
        return AIResult(text=payload, input_tokens=90, output_tokens=60, seconds=0.0)


def test_malformed_finding_items():
    print("[malformed finding items don't crash]")
    with tempfile.TemporaryDirectory() as d:
        repo = Path(d) / "repo"
        repo.mkdir()
        (repo / "db.py").write_text("print('x')\n", encoding="utf-8")
        crashed = False
        findings = []
        stats = {}
        try:
            findings, stats = run_source_audit(
                repo=repo, scan_id="t3", provider=MalformedStubProvider(),
                include_globs=["*.py"], skip_dirs=[], max_file_kb=48, start_index=1,
            )
        except Exception:
            crashed = True
        check("no crash on non-object finding item", not crashed)
        check("valid object still becomes a finding", len(findings) == 1)
        check("malformed item counted", stats.get("malformed_items") == 1)
        check("json still counted ok", stats.get("json_ok") == 1)


def test_skill_registry_and_loader():
    print("[skill registry + loader]")
    reg = SkillRegistry.discover(SKILLS_DIR)
    check("no skill load errors", reg.errors == [])
    check("full skill library discovered (>=6)", len(reg) >= 6)
    for name in ("source_audit", "secrets", "ssrf", "sqli", "idor", "ssti"):
        check(f"skill '{name}' present", reg.get(name) is not None)
    sa = reg.get("source_audit")
    sec = reg.get("secrets")
    if sa:
        check("supports source_audit mode", sa.supports_mode("source_audit"))
        check("declares python language", "python" in sa.languages)
        check("has a system prompt", len(sa.system_prompt) > 50)
        check("loaded finding schema", bool(sa.finding_schema))
        check("risk level is safe", sa.risk_level == "safe")
    if sec:
        check("secrets is language-agnostic", sec.languages == ())
        check("secrets has its own schema", bool(sec.finding_schema))


def test_planner():
    print("[planner]")
    reg = SkillRegistry.discover(SKILLS_DIR)
    py = plan(reg, Context(mode="source_audit", languages={"python"}))
    names_py = {s.name for s in py}
    check("python repo selects source_audit", "source_audit" in names_py)
    check("python repo also selects secrets (any-language)", "secrets" in names_py)
    go = plan(reg, Context(mode="source_audit", languages={"go"}))
    names_go = {s.name for s in go}
    check("go-only repo selects no python skill", "source_audit" not in names_go)
    check("go repo still selects secrets (any-language)", "secrets" in names_go)
    check("python repo selects focused ssti skill", "ssti" in names_py)
    check("python repo selects focused idor skill", "idor" in names_py)
    scan = plan(reg, Context(mode="target_scan", languages={"python"}))
    check("target_scan selects no source-audit skill", all(s.name != "source_audit" for s in scan))
    check("target_scan selects no secrets skill (source-only)", all(s.name != "secrets" for s in scan))


def test_filter_enabled():
    print("[enabled filter]")
    reg = SkillRegistry.discover(SKILLS_DIR)
    applicable = plan(reg, Context(mode="source_audit", languages={"python"}))
    check("empty enabled = all applicable", len(filter_enabled(applicable, [])) == len(applicable))
    two = filter_enabled(applicable, ["source_audit", "secrets"])
    check("config default keeps exactly the two shipped", {s.name for s in two} == {"source_audit", "secrets"})
    one = filter_enabled(applicable, ["ssti"])
    check("single-skill override", [s.name for s in one] == ["ssti"])
    check("unknown name yields nothing", filter_enabled(applicable, ["nope"]) == [])


def test_language_detection():
    print("[language detection]")
    with tempfile.TemporaryDirectory() as d:
        repo = Path(d)
        (repo / "a.py").write_text("x=1\n", encoding="utf-8")
        (repo / "b.js").write_text("var x=1\n", encoding="utf-8")
        langs = detect_languages(repo, set())
        check("detects python", "python" in langs)
        check("detects javascript", "javascript" in langs)


def test_validator():
    print("[finding validator]")
    schema = {
        "type": "object",
        "required": ["vuln_class", "severity", "why"],
        "properties": {
            "vuln_class": {"type": "string"},
            "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
            "why": {"type": "string"},
        },
    }
    good = {"vuln_class": "SSRF", "severity": "high", "why": "x"}
    check("valid item passes", validate_item(good, schema) == [])
    check("missing required fails", validate_item({"severity": "high", "why": "x"}, schema) != [])
    check("bad enum fails", validate_item({"vuln_class": "X", "severity": "spicy", "why": "x"}, schema) != [])
    check("non-dict fails", validate_item("just a string", schema) != [])
    check("empty schema accepts anything", validate_item("anything", {}) == [])


def _finding(fid, source, target, vuln_class, severity, line_hint, location=""):
    return Finding(
        id=fid, scan_id="d", source=source, target=target, vuln_class=vuln_class,
        severity=severity, location=location or f"{target} ({line_hint})",
        evidence={"raw_item": {"line_hint": line_hint}},
    )


def test_canonical_class():
    print("[canonical class]")
    check("LFI variants collapse",
          canonical_class("Local File Inclusion") == canonical_class("path traversal"))
    check("command injection variants collapse",
          canonical_class("Command Injection") == canonical_class("os command injection"))
    check("secret maps to hardcoded_secret",
          canonical_class("Hardcoded AWS access key") == "hardcoded_secret")
    check("unknown is stable", canonical_class("Frobnication") == canonical_class("frobnication"))


def test_dedup():
    print("[cross-skill dedup]")
    # same target + class + compatible line (substring) -> merge
    a = _finding("F-d-001", "source_audit:ollama", "leaky.py", "Command Injection", "high",
                 'return subprocess.check_output(f"host {host}", shell=True)',
                 location="leaky.py:lookup (subprocess.check_output)")
    b = _finding("F-d-002", "secrets:ollama", "leaky.py", "command injection", "medium",
                 'subprocess.check_output(f"host {host}", shell=True)')
    deduped, merges = dedup_findings([a, b])
    check("duplicate merged to one", len(deduped) == 1)
    check("one merge recorded", len(merges) == 1)
    if deduped:
        m = deduped[0]
        check("both sources recorded", m.source == "secrets:ollama+source_audit:ollama")
        check("max severity kept", m.severity == "high")
        check("function-location primary kept", ":" in m.location)
        check("merged_from in evidence", m.evidence.get("merged_from") == ["F-d-002"])

    # different class -> NOT merged
    c = _finding("F-d-003", "secrets:ollama", "leaky.py", "Hardcoded AWS access key", "high",
                 'AWS_ACCESS_KEY_ID = "AKIA..."')
    deduped2, _ = dedup_findings([a, c])
    check("different class not merged", len(deduped2) == 2)

    # different target -> NOT merged
    d = _finding("F-d-004", "source_audit:ollama", "other.py", "Command Injection", "high",
                 'subprocess.check_output(f"host {host}", shell=True)')
    deduped3, _ = dedup_findings([a, d])
    check("different target not merged", len(deduped3) == 2)

    # same class, DIFFERENT lines -> NOT merged (conservative)
    e = _finding("F-d-005", "source_audit:ollama", "leaky.py", "Command Injection", "high",
                 'os.system("ping " + ip)')
    deduped4, _ = dedup_findings([a, e])
    check("distinct lines not merged", len(deduped4) == 2)


def test_recon_header_analysis():
    print("[recon header analysis]")
    from security_agent.tools import analyze_headers, fingerprint
    none = analyze_headers({}, is_https=True)
    classes = [o["class"] for o in none]
    check("missing CSP flagged", any("Content-Security-Policy" in o["why"] for o in none))
    check("missing HSTS flagged on https", any("Strict-Transport-Security" in o["why"] for o in none))
    check("all flagged are low severity", all(o["severity"] == "low" for o in none))

    full = analyze_headers({
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "no-referrer",
        "Strict-Transport-Security": "max-age=63072000",
    }, is_https=True)
    check("no missing-header obs when all present",
          not any(o["class"] == "missing-security-header" for o in full))

    disc = analyze_headers({"Server": "nginx/1.18.0"}, is_https=False)
    check("version disclosure flagged", any(o["class"] == "version-disclosure" for o in disc))
    check("nginx fingerprinted", "nginx" in fingerprint({"Server": "nginx/1.18.0"}, ""))


def test_recon_findings():
    print("[recon -> findings]")
    from security_agent.recon import AttackSurface, surface_to_findings
    surf = AttackSurface(host="app.example.com", ips=["1.2.3.4"],
                         primary_url="https://app.example.com")
    surf.observations = [
        {"class": "exposed-sensitive-file", "severity": "high",
         "why": ".env readable", "evidence": "GET /.env -> 200"},
        {"class": "missing-security-header", "severity": "low",
         "why": "no CSP", "evidence": "no Content-Security-Policy"},
    ]
    findings = surface_to_findings(surf, "s9", start_index=1)
    check("two recon findings produced", len(findings) == 2)
    check("sourced to recon probe", all(f.source == "recon:probe" for f in findings))
    check("exposed file is high severity",
          any(f.severity == "high" and "Exposed" in f.vuln_class for f in findings))
    check("all candidate", all(f.state == State.CANDIDATE for f in findings))


def test_target_scan_planner():
    print("[planner selects recon for target_scan]")
    reg = SkillRegistry.discover(SKILLS_DIR)
    scan = plan(reg, Context(mode="target_scan", target="x"))
    names = {s.name for s in scan}
    check("recon selected for target_scan", "recon" in names)
    check("source-audit skills excluded from target_scan", "source_audit" not in names)


def test_taint_callgraph():
    print("[taint call-graph cross-file]")
    from security_agent.analysis import build_graph, find_chains, assemble_slice
    repo = Path(__file__).resolve().parent.parent / "evaluation" / "fixtures_taint" / "crossfile_cmdi_vuln"
    graph = build_graph(repo, ["*.py"], [])
    check("no parse errors", graph.errors == [])
    ping = next((f for f in graph.all_funcs if f.name == "ping"), None)
    run_ping = next((f for f in graph.all_funcs if f.name == "run_ping"), None)
    check("ping found", ping is not None)
    check("run_ping found", run_ping is not None)
    if ping and run_ping:
        check("ping is a source (reads request)", ping.is_source)
        check("ping calls run_ping", "run_ping" in ping.calls)
        check("run_ping has a sink", len(run_ping.sinks) >= 1)
        check("sink classified command_injection",
              any(s.vuln_class == "command_injection" for s in run_ping.sinks))

    chains = find_chains(graph)
    cross = [c for c in chains if c.crosses_files and c.sink.vuln_class == "command_injection"]
    check("cross-file source->sink chain found", len(cross) >= 1)
    if cross:
        sl = assemble_slice(cross[0])
        check("slice includes both files",
              "app.py" in sl and "util.py" in sl)
        check("slice includes the sink code", "subprocess.check_output" in sl)


def test_hosted_providers():
    print("[hosted providers]")
    from security_agent.ai import make_provider, provider_is_local
    from security_agent.ai import openai_compat as oai
    from security_agent.ai import anthropic as anth

    # OpenAI-compatible payload/parse
    p = oai.build_payload("gpt-4o", "SYS", "USER", json=True, temperature=0.1, max_tokens=512)
    check("openai has system+user messages",
          [m["role"] for m in p["messages"]] == ["system", "user"])
    check("openai json_object requested", p["response_format"] == {"type": "json_object"})
    txt, i, o = oai.parse_response(
        {"choices": [{"message": {"content": '{"findings":[]}'}}],
         "usage": {"prompt_tokens": 10, "completion_tokens": 3}})
    check("openai parse content", txt == '{"findings":[]}')
    check("openai parse tokens", (i, o) == (10, 3))

    # Anthropic payload/parse
    ap = anth.build_payload("claude-sonnet-5-5", "SYS", "USER", json=True,
                            temperature=0.1, max_tokens=512)
    check("anthropic system set + json nudge", "SYS" in ap["system"] and "JSON" in ap["system"])
    check("anthropic user message", ap["messages"][0]["role"] == "user")
    check("anthropic requires max_tokens", ap["max_tokens"] == 512)
    atxt, ai_, ao = anth.parse_response(
        {"content": [{"type": "text", "text": "hello"}],
         "usage": {"input_tokens": 7, "output_tokens": 2}})
    check("anthropic parse text", atxt == "hello")
    check("anthropic parse tokens", (ai_, ao) == (7, 2))

    # Routing + locality + missing-key error
    check("ollama is local", provider_is_local({"provider": "ollama"}))
    check("openai is not local", not provider_is_local({"provider": "openai"}))
    try:
        make_provider({"provider": "openai", "name": "gpt-4o",
                       "api_key_env": "DEFINITELY_UNSET_KEY_VAR_XYZ"})
        missing_raised = False
    except ValueError:
        missing_raised = True
    check("missing API key raises clear error", missing_raised)
    try:
        make_provider({"provider": "nope", "name": "x"})
        unknown_raised = False
    except ValueError:
        unknown_raised = True
    check("unknown provider raises", unknown_raised)


def test_report_exports():
    print("[report exports json/sarif/html]")
    import json as _json
    from security_agent.reporting import render_json, render_sarif, render_html
    scan_row = {"mode": "audit", "target": "repo", "model": "qwen2.5-coder:7b",
                "started_at": "2026-10-05T00:00:00+00:00"}
    findings = [
        {"id": "F-1", "scan_id": "s", "source": "sqli:ollama", "target": "db.py",
         "vuln_class": "SQL Injection", "severity": "high", "confidence": "high",
         "location": "db.py:17 (query)", "description": "concatenated input",
         "poc": "' OR 1=1", "remediation": "parameterize", "state": "CANDIDATE",
         "created_at": "t", "evidence": '{"file":"db.py"}'},
        {"id": "F-2", "scan_id": "s", "source": "recon:probe", "target": "x",
         "vuln_class": "XSS", "severity": "low", "confidence": "",
         "location": "x", "description": "<script>alert(1)</script>",
         "poc": "", "remediation": "", "state": "CANDIDATE",
         "created_at": "t", "evidence": "{}"},
    ]

    rep = _json.loads(render_json("s", scan_row, findings))
    check("json tool name", rep["tool"] == "security-agent")
    check("json total 2", rep["summary"]["total"] == 2)
    check("json severity counts", rep["summary"]["by_severity"].get("high") == 1)
    check("json findings sorted high-first", rep["findings"][0]["severity"] == "high")
    check("json evidence parsed to object", isinstance(rep["findings"][0]["evidence"], dict))

    sar = _json.loads(render_sarif("s", scan_row, findings))
    check("sarif version", sar["version"] == "2.1.0")
    check("sarif driver name", sar["runs"][0]["tool"]["driver"]["name"] == "security-agent")
    check("sarif two results", len(sar["runs"][0]["results"]) == 2)
    high = next(r for r in sar["runs"][0]["results"] if r["ruleId"] == "sql-injection")
    check("sarif high -> error level", high["level"] == "error")
    check("sarif parsed line number",
          high["locations"][0]["physicalLocation"].get("region", {}).get("startLine") == 17)

    doc = render_html("s", scan_row, findings)
    check("html is a document", doc.startswith("<!doctype html>"))
    check("html includes finding id", "F-1" in doc)
    check("html escapes injected markup", "<script>alert(1)</script>" not in doc)
    check("html has escaped form", "&lt;script&gt;" in doc)


class VerdictStub(AIProvider):
    name = "stub-verdict"

    def __init__(self, verdict="confirm"):
        self._v = verdict

    def generate(self, system, prompt, *, json=True):
        return AIResult(
            text='{"verdict":"%s","confidence":"high","reasoning":"r"}' % self._v,
            input_tokens=50, output_tokens=10, seconds=0.0)


_VERDICT_STUB_DEFAULT = "true_positive"


def test_validation():
    print("[automated validation]")
    from security_agent.validation import build_user_prompt, parse_verdict, run_validation
    from security_agent.skillengine import SkillRegistry as _Reg

    # parse_verdict robustness + alias tolerance
    check("true_positive parsed", parse_verdict('{"verdict":"true_positive"}')["verdict"] == "true_positive")
    check("alias confirm->true_positive", parse_verdict('{"verdict":"confirm"}')["verdict"] == "true_positive")
    check("alias reject->false_positive", parse_verdict('{"verdict":"reject"}')["verdict"] == "false_positive")
    check("bad verdict -> uncertain", parse_verdict('{"verdict":"spicy"}')["verdict"] == "uncertain")
    check("non-json -> uncertain", parse_verdict("not json")["verdict"] == "uncertain")

    # prompt building
    up = build_user_prompt({"vuln_class": "SSRF", "location": "a.py:3", "severity": "high",
                            "source": "ssrf:ollama", "description": "fetches user url",
                            "poc": "?url=...", "evidence": {"chain": ["a.py::f", "b.py::g"]}},
                           code_context="requests.get(url)")
    check("prompt has class", "SSRF" in up)
    check("prompt includes chain", "a.py::f -> b.py::g" in up)
    check("prompt includes code context", "requests.get(url)" in up)

    # run_validation with a stub skill + provider
    skill = _Reg.discover(SKILLS_DIR).get("validation")
    check("validation skill present", skill is not None)
    if skill:
        verdict, _s = run_validation({"vuln_class": "SSRF", "evidence": {}},
                                     VerdictStub("true_positive"), skill)
        check("run_validation returns true_positive", verdict["verdict"] == "true_positive")

    # lifecycle: validator can promote to VALIDATED but not FALSE_POSITIVE
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        store = FindingStore(Path(d) / "v.db")
        store.create_scan("vs", "audit", "x", "m", {})
        store.add_finding(Finding(id="F-vs-1", scan_id="vs", source="s", target="a.py",
                                  vuln_class="SSRF", state=State.CANDIDATE,
                                  evidence={"file": "a.py"}))
        store.transition("F-vs-1", State.VALIDATION_PENDING, actor="validator")
        store.transition("F-vs-1", State.VALIDATED, actor="validator")
        check("validator promoted to VALIDATED", store.get("F-vs-1")["state"] == "VALIDATED")
        store.annotate("F-vs-1", {"validation": {"verdict": "confirm"}})
        ev = json.loads(store.get("F-vs-1")["evidence"])
        check("annotate merged verdict", ev.get("validation", {}).get("verdict") == "confirm")
        store.add_finding(Finding(id="F-vs-2", scan_id="vs", source="s", target="a.py",
                                  vuln_class="XSS", state=State.CANDIDATE))
        try:
            store.transition("F-vs-2", State.FALSE_POSITIVE, actor="validator")
            blocked = False
        except PermissionError:
            blocked = True
        check("validator cannot mark FALSE_POSITIVE", blocked)
        store.close()


def test_rag_retriever():
    print("[rag knowledge retriever]")
    from security_agent.rag import KnowledgeBase, format_hits_for_prompt, tokenize
    corpus = Path(__file__).resolve().parent.parent / "knowledge" / "patterns.jsonl"
    kb = KnowledgeBase.load(corpus)
    check("corpus loaded", len(kb.records) >= 8)
    check("tokenize drops stopwords", "the" not in tokenize("the server fetches a url"))

    ssrf = kb.retrieve("server fetches a user supplied url without an allowlist", k=3, vuln_class="ssrf")
    check("ssrf query returns hits", len(ssrf) >= 1)
    check("top ssrf hit is ssrf class", ssrf[0].record.vuln_class == "ssrf")

    sqli = kb.retrieve("sql query built by string concatenation", k=2, vuln_class="sqli")
    check("sqli query returns sqli record", sqli and sqli[0].record.vuln_class == "sqli")

    idor = kb.retrieve("anything", k=5, vuln_class="idor")
    check("class filter restricts to idor", all(h.record.vuln_class == "idor" for h in idor))

    # unknown class -> falls back to whole corpus (non-empty)
    fallback = kb.retrieve("secrets in code", k=2, vuln_class="nonexistent_class")
    check("unknown class falls back to corpus", len(fallback) >= 1)

    lines = format_hits_for_prompt(ssrf)
    check("format produces reference lines", lines and "ssrf" in lines[0])

    # empty corpus is safe
    empty = KnowledgeBase([])
    check("empty corpus retrieve is safe", empty.retrieve("x") == [])


def test_recon_enumeration():
    print("[recon enumeration: robots/sitemap/subdomains]")
    from security_agent.recon import parse_robots, parse_sitemap, enumerate_subdomains

    rob = parse_robots("User-agent: *\nDisallow: /admin\nDisallow: /internal  # secret\n"
                       "Allow: /public\nSitemap: https://x/sitemap.xml\n")
    check("robots disallow parsed", rob["disallow"] == ["/admin", "/internal"])
    check("robots allow parsed", rob["allow"] == ["/public"])
    check("robots sitemap parsed", rob["sitemaps"] == ["https://x/sitemap.xml"])
    check("robots strips comments", "secret" not in "".join(rob["disallow"]))

    locs = parse_sitemap("<urlset><url><loc>https://x/a</loc></url>"
                         "<url><loc>https://x/b</loc></url></urlset>")
    check("sitemap locs parsed", locs == ["https://x/a", "https://x/b"])

    # injectable resolver: only www + api "resolve"
    def fake_resolve(host):
        return (["1.2.3.4"], "") if host.split(".")[0] in {"www", "api"} else ([], "nxdomain")
    subs = enumerate_subdomains("example.com", wordlist=["www", "api", "nope"],
                                resolver=fake_resolve)
    hosts = {s["host"] for s in subs}
    check("resolving subdomains found", hosts == {"www.example.com", "api.example.com"})
    check("non-resolving dropped", "nope.example.com" not in hosts)


def test_semantic_rag():
    print("[semantic rag embeddings]")
    from security_agent.rag import (
        cosine, SemanticKnowledgeBase, build_cache, load_cache, load_knowledge,
    )
    from security_agent.rag.embeddings import build_embed_payload, parse_embed_response, EmbeddingError
    from security_agent.rag.retriever import Record

    check("cosine identical=1", abs(cosine([1.0, 0.0], [1.0, 0.0]) - 1.0) < 1e-9)
    check("cosine orthogonal=0", abs(cosine([1.0, 0.0], [0.0, 1.0])) < 1e-9)
    check("cosine empty safe", cosine([], [1.0]) == 0.0)

    # Ollama embed payload/parse (pure)
    check("embed payload shape", build_embed_payload("m", "t") == {"model": "m", "prompt": "t"})
    check("embed parse ok", parse_embed_response({"embedding": [1.0, 2.0]}) == [1.0, 2.0])
    try:
        parse_embed_response({"error": "nope"})
        raised = False
    except EmbeddingError:
        raised = True
    check("embed parse error raises", raised)

    # Deterministic fake embedder over a tiny vocab -> separable vectors
    vocab = ["ssrf", "sql", "idor"]
    class FakeEmbedder:
        model = "fake"
        def embed(self, text):
            t = text.lower()
            return [float(t.count(w)) for w in vocab]

    recs = [Record("ssrf-x", "ssrf", "ssrf thing", "ssrf ssrf fetch", "s"),
            Record("sqli-x", "sqli", "sql thing", "sql sql query", "s"),
            Record("idor-x", "idor", "idor thing", "idor idor access", "s")]
    emb = FakeEmbedder()
    vectors = {r.id: emb.embed(r.blob()) for r in recs}
    skb = SemanticKnowledgeBase(recs, vectors, emb)
    hits = skb.retrieve("sql injection in query", k=1)
    check("semantic ranks sqli top for sql query", hits[0].record.vuln_class == "sqli")
    hits2 = skb.retrieve("ssrf url fetch", k=1)
    check("semantic ranks ssrf top for ssrf query", hits2[0].record.vuln_class == "ssrf")

    # cache round-trip + factory fallback
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        corpus = Path(d) / "c.jsonl"
        corpus.write_text("\n".join(json.dumps({"id": r.id, "vuln_class": r.vuln_class,
                          "title": r.title, "text": r.text, "source": r.source}) for r in recs),
                          encoding="utf-8")
        cache = Path(d) / "emb.json"
        n = build_cache(recs, emb, cache)
        check("build_cache wrote all", n == 3)
        model, vecs = load_cache(cache)
        check("cache round-trip", model == "fake" and set(vecs) == {"ssrf-x", "sqli-x", "idor-x"})
        kb, mode = load_knowledge(corpus, mode="semantic", cache=cache, embedder=emb)
        check("factory picks semantic when cache present", mode == "semantic")
        kb2, mode2 = load_knowledge(corpus, mode="semantic", cache=Path(d) / "missing.json", embedder=emb)
        check("factory falls back to bm25 without cache", mode2 == "bm25")


def test_human_gate():
    print("[lifecycle human gate]")
    with tempfile.TemporaryDirectory() as d:
        store = FindingStore(Path(d) / "f.db")
        store.create_scan("t2", "audit", "x", "stub", {})
        store.add_finding(Finding(id="F-t2-001", scan_id="t2", source="s",
                                   target="app.py", vuln_class="SSRF", state=State.CANDIDATE))
        # a skill (non-human) must NOT be able to confirm
        try:
            store.transition("F-t2-001", State.VALIDATION_PENDING, actor="skill")
            store.transition("F-t2-001", State.VALIDATED, actor="skill")
            store.transition("F-t2-001", State.HUMAN_CONFIRMED, actor="skill")
            blocked = False
        except PermissionError:
            blocked = True
        check("skill cannot HUMAN_CONFIRM", blocked)
        # human can
        store.transition("F-t2-001", State.HUMAN_CONFIRMED, actor="human")
        check("human can HUMAN_CONFIRM", store.get("F-t2-001")["state"] == "HUMAN_CONFIRMED")
        # illegal jump rejected
        store.add_finding(Finding(id="F-t2-002", scan_id="t2", source="s",
                                   target="app.py", vuln_class="LFI", state=State.CANDIDATE))
        try:
            store.transition("F-t2-002", State.HUMAN_CONFIRMED, actor="human")
            illegal_blocked = False
        except ValueError:
            illegal_blocked = True
        check("illegal CANDIDATE->CONFIRMED blocked", illegal_blocked)
        store.close()


class FlakyStubProvider(AIProvider):
    """First call raises (e.g. Ollama dropped), later calls succeed; emits a
    capitalized severity the way local models often do."""
    name = "stub-flaky"

    def __init__(self):
        self.calls = 0

    def generate(self, system, prompt, *, json=True):
        self.calls += 1
        if self.calls == 1:
            raise ConnectionError("simulated model outage")
        return AIResult(text='{"findings":[{"vuln_class":"SQL Injection","function":"q",'
                             '"severity":"High","confidence":"Medium","why":"concat"}]}',
                        input_tokens=1, output_tokens=1, seconds=0.0)


def test_review_regressions():
    print("[review regressions]")
    import http.server
    import socketserver
    import threading
    from security_agent.skills.source_audit import discover_files
    from security_agent.analysis.callgraph import build_graph
    from security_agent.skillengine.validator import normalize_enums
    from security_agent.ai import make_provider
    from security_agent.reporting.sarif import render_sarif
    from security_agent.tools import probe
    from security_agent.recon import profiler
    from security_agent.tools.http_probe import ProbeResult

    # skip_dirs must match inside the repo, not the repo's own location
    # (git URLs are cloned into .work/, which is itself a skip dir).
    with tempfile.TemporaryDirectory() as d:
        repo = Path(d) / ".work" / "clone"
        (repo / "tests").mkdir(parents=True)
        (repo / "app.py").write_text("import os\ndef f(request):\n    os.system(request.args['c'])\n")
        (repo / "tests" / "t.py").write_text("x = 1\n")
        skip = [".work", "tests"]
        files, _ = discover_files(repo, ["*.py"], skip, 48)
        check("repo under .work still audited", [p.name for p in files] == ["app.py"])
        check("languages detected under .work", detect_languages(repo, set(skip)) == {"python"})
        check("callgraph built under .work", len(build_graph(repo, ["*.py"], skip).all_funcs) == 1)

        # a failed model call skips one file; a capitalized severity is kept
        (repo / "b.py").write_text("y = 2\n")
        found, stats = run_source_audit(repo=repo, scan_id="r", provider=FlakyStubProvider(),
                                        include_globs=["*.py"], skip_dirs=skip, max_file_kb=48,
                                        skill=SkillRegistry.discover(SKILLS_DIR).get("source_audit"))
        check("model error counted, run continues", stats.get("errors") == 1 and len(found) == 1)
        check("'High' severity accepted + normalized", found and found[0].severity == "high")

    check("'rce' needle not inside 'source'",
          canonical_class("Information disclosure via source maps") != "command_injection")
    check("'force' is not command injection", canonical_class("Brute force login") != "command_injection")
    check("RCE still canonicalizes", canonical_class("RCE via eval") == "command_injection")
    check("normalize_enums leaves unknown values",
          normalize_enums({"severity": "severe"}, {"properties": {"severity": {"enum": ["high"]}}})
          == {"severity": "severe"})

    import os as _os
    _os.environ.setdefault("OPENAI_API_KEY", "test-key")
    p = make_provider({"provider": "openai", "name": "gpt-4o",
                       "base_url": "http://127.0.0.1:11434/api/generate"})
    check("openai ignores the Ollama base_url", p.base_url == "https://api.openai.com/v1")

    # next_index must not reuse an id after a dedup gap
    with tempfile.TemporaryDirectory() as d:
        store = FindingStore(Path(d) / "f.db")
        for fid in ("F-g-001", "F-g-003"):
            store.add_finding(Finding(id=fid, scan_id="g", source="s", target="a", vuln_class="x"))
        check("next_index skips past gaps", store.next_index("g") == 4)
        store.close()

    # probe must not follow a redirect to an unscoped host
    hits = []

    class Redir(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(self.path)
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/elsewhere")
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = socketserver.TCPServer(("127.0.0.1", 0), Redir)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        r = probe(f"http://127.0.0.1:{srv.server_address[1]}/.env", timeout=3)
    finally:
        srv.shutdown()
        srv.server_close()
    check("redirect not followed (3xx surfaced)", r.status == 302 and len(hits) == 1)

    # a catch-all 200 HTML page is not an exposed .env / .git/config
    def fake_probe(url, timeout=8.0):
        if url.endswith("/.env"):
            return ProbeResult(url=url, ok=True, status=200, body_snippet="<html>app</html>")
        if url.endswith("/.git/config"):
            return ProbeResult(url=url, ok=True, status=200,
                               body_snippet='[core]\n\trepositoryformatversion = 0\n')
        return ProbeResult(url=url, ok=True, status=404 if "/." in url or "txt" in url
                           or "xml" in url else 200)
    real_probe, real_resolve = profiler.probe, profiler.resolve
    profiler.probe, profiler.resolve = fake_probe, (lambda h: (["127.0.0.1"], ""))
    try:
        surf = profiler.profile_target("http://h.test", host="h.test", max_rps=0)
    finally:
        profiler.probe, profiler.resolve = real_probe, real_resolve
    flagged = {o["evidence"] for o in surf.observations if o["class"] == "exposed-sensitive-file"}
    check("catch-all .env not flagged", "GET /.env -> 200" not in flagged)
    check("real .git/config still flagged", "GET /.git/config -> 200" in flagged)

    # SARIF: URL port is not a line; taint sink line used; severity on the rule
    rows = [
        {"id": "F-1", "scan_id": "s", "source": "recon:probe", "target": "h", "vuln_class": "X",
         "severity": "low", "confidence": "", "location": "https://h:8443", "description": "",
         "poc": "", "remediation": "", "state": "CANDIDATE", "created_at": "t", "evidence": "{}"},
        {"id": "F-2", "scan_id": "s", "source": "taint:x", "target": "app.py", "vuln_class": "CMDi",
         "severity": "high", "confidence": "", "location": "util.py:run (sink subprocess.run @ 12)",
         "description": "", "poc": "", "remediation": "", "state": "CANDIDATE", "created_at": "t",
         "evidence": json.dumps({"chain": ["app.py::f", "util.py::run"], "sink": {"line": 12}})},
    ]
    run = json.loads(render_sarif("s", None, rows))["runs"][0]
    regions = [r["locations"][0]["physicalLocation"].get("region") for r in run["results"]]
    check("sarif: URL port not a line number", regions[0] is None)
    check("sarif: taint sink line used", regions[1] == {"startLine": 12})
    check("sarif: security-severity on rule",
          all("security-severity" in r["properties"] for r in run["tool"]["driver"]["rules"]))


def test_diff_audit():
    print("[incremental diff audit]")
    import subprocess as sp
    from security_agent.skills.source_audit import discover_files
    from security_agent.vcs import changed_files

    # discover_files `restrict` (pure, no git)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        repo = Path(d)
        (repo / "a.py").write_text("x=1\n", encoding="utf-8")
        (repo / "b.py").write_text("y=2\n", encoding="utf-8")
        only_a, _ = discover_files(repo, ["*.py"], [], 48, restrict={"a.py"})
        check("restrict limits discovery", {f.name for f in only_a} == {"a.py"})
        all_f, _ = discover_files(repo, ["*.py"], [], 48, restrict=None)
        check("no restrict discovers all", {f.name for f in all_f} == {"a.py", "b.py"})
        check("non-git repo reports error", changed_files(repo)[1] != "")

    # vcs.changed_files on a real temp git repo
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        repo = Path(d)

        def git(*a):
            return sp.run(["git", "-C", str(repo), *a], capture_output=True, text=True)

        git("init", "-q")
        git("config", "user.email", "t@t")
        git("config", "user.name", "t")
        (repo / "tracked.py").write_text("print(1)\n", encoding="utf-8")
        git("add", "-A")
        git("commit", "-q", "-m", "init")
        check("clean repo => no changes", changed_files(repo)[0] == set())
        (repo / "tracked.py").write_text("print(2)\n", encoding="utf-8")   # modified
        (repo / "new.py").write_text("print(3)\n", encoding="utf-8")       # untracked
        changed, err = changed_files(repo)
        check("no error on git repo", err == "")
        check("detects modified + untracked", changed == {"tracked.py", "new.py"})


if __name__ == "__main__":
    test_scope_guard()
    test_id_uniqueness_and_store()
    test_malformed_finding_items()
    test_skill_registry_and_loader()
    test_planner()
    test_filter_enabled()
    test_language_detection()
    test_validator()
    test_canonical_class()
    test_dedup()
    test_recon_header_analysis()
    test_recon_findings()
    test_target_scan_planner()
    test_taint_callgraph()
    test_hosted_providers()
    test_report_exports()
    test_validation()
    test_rag_retriever()
    test_recon_enumeration()
    test_semantic_rag()
    test_human_gate()
    test_review_regressions()
    test_diff_audit()
    print(f"\n{_PASS} passed, {_FAIL} failed")
    sys.exit(1 if _FAIL else 0)
