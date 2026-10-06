"""Cross-skill finding de-duplication.

When several skills audit the same file, a weak local model may report the same
underlying bug from more than one skill (observed: the `secrets` skill also
reporting a command injection that `source_audit` found). This merges such
duplicates into a single finding that records every skill that saw it — the
first real piece of the evidence graph (DESIGN 9c layer 7).

Merge rule (deliberately conservative — never fuse two genuinely different bugs):
two findings merge iff they share the same target file, the same *canonical*
vuln class, AND a compatible code-line signature (one line_hint is a substring
of the other, or one side has no line signature). Distinct lines never merge.

Owns `canonical_class` so the whole platform (and the eval harness) share one
vuln-class vocabulary.
"""
from __future__ import annotations

import re
from collections import defaultdict

from security_agent.findings.models import Finding

# canonical class -> substrings that indicate it (lowercase, matched on a
# normalized form of the model's vuln_class text). Single source of truth;
# evaluation/metrics.py imports canonical_class from here.
CANON: dict[str, list[str]] = {
    "path_traversal": ["path travers", "traversal", "lfi", "local file inclusion",
                       "directory travers", "file inclusion", "arbitrary file read"],
    "sqli": ["sql inject", "sqli", "sql-injection"],
    "command_injection": ["command inject", "cmd inject", "os command", "rce",
                          "remote code execu", "shell inject", "code inject"],
    "ssrf": ["ssrf", "server-side request", "server side request"],
    "xss": ["xss", "cross-site script", "cross site script"],
    "idor": ["idor", "insecure direct object", "broken access", "authorization"],
    "ssti": ["ssti", "template inject"],
    "deserialization": ["deserial", "pickle", "unsafe yaml"],
    "open_redirect": ["open redirect"],
    "hardcoded_secret": ["hardcoded", "hard-coded", "secret", "api key", "access key",
                         "credential", "private key", "password"],
}

_SEVERITY_ORDER = {"unknown": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def canonical_class(raw_class: str) -> str:
    """Map a free-form vuln_class to a canonical token, or 'other:<text>'.

    Needles must start at a word boundary, so short ones like "rce" don't fire
    inside "source" / "force" / "resource"."""
    s = " ".join(str(raw_class).lower().replace("_", " ").replace("-", " ").split())
    for canon, needles in CANON.items():
        if any(re.search(r"\b" + re.escape(n), s) for n in needles):
            return canon
    return f"other:{s}" if s else "other:unknown"


def _line_sig(f: Finding) -> str:
    """Normalized code-line signature: the model's line_hint if present, else the
    location, whitespace-stripped and lowercased."""
    raw = ""
    if isinstance(f.evidence, dict):
        item = f.evidence.get("raw_item")
        if isinstance(item, dict):
            raw = str(item.get("line_hint", ""))
    if not raw:
        # fall back to whatever is inside the location string
        raw = f.location
    return "".join(str(raw).lower().split())


def _compatible(a: str, b: str) -> bool:
    if not a or not b:
        return True                       # can't distinguish -> allow merge within same class+target
    return a in b or b in a


def _severity_rank(sev: str) -> int:
    return _SEVERITY_ORDER.get(str(sev).lower(), 0)


def _merge_cluster(cluster: list[Finding]) -> tuple[Finding, dict]:
    """Merge >1 findings of the same bug into one; return (finding, merge_record)."""
    # primary: prefer a location with a function (contains ':'), then lowest id
    cluster_sorted = sorted(cluster, key=lambda f: (":" not in f.location, f.id))
    primary = cluster_sorted[0]
    others = cluster_sorted[1:]

    sources = sorted({f.source for f in cluster})
    severity = max(cluster, key=lambda f: _severity_rank(f.severity)).severity

    evidence = dict(primary.evidence) if isinstance(primary.evidence, dict) else {}
    evidence["merged_from"] = [f.id for f in others]
    evidence["all_sources"] = sources
    evidence["merged_raw_items"] = [
        f.evidence.get("raw_item") for f in cluster
        if isinstance(f.evidence, dict) and f.evidence.get("raw_item") is not None
    ]

    merged = Finding(
        id=primary.id,
        scan_id=primary.scan_id,
        source="+".join(sources),
        target=primary.target,
        vuln_class=primary.vuln_class,
        severity=severity,
        confidence=primary.confidence,
        location=primary.location,
        description=primary.description,
        poc=primary.poc,
        remediation=primary.remediation,
        state=primary.state,
        created_at=primary.created_at,
        evidence=evidence,
    )
    record = {
        "kept": primary.id,
        "merged": [f.id for f in others],
        "sources": sources,
        "vuln_class": primary.vuln_class,
        "target": primary.target,
    }
    return merged, record


def _cluster_by_sig(group: list[Finding]) -> list[list[Finding]]:
    """Greedily cluster same-(target,class) findings by compatible line signature."""
    clusters: list[list[Finding]] = []
    reps: list[str] = []
    for f in group:
        sig = _line_sig(f)
        for i, rep in enumerate(reps):
            if _compatible(sig, rep):
                clusters[i].append(f)
                if not rep and sig:        # upgrade an empty representative
                    reps[i] = sig
                break
        else:
            clusters.append([f])
            reps.append(sig)
    return clusters


def apply_taint_authority(
    findings: list[Finding], cleared: list[dict],
) -> tuple[list[Finding], list[dict]]:
    """Taint-authoritative suppression (DESIGN Phase 18/17 merge policy).

    The cross-file taint engine reasons over a whole source->sink slice, so when
    it judges a chain *neutralized* it is more trustworthy than a per-file reader
    that only saw the sink in isolation. `cleared` is the list of neutralized-chain
    verdicts taint emitted ({class, chain_files, ...}). We drop any NON-taint
    finding whose canonical class matches a cleared verdict AND whose file lies on
    that cleared chain — that is exactly the per-file false positive taint corrects.

    Conservative: taint's own findings are never dropped; a finding is suppressed
    only when taint explicitly cleared a chain of the same class through its file.
    Returns (kept_findings, suppressed_records)."""
    if not cleared:
        return findings, []
    cleared_files: dict[str, set[str]] = defaultdict(set)
    for c in cleared:
        cleared_files[c["class"]].update(c.get("chain_files", []))

    kept: list[Finding] = []
    suppressed: list[dict] = []
    for f in findings:
        is_taint = isinstance(f.evidence, dict) and f.evidence.get("engine") == "taint"
        files = cleared_files.get(canonical_class(f.vuln_class), set())
        if not is_taint and f.target in files:
            suppressed.append({"id": f.id, "source": f.source,
                               "vuln_class": f.vuln_class, "target": f.target,
                               "reason": "taint judged this source->sink chain neutralized"})
        else:
            kept.append(f)
    return kept, suppressed


def dedup_findings(findings: list[Finding]) -> tuple[list[Finding], list[dict]]:
    """Merge cross-skill duplicates. Returns (deduped_findings, merge_records)."""
    buckets: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for f in findings:
        buckets[(f.target, canonical_class(f.vuln_class))].append(f)

    deduped: list[Finding] = []
    merges: list[dict] = []
    for group in buckets.values():
        for cluster in _cluster_by_sig(group):
            if len(cluster) == 1:
                deduped.append(cluster[0])
            else:
                merged, record = _merge_cluster(cluster)
                deduped.append(merged)
                merges.append(record)

    deduped.sort(key=lambda f: f.id)
    return deduped, merges
