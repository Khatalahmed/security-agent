"""Scoring for the security-agent evaluation harness.

Turns raw model findings + ground truth into per-fixture and aggregate metrics:
detection rate, false-positive rate, false-negative rate, JSON-valid rate,
and timing. Pure stdlib; no dependency on the platform package.

The hard part is matching the model's free-form `vuln_class` strings
("Local File Inclusion", "Path Traversal", "LFI") to canonical tokens. We do
that with a keyword map (CANON) and fall back to a normalized-substring check.
"""
from __future__ import annotations

from dataclasses import dataclass, field

# Single source of truth for the vuln-class vocabulary lives in the platform.
from security_agent.findings.dedup import canonical_class as canonicalize


@dataclass
class FixtureScore:
    fixture: str
    expected: list[str]
    found: list[str]                 # canonicalized, deduped
    raw_found: list[str] = field(default_factory=list)
    tp: int = 0
    fp: int = 0
    fn: int = 0
    json_ok: int = 0
    json_bad: int = 0
    seconds: float = 0.0

    @property
    def clean_fixture(self) -> bool:
        return len(self.expected) == 0

    def as_dict(self) -> dict:
        return {
            "fixture": self.fixture,
            "expected": self.expected,
            "found": self.found,
            "raw_found": self.raw_found,
            "tp": self.tp, "fp": self.fp, "fn": self.fn,
            "json_ok": self.json_ok, "json_bad": self.json_bad,
            "seconds": round(self.seconds, 1),
        }


def score_fixture(fixture: str, expected: list[str], raw_classes: list[str],
                  json_ok: int, json_bad: int, seconds: float,
                  graded_on: list[str] | None = None) -> FixtureScore:
    """Compare one fixture's findings against the classes this run is responsible
    for. For a broad skill that's the fixture's full `expected`; for a focused
    skill pass `graded_on = expected ∩ skill.detects` (empty means the skill
    should find nothing here, so any finding is a false positive)."""
    found = sorted({canonicalize(c) for c in raw_classes})
    graded = set(graded_on) if graded_on is not None else set(expected)
    tp = len(graded & set(found))
    fn = len(graded - set(found))
    # false positives: any found class the run was not responsible for
    fp = len([f for f in found if f not in graded])
    return FixtureScore(
        fixture=fixture, expected=sorted(graded), found=found,
        raw_found=list(raw_classes), tp=tp, fp=fp, fn=fn,
        json_ok=json_ok, json_bad=json_bad, seconds=seconds,
    )


def aggregate(scores: list[FixtureScore]) -> dict:
    """Roll per-fixture scores into headline metrics."""
    tp = sum(s.tp for s in scores)
    fp = sum(s.fp for s in scores)
    fn = sum(s.fn for s in scores)
    json_ok = sum(s.json_ok for s in scores)
    json_bad = sum(s.json_bad for s in scores)
    total_files = json_ok + json_bad
    total_expected = sum(len(s.expected) for s in scores)

    clean = [s for s in scores if s.clean_fixture]
    clean_fp = sum(s.fp for s in clean)
    clean_with_fp = sum(1 for s in clean if s.fp > 0)

    def rate(n: int, d: int) -> float:
        return round(n / d, 3) if d else 0.0

    return {
        "fixtures": len(scores),
        "detection_rate": rate(tp, total_expected),          # TP / all planted bugs
        "false_negative_rate": rate(fn, total_expected),
        "false_positives_total": fp,
        "fp_on_clean_fixtures": clean_fp,                     # the number that matters most
        "clean_fixtures": len(clean),
        "clean_fixtures_with_any_fp": clean_with_fp,
        "json_valid_rate": rate(json_ok, total_files),
        "files_analyzed": total_files,
        "total_seconds": round(sum(s.seconds for s in scores), 1),
        "avg_seconds_per_file": round(sum(s.seconds for s in scores) / total_files, 1) if total_files else 0.0,
        "counts": {"tp": tp, "fp": fp, "fn": fn, "expected": total_expected},
    }
