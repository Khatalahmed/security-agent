"""Grow the knowledge corpus.

`add_record` appends one JSONL record. `ingest_files` bulk-imports text/markdown
files (e.g. a checkout of the hackerone-reports dataset) as records, inferring the
vuln class from an explicit arg or the file path. The corpus is plain JSONL so it
stays diffable and dependency-free.
"""
from __future__ import annotations

import json
from pathlib import Path

from security_agent.findings.dedup import canonical_class


def add_record(corpus: Path, record: dict) -> None:
    corpus.parent.mkdir(parents=True, exist_ok=True)
    with open(corpus, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def ingest_files(corpus: Path, src_dir: Path, vuln_class: str | None = None,
                 globs: tuple[str, ...] = ("*.md", "*.txt"),
                 max_chars: int = 4000) -> int:
    """Import matching files under src_dir as records. Returns the count added.

    vuln_class, if omitted, is inferred by canonicalizing the first path segment
    under src_dir (the hackerone-reports layout groups reports by bug type)."""
    added = 0
    for p in sorted(src_dir.rglob("*")):
        if not p.is_file() or not any(p.match(g) for g in globs):
            continue
        rel = p.relative_to(src_dir)
        vc = (vuln_class or canonical_class(rel.parts[0] if rel.parts else p.stem))
        text = p.read_text(encoding="utf-8", errors="replace")[:max_chars]
        add_record(corpus, {
            "id": str(rel).replace("\\", "/"),
            "vuln_class": vc,
            "title": p.stem,
            "text": text,
            "source": f"ingested:{rel}",
        })
        added += 1
    return added


def format_hits_for_prompt(hits) -> list[str]:
    """Render retrieved hits as short reference lines for a skill prompt."""
    return [f"[{h.record.vuln_class}] {h.record.title}: {h.record.text}" for h in hits]
