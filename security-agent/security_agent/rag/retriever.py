"""Knowledge retrieval over the distilled vulnerability corpus — pure stdlib BM25.

No embeddings / vector DB / third-party deps: a transparent, deterministic
keyword retriever (BM25 Okapi) over `knowledge/patterns.jsonl`. Each record is
{id, vuln_class, title, text, source}. Used to ground skill prompts with
real-world-style patterns for the relevant class (DESIGN 9d: HackerOne as RAG).

The corpus is designed to grow: ingest more records (e.g. from the
hackerone-reports dataset) via `rag.ingest` / the `knowledge` CLI.
"""
from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path

_TOKEN_RE = re.compile(r"[a-z0-9]+")
_STOP = {
    "the", "a", "an", "and", "or", "of", "to", "in", "is", "it", "for", "on",
    "with", "that", "this", "as", "by", "be", "are", "at", "from", "into",
    "not", "no", "via", "if", "then", "else", "but", "so", "its",
}

_K1 = 1.5
_B = 0.75


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall(str(text).lower()) if t not in _STOP and len(t) > 1]


@dataclass
class Record:
    id: str
    vuln_class: str
    title: str
    text: str
    source: str

    def blob(self) -> str:
        return f"{self.vuln_class} {self.title} {self.text}"


@dataclass
class Hit:
    record: Record
    score: float


class KnowledgeBase:
    def __init__(self, records: list[Record]):
        self.records = records
        self._tokens = [tokenize(r.blob()) for r in records]
        self._df: dict[str, int] = {}
        for toks in self._tokens:
            for t in set(toks):
                self._df[t] = self._df.get(t, 0) + 1
        self._len = [len(t) for t in self._tokens]
        self._avgdl = (sum(self._len) / len(self._len)) if self._len else 0.0
        self._n = len(records)

    @classmethod
    def load(cls, path: Path) -> "KnowledgeBase":
        records: list[Record] = []
        if path.is_file():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    d = json.loads(line)
                except json.JSONDecodeError:
                    continue
                records.append(Record(
                    id=str(d.get("id", "")), vuln_class=str(d.get("vuln_class", "")).lower(),
                    title=str(d.get("title", "")), text=str(d.get("text", "")),
                    source=str(d.get("source", "")),
                ))
        return cls(records)

    def _idf(self, term: str) -> float:
        df = self._df.get(term, 0)
        return math.log(1 + (self._n - df + 0.5) / (df + 0.5))

    def _score(self, q_terms: list[str], idx: int) -> float:
        toks = self._tokens[idx]
        if not toks:
            return 0.0
        dl = self._len[idx]
        tf: dict[str, int] = {}
        for t in toks:
            tf[t] = tf.get(t, 0) + 1
        s = 0.0
        for t in q_terms:
            f = tf.get(t, 0)
            if f == 0:
                continue
            denom = f + _K1 * (1 - _B + _B * dl / (self._avgdl or 1))
            s += self._idf(t) * (f * (_K1 + 1)) / denom
        return s

    def retrieve(self, query: str, k: int = 3, vuln_class: str | None = None) -> list[Hit]:
        """Top-k records for a query. If vuln_class is given, restrict to that
        class when it has records; otherwise fall back to the whole corpus."""
        q_terms = tokenize(query)
        if vuln_class:
            vc = vuln_class.lower()
            idxs = [i for i, r in enumerate(self.records) if r.vuln_class == vc]
            if not idxs:
                idxs = list(range(self._n))
        else:
            idxs = list(range(self._n))
        scored = [(self._score(q_terms, i), i) for i in idxs]
        scored = [(s, i) for s, i in scored if s > 0] or [(0.0, i) for i in idxs]
        scored.sort(key=lambda x: (-x[0], self.records[x[1]].id))
        return [Hit(self.records[i], round(s, 3)) for s, i in scored[:k]]
