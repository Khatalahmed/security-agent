"""Semantic retrieval via local embeddings (Ollama) + cosine similarity.

Keeps the platform's principles: fully local (Ollama embeddings endpoint), pure
stdlib for the math, no vector-DB dependency. Record vectors are cached to disk
so audits don't re-embed the corpus every run.

Requires an embeddings-capable Ollama (`ollama serve` with an embedding model such
as `nomic-embed-text` pulled). When embeddings are unavailable, callers fall back
to the BM25 retriever — the semantic path is an upgrade, never a hard requirement.
"""
from __future__ import annotations

import json
import math
import time
import urllib.error
import urllib.request
from pathlib import Path

from security_agent.ai.base import AIResult  # noqa: F401  (kept for symmetry/typing)
from security_agent.rag.retriever import Hit, KnowledgeBase, Record


def cosine(a: list[float], b: list[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


class EmbeddingError(Exception):
    pass


def build_embed_payload(model: str, text: str) -> dict:
    return {"model": model, "prompt": text}


def parse_embed_response(data: dict) -> list[float]:
    emb = data.get("embedding")
    if not isinstance(emb, list) or not emb:
        raise EmbeddingError(data.get("error") or "no embedding in response")
    return [float(x) for x in emb]


class OllamaEmbedder:
    def __init__(self, model: str = "nomic-embed-text",
                 base_url: str = "http://127.0.0.1:11434/api/embeddings",
                 timeout: int = 120):
        self.model = model
        self.base_url = base_url
        self.timeout = timeout

    def embed(self, text: str) -> list[float]:
        req = urllib.request.Request(
            self.base_url, data=json.dumps(build_embed_payload(self.model, text)).encode(),
            headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read())
        except urllib.error.URLError as e:
            raise EmbeddingError(f"embeddings request failed ({self.base_url}): {e}. "
                                 "Run `ollama serve` with an embedding model pulled.") from e
        return parse_embed_response(data)


class SemanticKnowledgeBase:
    """Same retrieve() shape as the BM25 KnowledgeBase, ranked by cosine over
    cached record vectors."""

    def __init__(self, records: list[Record], vectors: dict[str, list[float]], embedder):
        self.records = records
        self.vectors = vectors
        self.embedder = embedder

    def retrieve(self, query: str, k: int = 3, vuln_class: str | None = None) -> list[Hit]:
        q = self.embedder.embed(query)
        if vuln_class:
            vc = vuln_class.lower()
            pool = [r for r in self.records if r.vuln_class == vc] or self.records
        else:
            pool = self.records
        scored = [(cosine(q, self.vectors.get(r.id, [])), r) for r in pool]
        scored = [(s, r) for s, r in scored if s > 0] or [(0.0, r) for r in pool]
        scored.sort(key=lambda x: (-x[0], x[1].id))
        return [Hit(r, round(s, 4)) for s, r in scored[:k]]


def build_cache(records: list[Record], embedder, path: Path) -> int:
    """Embed every record and write a cache file. Returns count embedded."""
    vectors = {}
    for r in records:
        vectors[r.id] = embedder.embed(r.blob())
        time.sleep(0)  # yield; embedding calls are the slow part
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"model": getattr(embedder, "model", "?"),
                                "vectors": vectors}), encoding="utf-8")
    return len(vectors)


def load_cache(path: Path) -> tuple[str, dict[str, list[float]]]:
    """Return (model, {id: vector}); ('', {}) if no/invalid cache."""
    if not path.is_file():
        return "", {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return str(data.get("model", "")), {k: [float(x) for x in v]
                                            for k, v in (data.get("vectors") or {}).items()}
    except (json.JSONDecodeError, ValueError, TypeError):
        return "", {}


def load_semantic_kb(corpus: Path, cache: Path, embedder) -> SemanticKnowledgeBase | None:
    """Build a SemanticKnowledgeBase if a usable cache exists, else None (caller
    falls back to BM25)."""
    _model, vectors = load_cache(cache)
    if not vectors:
        return None
    records = KnowledgeBase.load(corpus).records
    if not any(r.id in vectors for r in records):
        return None
    return SemanticKnowledgeBase(records, vectors, embedder)
