"""RAG layer: retrieve distilled vulnerability knowledge to ground skill prompts.

Pure stdlib (BM25). Corpus is `knowledge/patterns.jsonl`; grows via `ingest`.
"""
from pathlib import Path

from security_agent.rag.retriever import KnowledgeBase, Record, Hit, tokenize
from security_agent.rag.ingest import add_record, ingest_files, format_hits_for_prompt
from security_agent.rag.embeddings import (
    OllamaEmbedder, SemanticKnowledgeBase, EmbeddingError, cosine,
    build_cache, load_cache, load_semantic_kb,
)


def load_knowledge(corpus: Path, mode: str = "bm25", cache: Path | None = None,
                   embedder=None):
    """Return a retriever with a .retrieve(query, k, vuln_class) method.

    mode='semantic' uses cached embeddings + cosine when a usable cache and
    embedder are available; otherwise it transparently falls back to BM25.
    """
    if mode == "semantic" and cache is not None and embedder is not None:
        skb = load_semantic_kb(corpus, cache, embedder)
        if skb is not None:
            return skb, "semantic"
    return KnowledgeBase.load(corpus), "bm25"


__all__ = [
    "KnowledgeBase", "Record", "Hit", "tokenize",
    "add_record", "ingest_files", "format_hits_for_prompt",
    "OllamaEmbedder", "SemanticKnowledgeBase", "EmbeddingError", "cosine",
    "build_cache", "load_cache", "load_semantic_kb", "load_knowledge",
]
