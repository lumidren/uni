"""A tiny, dependency-free TF-IDF retriever — the RAG backbone.

A full vector DB (Chroma/FAISS + an embedding model) is overkill for a demo and
pulls in heavy dependencies. Instead we implement TF-IDF vectors + cosine
similarity in pure Python. It is a legitimate retrieval model: documents and
queries become sparse term vectors, and similarity ranks matches. Swapping in
dense embeddings later is a drop-in replacement behind the same interface.

Crucially, retrieval here is a *candidate generator*. The mapping engine then
demands structural evidence (shared control tags, obligation type) before it
claims equivalence — so we never rely on textual similarity alone.
"""
from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field

_WORD = re.compile(r"[a-z0-9]+")
_STOP = {
    "the", "a", "an", "and", "or", "of", "to", "in", "for", "on", "with", "shall",
    "must", "be", "is", "are", "that", "this", "as", "by", "at", "from", "which",
    "any", "all", "its", "their", "such", "may", "will", "has", "have", "data",
}


def tokenize(text: str) -> list[str]:
    return [w for w in _WORD.findall(text.lower()) if w not in _STOP and len(w) > 2]


@dataclass
class TfidfIndex:
    corpus_ids: list[str] = field(default_factory=list)
    _docs: dict[str, Counter] = field(default_factory=dict)
    _idf: dict[str, float] = field(default_factory=dict)

    def fit(self, documents: dict[str, str]) -> "TfidfIndex":
        self.corpus_ids = list(documents.keys())
        self._docs = {doc_id: Counter(tokenize(text)) for doc_id, text in documents.items()}
        n = len(documents) or 1
        df: Counter = Counter()
        for tf in self._docs.values():
            df.update(tf.keys())
        self._idf = {term: math.log((1 + n) / (1 + d)) + 1.0 for term, d in df.items()}
        return self

    def _vector(self, tokens: Counter) -> dict[str, float]:
        vec = {}
        total = sum(tokens.values()) or 1
        for term, count in tokens.items():
            idf = self._idf.get(term)
            if idf:
                vec[term] = (count / total) * idf
        return vec

    @staticmethod
    def _cosine(a: dict[str, float], b: dict[str, float]) -> float:
        if not a or not b:
            return 0.0
        common = set(a) & set(b)
        dot = sum(a[t] * b[t] for t in common)
        na = math.sqrt(sum(v * v for v in a.values()))
        nb = math.sqrt(sum(v * v for v in b.values()))
        return dot / (na * nb) if na and nb else 0.0

    def query(self, text: str, top_k: int = 5) -> list[tuple[str, float]]:
        qv = self._vector(Counter(tokenize(text)))
        scored = []
        for doc_id in self.corpus_ids:
            dv = self._vector(self._docs[doc_id])
            scored.append((doc_id, self._cosine(qv, dv)))
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_k]

    def shared_terms(self, text_a: str, text_b: str, top: int = 6) -> list[str]:
        """Terms that drive a match — used as human-readable mapping evidence."""
        ta, tb = Counter(tokenize(text_a)), Counter(tokenize(text_b))
        common = set(ta) & set(tb)
        ranked = sorted(common, key=lambda t: self._idf.get(t, 0.0), reverse=True)
        return ranked[:top]
