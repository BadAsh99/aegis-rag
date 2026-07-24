"""Embedding + an in-memory cosine vector store.

Critical property: the store only ever holds PROTECTED text. Exfiltrate the
whole thing (see `dump()`) and you get tokens, not people.

Default embedder is dependency-free (numpy only) so the repo runs tonight. Set
AEGIS_EMBEDDER=minilm for real sentence-transformers semantics in the submission.
"""
from __future__ import annotations
import hashlib
import numpy as np


class HashEmbedder:
    """Deterministic bag-of-hashed-tokens embedder. Zero heavy deps."""

    def __init__(self, dim: int = 256):
        self.dim = dim

    def encode(self, texts):
        texts = list(texts)
        vecs = np.zeros((len(texts), self.dim), dtype=np.float32)
        for i, t in enumerate(texts):
            for tok in str(t).lower().split():
                h = int(hashlib.md5(tok.encode()).hexdigest(), 16)
                vecs[i, h % self.dim] += 1.0
        norms = np.linalg.norm(vecs, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return vecs / norms


class MiniLMEmbedder:
    """Real semantic embeddings via sentence-transformers (optional dependency)."""

    def __init__(self, model_name: str):
        from sentence_transformers import SentenceTransformer  # noqa: local import

        self.model = SentenceTransformer(model_name)

    def encode(self, texts):
        return self.model.encode(list(texts), normalize_embeddings=True)


def get_embedder(kind: str, model_name: str):
    if (kind or "hash").lower() == "minilm":
        return MiniLMEmbedder(model_name)
    return HashEmbedder()


class VectorStore:
    def __init__(self, embedder, text_key: str = "text"):
        self.embedder = embedder
        self.text_key = text_key
        self.docs: list[dict] = []
        self.vecs = None

    def add(self, docs):
        texts = [d[self.text_key] for d in docs]
        v = np.asarray(self.embedder.encode(texts), dtype=np.float32)
        self.vecs = v if self.vecs is None else np.vstack([self.vecs, v])
        self.docs.extend(docs)

    def search(self, query: str, k: int = 3):
        q = np.asarray(self.embedder.encode([query]), dtype=np.float32)[0]
        sims = self.vecs @ q
        idx = np.argsort(-sims)[:k]
        return [(self.docs[i], float(sims[i])) for i in idx]

    def dump(self) -> list[dict]:
        """Exactly what an attacker gets if they exfiltrate the store."""
        return self.docs
