"""AEGIS orchestrator: ingest -> embed/store -> retrieve -> prompt -> LLM -> reveal.

Everything from ingest through the LLM handles ONLY tokens. Detokenization
happens exactly once, at the very end, gated by policy.
"""
from __future__ import annotations
import re

from . import config
from .ingest import load_and_protect
from .llm import get_llm
from .policy import Principal, is_authorized
from .protection import get_protector
from .vectorstore import VectorStore, get_embedder

TOKEN_RE = re.compile(r"tok:[0-9a-f]{20}")

PROMPT_TEMPLATE = (
    "You are a support assistant. Answer using ONLY the context below. "
    "Identifiers appear as tokens (e.g. tok:ab12...) — treat each as an opaque "
    "handle and never invent the real value.\n\n"
    "QUESTION: {q}\n\nCONTEXT:\n{ctx}\n"
)


class Aegis:
    def __init__(self, protector=None, embedder=None, llm=None):
        self.protector = protector or get_protector(config.PROTECTOR)
        self.embedder = embedder or get_embedder(config.EMBEDDER, config.MINILM_MODEL)
        self.store = VectorStore(self.embedder)
        self.llm = llm or get_llm(config.LLM_PROVIDER, config.LLM_MODEL)

    def ingest(self, path: str | None = None) -> list[dict]:
        docs = load_and_protect(path or config.DATA_PATH, self.protector)
        self.store.add(docs)
        return docs

    def build_prompt(self, question: str, hits) -> str:
        ctx = "\n".join(f"- ({s:.2f}) {d['text']}" for d, s in hits)
        return PROMPT_TEMPLATE.format(q=question, ctx=ctx)

    def _reveal(self, text: str, authorized: bool) -> str:
        def repl(m):
            try:
                return self.protector.unprotect(m.group(0), authorized=authorized)
            except Exception:
                return m.group(0)  # denial -> stays a token

        return TOKEN_RE.sub(repl, text)

    def answer(self, question: str, principal: Principal, k: int | None = None) -> dict:
        hits = self.store.search(question, k or config.TOP_K)
        prompt = self.build_prompt(question, hits)   # tokens only
        llm_answer = self.llm.complete(prompt)         # model sees tokens only
        authorized = is_authorized(principal)
        return {
            "question": question,
            "prompt": prompt,
            "llm_answer": llm_answer,
            "authorized": authorized,
            "final_answer": self._reveal(llm_answer, authorized),
            "hits": hits,
        }
