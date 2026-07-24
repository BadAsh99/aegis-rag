"""AEGIS orchestrator: ingest -> embed/store -> retrieve -> prompt -> LLM -> reveal.

Everything from ingest through the LLM handles ONLY tokens. Detokenization
happens exactly once, at the very end, gated by policy — and it runs through the
Protector so token *recognition* is never hardcoded to one backend's format.

Retrieval is hybrid:
  - exact identifier match: the query's PII is tokenized with the SAME
    deterministic protector, so "find the ticket from Jordan Rivera" resolves
    Rivera -> the same token the store holds, and matches exactly. This is a
    uniquely tokenization-native capability (you can search on protected values
    precisely *because* they're deterministic), not despite protection.
  - semantic match: the tokenized query is embedded for topic retrieval.
"""
from __future__ import annotations

from . import config
from .ingest import load_and_protect, protect_records
from .llm import get_llm
from .policy import Principal, is_authorized
from .protection import get_protector
from .vectorstore import VectorStore, get_embedder

PROMPT_TEMPLATE = (
    "You are a support assistant. Answer using ONLY the context below. "
    "Identifiers appear as tokens (opaque handles) — never invent the real value.\n\n"
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

    def ingest_records(self, records: list[dict]) -> list[dict]:
        docs = protect_records(records, self.protector)
        self.store.add(docs)
        return docs

    def retrieve(self, question: str, k: int):
        # Tokenize any PII in the query with the same protector (deterministic).
        protected_q = self.protector.protect_freetext(question)
        q_tokens = self.protector.tokens_in(protected_q)

        exact, seen = [], set()
        if q_tokens:
            for d in self.store.docs:
                if id(d) in seen:
                    continue
                if any(t in d["text"] for t in q_tokens):
                    exact.append((d, 1.0))
                    seen.add(id(d))

        semantic = [(d, s) for d, s in self.store.search(protected_q, k) if id(d) not in seen]
        return (exact + semantic)[:k]

    def build_prompt(self, question: str, hits) -> str:
        ctx = "\n".join(f"- ({s:.2f}) {d['text']}" for d, s in hits)
        return PROMPT_TEMPLATE.format(q=question, ctx=ctx)

    def answer(self, question: str, principal: Principal, k: int | None = None) -> dict:
        hits = self.retrieve(question, k or config.TOP_K)
        prompt = self.build_prompt(question, hits)   # tokens only
        llm_answer = self.llm.complete(prompt)         # model sees tokens only
        authorized = is_authorized(principal)
        return {
            "question": question,
            "prompt": prompt,
            "llm_answer": llm_answer,
            "authorized": authorized,
            # detokenization goes through the protector -> no hardcoded token format
            "final_answer": self.protector.reveal(llm_answer, authorized=authorized),
            "hits": hits,
        }
