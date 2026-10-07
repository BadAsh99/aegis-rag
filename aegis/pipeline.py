"""AEGIS orchestrator: ingest -> embed/store -> retrieve -> prompt -> LLM -> reveal.

Everything from ingest through the LLM handles ONLY tokens (as far as the PII
detector can see: the user's question is tokenized before it enters the prompt
too). Detokenization happens exactly once, at the very end, gated by policy, and
it runs through the Protector so token *recognition* is never hardcoded to one
backend's format.

Every answer carries a DERIVED taint flag: if any retrieved record is untrusted
content (default: all of it, tickets are customer-written), the turn is tainted.
Trust is set by the operator at ingest (`ingest(..., trusted=True)`); a record
cannot mark itself trusted. The pipeline keeps each turn's taint and scope
internally, keyed by turn id; `act()` reads them from there, not from the result
dict, so editing the returned result cannot clear taint. (`ActionGate.check` is
the policy primitive; code that calls it directly is bypassing the pipeline.)

Retrieval is hybrid:
  - exact identifier match: the query's PII is tokenized with the SAME
    deterministic protector, so "find the ticket from Jordan Rivera" resolves
    Rivera -> the same token the store holds, and matches exactly. This is a
    uniquely tokenization-native capability (you can search on protected values
    precisely *because* they're deterministic), not despite protection.
  - semantic match: the tokenized query is embedded for topic retrieval.
"""
from __future__ import annotations

import uuid

from . import config
from .action_gate import Action, ActionGate, Decision
from .ingest import load_and_protect, protect_records
from .llm import get_llm
from .policy import Principal, is_authorized
from .protection import get_protector
from .vectorstore import VectorStore, get_embedder

PROMPT_TEMPLATE = (
    "You are a support assistant. Answer using ONLY the context below. "
    "Identifiers appear as tokens (opaque handles), never invent the real value.\n\n"
    "QUESTION: {q}\n\nCONTEXT:\n{ctx}\n"
)


class Aegis:
    def __init__(self, protector=None, embedder=None, llm=None):
        self.protector = protector or get_protector(config.PROTECTOR)
        self.embedder = embedder or get_embedder(config.EMBEDDER, config.MINILM_MODEL)
        self.store = VectorStore(self.embedder)
        self.llm = llm or get_llm(config.LLM_PROVIDER, config.LLM_MODEL)
        self._turns: dict[str, tuple[bool, object]] = {}  # turn_id -> (tainted, scope)

    def ingest(self, path: str | None = None, *, trusted: bool = False) -> list[dict]:
        docs = load_and_protect(path or config.DATA_PATH, self.protector)
        return self._add(docs, trusted)

    def ingest_records(self, records: list[dict], *, trusted: bool = False) -> list[dict]:
        docs = protect_records(records, self.protector)
        return self._add(docs, trusted)

    def _add(self, docs, trusted: bool):
        for d in docs:
            d["_trusted"] = trusted is True   # operator-assigned, never from the record
        self.store.add(docs)
        return docs

    def retrieve(self, question: str, k: int):
        from .pii import find_pii

        # Tokenize any PII in the query with the same protector (deterministic).
        protected_q = self.protector.protect_freetext(question)
        q_tokens = self.protector.tokens_in(protected_q)
        # FAIR BASELINE: a plaintext store can exact-match the raw identifier, so
        # give every protector its own exact-match key, tokens for tokenizing
        # backends, raw spans for naive. (Without this, naive is handicapped and
        # the identifier-recall comparison is rigged; the audit flagged that.)
        raw_ids = {span for _label, span in find_pii(question)}
        keys = set(q_tokens) | raw_ids

        exact, seen = [], set()
        if keys:
            for d in self.store.docs:
                if id(d) in seen:
                    continue
                if any(key in d["text"] for key in keys):
                    exact.append((d, 1.0))
                    seen.add(id(d))

        semantic = [(d, s) for d, s in self.store.search(protected_q, k) if id(d) not in seen]
        return (exact + semantic)[:k]

    def build_prompt(self, question: str, hits) -> str:
        ctx = "\n".join(f"- ({s:.2f}) {d['text']}" for d, s in hits)
        return PROMPT_TEMPLATE.format(q=question, ctx=ctx)

    def answer(self, question: str, principal: Principal, k: int | None = None) -> dict:
        hits = self.retrieve(question, k or config.TOP_K)
        protected_q = self.protector.protect_freetext(question)
        prompt = self.build_prompt(protected_q, hits)  # tokens only, question included
        llm_answer = self.llm.complete(prompt)         # model sees tokens only
        scope = principal.reveal_scope                 # role+purpose gated, then SCOPE-bound
        tainted = any(d.get("_trusted") is not True for d, _ in hits)
        turn_id = uuid.uuid4().hex
        self._turns[turn_id] = (tainted, scope)
        return {
            "turn_id": turn_id,
            "question": question,
            "prompt": prompt,
            "llm_answer": llm_answer,
            "authorized": is_authorized(principal),
            "scope": scope,       # informational copies; act() uses the internal record
            "tainted": tainted,
            # detokenize ONLY tokens this caller is scoped to; the rest stay tokens.
            # Runs through the protector -> no hardcoded token format, and the same
            # gate fires the honeytoken tripwire + writes the reveal ledger.
            "final_answer": self.protector.reveal(llm_answer, scope=scope, purpose=principal.purpose),
            "hits": hits,
        }

    def act(self, result: dict, action: Action, gate: ActionGate) -> Decision:
        """Run an agent-proposed egress through the action-gate, using the taint and
        scope the pipeline recorded for this turn. An unknown turn fails closed
        (tainted, empty scope). The caller only executes if `decision.allowed`."""
        tainted, scope = self._turns.get(result.get("turn_id"), (True, frozenset()))
        return gate.check(action, tainted=tainted, scope=scope)
