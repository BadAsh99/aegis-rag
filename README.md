# AEGIS — a RAG pipeline where sensitive data is never exposed in raw form

> **2026 Protegrity AI Pipeline Security Hackathon** · track: *Architect AI without exposure* · handle: **BadAsh99**

Most "secure AI" stories defend the prompt. AEGIS defends the **data**. Sensitive
values are tokenized on ingest with **Protegrity Developer Edition**, stay
protected through embedding, vector storage, retrieval, and LLM inference, and
are detokenized **only** for a policy-authorized caller, at the very end.

**Breach the vector store, or dump the prompt logs, and you get tokens — not people.**

```
raw record ──▶ protect() ──▶ embed ──▶ vector store ──▶ retrieve ──▶ LLM prompt ──▶ LLM answer ──▶ unprotect() ──▶ user
             (Protegrity)                (tokens)                     (tokens)         (tokens)      ▲ policy-gated
                                                                                                     └ authorized callers only
```

Everything from ingest through the model handles **only tokens**. There is exactly
one detokenization point, and it is gated by policy.

---

## Quickstart (runs offline in ~30 seconds, no API keys)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py          # narrated demo
pytest -q              # the security assertions
```

Defaults use a **MockProtector** (deterministic, offline stand-in for Protegrity
Developer Edition) and a **MockLLM** (no key), so the whole pipeline is runnable
today. Swapping in the real backends is a set of env flags — see
[`.env.example`](.env.example).

## What the demo shows

`python app.py` walks through, on synthetic support-ticket data:

1. **Attacker view** — the entire vector store dumped: every name / email / SSN /
   phone is a `tok:…` handle. Zero raw PII at rest.
2. **The LLM prompt** — tokens only. A prompt-log leak exposes tokens.
3. **Unauthorized caller** — the answer stays tokenized.
4. **Authorized caller** (role + purpose pass policy) — detokenized output, and
   *only here* does raw PII appear.

## The security property, as a test

`tests/test_no_raw_leak.py` asserts the whole point automatically:

- no raw PII in the vector store
- no raw PII in the LLM prompt
- an unauthorized caller never receives raw PII
- an authorized caller *can* detokenize

```
$ pytest -q
....                                                4 passed
```

## How this maps to Protegrity Developer Edition

The pipeline is identical whether it runs on the mock or the real backend — only
the `Protector` implementation changes:

| Today (offline)                    | Submission (real)                                   |
|------------------------------------|-----------------------------------------------------|
| `MockProtector` (deterministic)    | `ProtegrityProtector` → Developer Edition `protect()` / `unprotect()` |
| local vault map                    | Protegrity protected store + **policy engine**      |
| `AEGIS_PROTECTOR=mock`             | `AEGIS_PROTECTOR=protegrity`                         |

The swap point is one class in [`aegis/protection.py`](aegis/protection.py)
(`ProtegrityProtector`, with the expected `protect`/`unprotect` shape and TODOs).
In production, prefer Protegrity's own policy engine to enforce `unprotect`
authorization — the demo's [`policy.py`](aegis/policy.py) is the stand-in.

## Project structure

```
aegis/
  protection.py   Protector interface · MockProtector · ProtegrityProtector (swap point)
  pii.py          detect + tokenize PII hiding in free text
  ingest.py       protect records BEFORE anything else touches them
  vectorstore.py  embedder (hash | minilm) + in-memory cosine store (protected text only)
  llm.py          provider-agnostic (mock | openai | anthropic) — only ever sees tokens
  policy.py       authorization for detokenization (stand-in for Protegrity policy)
  pipeline.py     orchestrator: ingest → embed → retrieve → prompt → LLM → reveal
app.py            narrated demo CLI
data/             synthetic PII records
tests/            the "no raw leak" security assertions
```

## Upgrades toward the final submission

- **Real embeddings:** `AEGIS_EMBEDDER=minilm` (sentence-transformers all-MiniLM-L6-v2).
- **Real LLM:** `AEGIS_LLM=anthropic` (or `openai`) + a key.
- **Real protection:** implement `ProtegrityProtector` + `AEGIS_PROTECTOR=protegrity` once Developer Edition access lands.
- **Record** the 10–15 min demo — outline in [`DEMO_SCRIPT.md`](DEMO_SCRIPT.md).

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the data-flow diagram, threat model,
and OWASP LLM Top 10 mapping.

---

*Built by Ash Clements (BadAsh99). AISeal (OWASP LLM Top 10 scanner) and
badash-killchain (agent/RAG trust-boundary research) inform the threat model.*
