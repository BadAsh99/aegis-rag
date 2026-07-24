# AEGIS — assume the prompt injection wins

> **The injection succeeded. The attacker got tokens, not people.**
>
> A RAG pipeline built on the premise that prompt injection *will* succeed — so when an attacker exfiltrates from the vector store or hijacks the LLM, they steal Protegrity tokens, not names / SSNs / PHI. Real values resolve only for an authenticated, authorized caller.
>
> 2026 Protegrity AI Pipeline Security Hackathon · track: *Architect AI Without Exposure* · handle: **BadAsh99**

<!-- MONEY-SHOT GIF GOES HERE (record `python attack_demo.py`, cut to a GIF, drop it above this line).
     Split-screen, same injection payload: LEFT naive RAG leaks real people; RIGHT AEGIS leaks tokens. -->

```text
💉  BREACH 2 — indirect prompt injection (the injection succeeds in BOTH)
    ATTACKER'S EXFIL CHANNEL:
      NAIVE  →  phones: ['312-555-0125', '480-555-0193']   emails: ['m.webb@example.com']   ← REAL PEOPLE
      AEGIS  →  phones: —   emails: —                                                        ← nothing but tokens
```

---

## The threat this defends against

- **EchoLeak (CVE-2025-32711)** — the first zero-click data-exfil from M365 Copilot (CVSS 9.3). Injection arrives in retrieved content; the model exfiltrates. Not theory.
- **OWASP LLM08:2025 — Vector & Embedding Weaknesses** — a *new* 2025 category naming embedding-inversion and cross-tenant leakage. AEGIS maps to it 1:1.
- **OWASP LLM02 — Sensitive Information Disclosure.**

The credible field has already conceded the input layer: Simon Willison's *lethal trifecta*, Google DeepMind's *CaMeL* ("defeating prompt injection **by design**"). You can't reliably detect intent at the prompt. **So AEGIS doesn't try.** It gates the data.

## The move — gate the data, not the prompt

```text
raw record ─▶ protect() ─▶ embed ─▶ vector store ─▶ retrieve ─▶ LLM prompt ─▶ answer ─▶ reveal() ─▶ user
            (Protegrity)             (tokens)                    (tokens)      (tokens)   ▲ authorized only
```

Ingest is the first thing to touch the data; detokenization is the last, and only for a caller that passes policy. Between them, the vector DB, the embeddings, and the LLM handle **only tokens**. Win the prompt, steal the store, dump the logs — the loot is worthless.

## Run the attack yourself (offline, no API keys)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python attack_demo.py   # split-screen: naive leaks people, AEGIS leaks tokens (same injection)
python benchmark.py     # the privacy/utility table + a live re-identification attack
pytest -q               # the security assertions (incl. one HONEST xfail — see below)
```

Runs on a deterministic offline `MockProtector` + `MockLLM`. Real backends are env flags (`.env.example`).

## The numbers (measured, not claimed) — `python benchmark.py`

| strategy | topic recall | **identifier recall** | store leak | exfil leak | **authorized reveal** | **re-id attack** |
|---|---|---|---|---|---|---|
| none (naive) | 1.00 | 0.50 | 1.00 | 1.00 | 1.00 | 0.83 |
| mask `[REDACTED]` | 1.00 | 0.50 | 0.00 | 0.00 | **0.00** | 0.17 |
| **tokenize (AEGIS)** | 1.00 | **1.00** | **0.00** | **0.00** | **1.00** | **0.17** |

AEGIS is the only row that's good in every column: **zero leakage, identifier lookup works, authorized callers still resolve, and the re-identification attack drops to chance.** Masking buys privacy by destroying utility (lookup dies, the value is gone forever). Naive keeps utility but its embeddings re-identify people 83% of the time. **Same privacy as masking, the utility of plaintext.**

## What this is NOT (the honesty box)

- **Not** a prompt-injection *preventer*. The injection still succeeds — AEGIS makes the loot worthless.
- **Not** novel tokenization. The pattern is productized (Skyflow LLM Privacy Vault) and open-source (Microsoft Presidio). What's original here is the **adversarial proof + the authorized-reveal gate + the honest measurement**, not the architecture.
- **Not** "never exposed." Free-text PII protection = **detector recall**: regex under the mock (misses names in prose — see the `xfail` in `tests/`), real NER under Protegrity (`find_and_protect` catches PERSON). We *measure* the gap; we don't hide it.
- **Not** air-gapped. Protegrity's tokenization crypto is a hosted API call (rate-limited); the discovery/guardrail pieces run local.

## Where this sits (prior art — cited on purpose)

- **Control-flow defenses** (DeepMind CaMeL, the Dual-LLM pattern, the lethal trifecta) gate *what the agent is allowed to do*. AEGIS is the **data-layer complement**: it gates *what the data is worth if stolen*. They stop the action; this neutralizes the loot.
- **Tokenization for AI** (Skyflow, Presidio, Protegrity) is the established pattern. AEGIS is a concrete, benchmarked, *attacked* instance — and the pattern is vendor-agnostic; Protegrity is one implementation.

## The Protegrity swap (one class)

The pipeline is identical on the mock or on real Protegrity Developer Edition — only `aegis/protection.py`'s `ProtegrityProtector` changes, plus env flags:

| | offline (today) | real (submission) |
|---|---|---|
| protection | `MockProtector` (regex) | `ProtegrityProtector` → `find_and_protect` (PERSON NER) + `appython` structured + RBAC |
| flag | `AEGIS_PROTECTOR=mock` | `AEGIS_PROTECTOR=protegrity` |

The `ProtegrityProtector` is written against the published API (`protegrity-developer-python`), ready to activate the moment DE access lands — and its NER closes the name-recall gap automatically.

## Structure

```
aegis/
  protection.py   Protector interface · Naive / Mask / Mock / Protegrity backends (the swap point)
  pii.py          regex PII detection (mock free-text path; real path = Protegrity NER)
  ingest.py       protect BEFORE anything touches the data
  vectorstore.py  embedder + in-memory cosine store (protected text only)
  llm.py          provider-agnostic (mock | openai | anthropic) — only ever sees tokens
  policy.py       authorization for detokenization (stand-in for Protegrity's policy engine)
  pipeline.py     orchestrator + query-side tokenization (identifier lookup on protected data)
app.py            narrated demo
attack_demo.py    the money-shot: same injection, naive vs AEGIS
benchmark.py      the privacy/utility table + a runnable re-identification attack
tests/            the security assertions, with an independent oracle
```

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for the threat model, the per-layer attack table, and the OWASP LLM08/LLM02 mapping.

---

*Built by Ash Clements (BadAsh99). Companion to AISeal (OWASP LLM Top 10 scanner) and Gray Swan red-team work — I break models, then build the layer that makes the breaks worthless.*
