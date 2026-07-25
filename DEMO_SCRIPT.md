# AEGIS, 10–15 min demo script

Record last, once real Protegrity + a real LLM are wired. One clean take. Screen
+ voice. Keep the terminal font large.

## 0:00, The problem (60s)
> "Everyone's securing the *prompt*. But the data leaks somewhere else, the
> vector store, the embeddings, the prompt logs, the model provider. Redaction
> breaks retrieval and misses cases. So I built a RAG pipeline where sensitive
> data is **never exposed in raw form**, using Protegrity Developer Edition."

State the thesis once: *gate the data, not the prompt.*

## 1:00, The architecture (2 min)
Show `ARCHITECTURE.md` diagram. Walk the flow left to right:
protect on ingest → embed → store → retrieve → prompt → LLM → **one** policy-gated
reveal. Emphasize: the protection boundary wraps everything but the final
authorized output.

## 3:00, Live run: the attacker view (2 min)
`python app.py`. Freeze on the **ATTACKER VIEW** panel.
> "This is the entire vector store. Every name, email, SSN, phone, a `tok:` handle.
> Steal this whole thing and you get tokens, not people."

## 5:00, Live run: the LLM only sees tokens (2 min)
Scroll to the **PROMPT** panel.
> "This is the exact prompt the model receives. Tokens. A prompt-log leak, the
> thing that just burned half the industry, exposes tokens."

## 7:00, Authorization is the only door (2 min)
Show **UNAUTHORIZED** (answer stays tokenized) then **AUTHORIZED** (detokenized).
> "Same pipeline, two callers. Raw PII appears in exactly one place: the final
> answer, for a caller that passed a policy check. Nowhere else, ever."

## 9:00, Prove it, don't claim it (1–2 min)
`pytest -q` → 4 passed.
> "The security property is a test, not a promise: no raw PII in the store, none
> in the prompt, unauthorized callers get nothing, authorized callers can reveal."

## 11:00, Protegrity + close (1–2 min)
Show `aegis/protection.py`, the `ProtegrityProtector` swap point.
> "The pipeline is identical on the mock or on Protegrity Developer Edition, > only this one class changes, `protect()` and `unprotect()`. In production,
> Protegrity's policy engine enforces the reveal. That's the whole idea: make
> the data safe at rest, in flight, and in the model, and let an authorized
> human be the only one who ever sees the real thing."

**Total: ~12 min.** Leave the pytest pass on screen at the end.
