# AEGIS demo, voice narration (word-for-word)

Target 11 to 13 minutes. Read it as written, or feed each section to a TTS voice.
Synced to `demo.sh` (six sections). Advance the script with Enter when your
narration for a section finishes. Delivery notes are in [brackets], do not read them.
Record the FINAL take with `AEGIS_PROTECTOR=protegrity` + the DE endpoint set so
section 6 runs live. No em-dashes on purpose, it reads clean aloud.

---

## Intro [~1:00, over the title banner]

Hi, I'm Ash Clements. This is AEGIS, my entry for the Protegrity AI Pipeline Security Hackathon.

Everyone building AI security right now is trying to harden the prompt, to catch the malicious instruction before the model acts on it. I took the opposite bet. I assumed the prompt injection wins, because the people who study this for a living have basically admitted it can not be reliably stopped at the input. So AEGIS does not defend the prompt. It gates the data. The whole idea is that when the injection succeeds, and it will, the attacker walks away with tokens, not people. Let me show you, and then I'll show you the same thing running on real Protegrity Developer Edition.

---

## Section 1, the attack [~2:00, over attack_demo.py]

[Let the output print, then narrate the four lines.]

This is one indirect prompt injection, a poisoned document that tells the model to dump every customer's name, email, phone, and SSN. I run it against four different callers, and the injection succeeds every single time. The model always emits the context.

Watch what each caller actually gets. On a plaintext pipeline, the attacker gets three real customers. Now the part most designs get wrong. A naive tokenized pipeline that only checks your role also leaks all three, because in a real support tool the agent is authorized, so it detokenizes everything. That is the EchoLeak trap.

AEGIS binds the reveal to scope, not just role. The injected agent only opened one ticket, so it can only unlock that one customer's data. Blast radius goes from three to one. Same injection, same model getting fooled, but the data gate holds.

---

## Section 2, detection [~1:30, over tripwire_demo.py]

[Over the tripwire alert and the ledger.]

The token gate is not just protection, it is a sensor. I seed the store with canary records that no real query should ever touch. The moment someone tries to cash a canary token, the tripwire fires, with the caller's identity, scope, and purpose attached. You are watching an exfiltration attempt in real time, and the decoy value itself never leaks because it is out of scope.

And every real reveal is a hash-chained receipt. That is a tamper-evident audit trail. Watch, I edit one entry, and the chain verification flips to false. So every exposure of a real human value is logged, attributed, and provable. That is your GDPR Article 30 record of processing, for free.

---

## Section 3, the action-gate [~1:15, over action_gate_demo.py]

[Over the deny/allow lines.]

There is one honest residual. A fully compromised, already-authorized session could detokenize its own scope. So I put a second layer at the outbound edge. Even if the session is compromised and holds real data, a least-privilege egress policy denies the send. An untrusted-triggered outbound call, or one to an off-allowlist destination, is blocked. The legitimate in-channel reply goes through.

That is the lethal trifecta closed from both ends. The data gate removes the loot, and the action gate removes the exit. This is the layer my own seventeen years in network and cloud security kept pointing at. You never let one component be its own last line of defense.

---

## Section 4, real model [~1:30, over real_llm_demo.py]

[Over the naive-vs-AEGIS output.]

A mock that echoes its context proves nothing, so here is the same injection through a real Claude. On the naive pipeline, the real model reads the poisoned document and leaks a real customer email. On AEGIS, the same model, the same injection, and the output is a token. It followed the instruction to the letter. There was simply nothing in its context except tokens.

That is the whole point in one line. The guarantee sits upstream of whether the model complies. Jailbreak it or not, it can not exfiltrate data it never received.

---

## Section 5, the numbers [~1:45, over benchmark.py]

[Over the table.]

I do not want you to take my word for any of this, so I measured it, on real semantic embeddings, against a fair baseline. Three strategies, one table.

Look at the re-identification column. On real embeddings, plaintext records link straight back to a person a hundred percent of the time. AEGIS, zero. Masking also gets you to zero leakage, but it destroys utility, identifier lookup dies and the value is gone forever. AEGIS keeps identical topic and identifier retrieval, with zero leakage, and the authorized caller still resolves. Mask's privacy, with plaintext's utility. That is the frontier win, and almost nobody publishes privacy, utility, and attack resistance together like this.

And I left my own honesty in the repo. There is a test that fails on purpose, proving where the offline detector misses names in prose. I measure the gap instead of hiding it. Real Protegrity closes it, which is exactly what you are about to see.

---

## Section 6, real Protegrity Developer Edition [~2:00, over protegrity_showcase.py]

[This is the money section. On the FINAL take, creds are set and this runs live.]

Everything so far ran on an offline stand-in so it works with no keys. Here it is on the real product. This is Protegrity Developer Edition doing the protection.

I take a record with a name, a social security number, and an email. I call find_and_protect, and Protegrity's classifier detects the PII and tokenizes it in place. Those tokens are what my vector store holds and what the model sees. Then find_and_unprotect reveals the original, and only for an authorized caller.

That is Protegrity Developer Edition protecting sensitive data across the whole pipeline. My adapter is a single class. The entire pipeline, the retrieval, the scope-bound reveal, the tripwire, the action gate, none of it changes. I flip one flag from the mock to real Protegrity, and the same guarantees now run on a production data-protection engine.

---

## Close [~1:00, over the final banner]

So that is AEGIS. Gate the data, bind the reveal, gate the action, and turn the token gate into a tripwire. I assumed the injection wins, and built the pipeline that makes winning worthless, on Protegrity Developer Edition.

I break AI models for a living, in red-team competitions, and then I build the defenses that make the breaks pointless. This is that, shipped. The code and the full writeup are at ashclements.dev. Thanks for watching.

---

### Timing cushion
If you land under 10 minutes, slow the delivery and pause a beat on each table and each result. If you run long, the sections you can trim are 2 and 3 (detection and action-gate), keep 1, 4, 5, and 6 full. Section 6 is the one the judges weight most, never rush it.
