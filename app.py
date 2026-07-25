"""AEGIS demo CLI, narrated, offline, no API keys.

    python app.py
    python app.py --q "login problem" --role support_agent
    python app.py --q "billing refund" --role anonymous     # denied detokenization

Runs on MockProtector + MockLLM by default. Swap to real backends via the env
flags in .env.example (AEGIS_PROTECTOR=protegrity, AEGIS_LLM=anthropic, ...).
"""
import argparse

from aegis.pipeline import Aegis
from aegis.policy import Principal

RULE = "=" * 72


def banner(title):
    print("\n" + RULE)
    print(title)
    print(RULE)


def show_attacker_view(aegis, n=3):
    banner("🔓  ATTACKER VIEW, exfiltrate the whole vector store, you get:")
    for d in aegis.store.dump()[:n]:
        print(f"  id={d.get('id'):<9} name={d.get('name')}")
        print(f"     text: {d['text'][:110]}")
    print("\n  Every name / email / SSN / phone above is a  tok:…  handle.")
    print("  The store, the embeddings, and the index hold ZERO raw PII.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--q", default="customer with a billing or refund complaint")
    ap.add_argument("--role", default="support_agent")
    ap.add_argument("--purpose", default="authorized_response")
    args = ap.parse_args()

    aegis = Aegis()
    docs = aegis.ingest()
    print(f"\nIngested + protected {len(docs)} records "
          f"(protector={aegis.protector.__class__.__name__}, "
          f"llm={aegis.llm.name}).")

    show_attacker_view(aegis)

    # 1) What the LLM actually receives, tokens only.
    res = aegis.answer(args.q, Principal(role="anonymous", purpose="none"))
    banner("🤖  PROMPT SENT TO THE LLM  (tokens only, a prompt-log leak = tokens):")
    print(res["prompt"])

    # 2) Unauthorized caller: answer stays tokenized.
    banner("⛔  UNAUTHORIZED caller, answer stays tokenized:")
    print(res["final_answer"])

    # 3) Authorized caller: policy-gated detokenization at the very end.
    auth = aegis.answer(args.q, Principal(role=args.role, purpose=args.purpose))
    banner(f"✅  AUTHORIZED caller ({args.role} / {args.purpose}), detokenized:")
    print(auth["final_answer"])
    print("\n" + RULE)
    print("The ONLY place raw PII appeared was the final line, for an authorized")
    print("caller, after an explicit policy check. Everywhere else: tokens.")
    print(RULE + "\n")


if __name__ == "__main__":
    main()
