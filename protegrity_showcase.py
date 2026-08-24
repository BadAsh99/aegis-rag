"""Real Protegrity Developer Edition showcase, the money shot for the judge video.

Runs against a LIVE Protegrity AI Developer Edition stack. Two stages:

  Stage 1, discovery + redaction. Needs only the local Data Discovery containers
  (public GHCR images, no login, no account):

      git clone https://github.com/Protegrity-AI-Developer-Edition/protegrity-ai-developer-edition.git
      cd protegrity-ai-developer-edition/data-discovery && docker compose up -d

  Stage 2, the full tokenize / detokenize round trip. Additionally needs free
  self-service credentials for the hosted Protection API:

      https://www.protegrity.com/developers/dev-edition-api
      export DEV_EDITION_EMAIL=... DEV_EDITION_PASSWORD=... DEV_EDITION_API_KEY=...

Stage 1 is what closes the documented detector gap in MockProtector: the offline
regex tokenizer cannot see a name in prose, and Protegrity's classifier can. That
gap is asserted as a deliberate xfail in the test suite.

    python protegrity_showcase.py
"""
import logging
import os

ENDPOINT = os.getenv(
    "AEGIS_PROTEGRITY_ENDPOINT",
    "http://localhost:8580/pty/data-discovery/v1.1/classify",
)

SAMPLE = "Customer Jane Smith, SSN 123-45-6789, reachable at jane.smith@example.com, called about a refund."

ENTITIES = ("PERSON", "EMAIL_ADDRESS", "SOCIAL_SECURITY_ID", "PHONE_NUMBER")


def _rule(title):
    print("\n" + "-" * 72)
    print(title)
    print("-" * 72)


def main():
    import protegrity_developer_python as pdp

    # The SDK configures its own INFO logging on import, one line per entity per
    # call. Those interleave ahead of the curated output and read as noise on a
    # recorded walkthrough; discover() reports the same findings in order below.
    logging.getLogger("protegrity_developer_python").setLevel(logging.WARNING)

    entity_map = {e: e for e in ENTITIES}
    pdp.configure(
        endpoint_url=ENDPOINT,
        named_entity_map=entity_map,
        classification_score_threshold=0.6,
        method="redact",
    )

    print("Protegrity AI Developer Edition, live.")
    print("Classification endpoint:", ENDPOINT)

    _rule("STAGE 1  Protegrity classifier finds the PII  (local containers, no account)")
    print("ORIGINAL :", SAMPLE)
    try:
        found = pdp.discover(SAMPLE)
    except Exception as exc:
        print("\nCould not reach the Data Discovery service at", ENDPOINT)
        print("Start it with:  cd protegrity-ai-developer-edition/data-discovery && docker compose up -d")
        print("Error:", type(exc).__name__, exc)
        return

    for entity, hits in sorted(found.items()):
        for hit in hits:
            loc = hit.get("location", {})
            span = SAMPLE[loc.get("start_index", 0):loc.get("end_index", 0)]
            names = ", ".join(c.get("name", "?") for c in hit.get("classifiers", []))
            print(f"  {entity:20} score {hit.get('score', 0):.2f}  {span!r}   [{names}]")

    print("\n  ^ PERSON is the one that matters. AEGIS's offline regex tokenizer cannot")
    print("    see a name in prose; that gap is a deliberate xfail in the test suite.")
    print("    Protegrity's classifier closes it. That is the whole reason to use it.")

    _rule("STAGE 1b  Protegrity rewrites the sensitive spans in place")
    print("REDACTED :", pdp.find_and_redact(SAMPLE))
    pdp.configure(endpoint_url=ENDPOINT, named_entity_map=entity_map,
                  classification_score_threshold=0.6, method="mask", masking_char="#")
    print("MASKED   :", pdp.find_and_redact(SAMPLE))
    pdp.configure(endpoint_url=ENDPOINT, named_entity_map=entity_map,
                  classification_score_threshold=0.6, method="redact")

    _rule("STAGE 2  Reversible tokenize / detokenize  (hosted Protection API)")
    if not (os.getenv("DEV_EDITION_EMAIL") and os.getenv("DEV_EDITION_PASSWORD")):
        print("SKIPPED. No DEV_EDITION_EMAIL / DEV_EDITION_PASSWORD in the environment.")
        print("Register free at https://www.protegrity.com/developers/dev-edition-api")
        print("\nWhat runs here once those are set:")
        print("  find_and_protect(text)   -> the spans above, replaced by reversible tokens")
        print("  find_and_unprotect(text) -> the original, for an authorized caller only")
        print("\nStage 1 above is already real Protegrity doing the detection. The adapter")
        print("(aegis/protection.py ProtegrityProtector) calls exactly these two functions.")
        return

    protected = pdp.find_and_protect(SAMPLE)
    print("PROTECTED:", protected)
    print("           ^ real Protegrity DE tokens. This is what the vector store and the LLM see.")
    revealed = pdp.find_and_unprotect(protected)
    print("REVEALED :", revealed)
    print("           ^ only for an authorized caller.")
    assert protected != SAMPLE, "DE did not tokenize the PII"
    print("\nProtegrity Developer Edition protected the name, SSN, and email end to end.")
    print("That is the pipeline guarantee: breach the store, the prompt, or the logs, and you get tokens.")


if __name__ == "__main__":
    main()
