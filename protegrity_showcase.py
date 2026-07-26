"""Real Protegrity Developer Edition showcase, the money shot for the judge video.

A live round-trip through the real DE SDK: a record with a name, SSN, and email;
find_and_protect() tokenizes the PII in place; those tokens are what the pipeline
stores and the LLM sees; find_and_unprotect() reveals for an authorized caller.
This is the segment that literally shows "Protegrity Developer Edition protects
sensitive data in the pipeline."

Needs the DE endpoint + key: set AEGIS_PROTECTOR=protegrity and
AEGIS_PROTEGRITY_ENDPOINT=<url> (both arrive with the DE "resources" email).
Without them it prints exactly what the segment will show, so the runner still
completes on the mock during rehearsal.

    python protegrity_showcase.py
"""
import os

SAMPLE = "Customer Jane Smith, SSN 123-45-6789, reachable at jane.smith@example.com, called about a refund."


def main():
    ready = os.getenv("AEGIS_PROTECTOR", "").lower() == "protegrity" and os.getenv("AEGIS_PROTEGRITY_ENDPOINT")
    if not ready:
        print("PENDING DEVELOPER EDITION CREDENTIALS.")
        print("When the DE endpoint + key land, set:")
        print("    export AEGIS_PROTECTOR=protegrity")
        print("    export AEGIS_PROTEGRITY_ENDPOINT=<discovery/protection API url>")
        print("and this segment runs a LIVE Protegrity round-trip:\n")
        print("    ORIGINAL :", SAMPLE)
        print("    PROTECTED: Customer tok:..., SSN tok:..., email tok:...   <- real Protegrity DE tokens")
        print("    the vector store and the LLM only ever see those tokens")
        print("    REVEALED : the original, only for an authorized caller\n")
        print("The adapter (aegis/protection.py ProtegrityProtector) is already wired to the")
        print("real SDK v1.1.1 (find_and_protect / find_and_unprotect), so this is one flip away.")
        return

    import protegrity_developer_python as pdp

    pdp.configure(endpoint_url=os.getenv("AEGIS_PROTEGRITY_ENDPOINT"))
    print("Running a live Protegrity Developer Edition round-trip.\n")
    print("ORIGINAL :", SAMPLE)
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
