"""Lightweight PII detection for free text.

Structured PII fields are protected by name in ingest.py. But PII also hides in
free-text bodies ("call me at 602-555-0148"). This tokenizes those in place so
even the unstructured text is safe before it ever reaches the embedder.

For production, swap these regexes for Protegrity's classifiers / a proper NER
model, the seam is the same.
"""
import re

EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
PHONE = re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")
CREDIT_CARD = re.compile(r"\b(?:\d[ -]?){13,16}\b")

PATTERNS = [("SSN", SSN), ("CREDIT_CARD", CREDIT_CARD), ("EMAIL", EMAIL), ("PHONE", PHONE)]


def tokenize_text(text: str, protector, owner: str | None = None) -> str:
    """Replace every detected PII span in `text` with a protector token.

    `owner` is the record the text came from, stamped onto each token so reveal
    can be scope-bound (an authorized agent only unlocks its own case's tokens).
    """
    if not text:
        return text
    for label, pat in PATTERNS:
        text = pat.sub(lambda m: protector.protect(m.group(0), data_element=label, owner=owner), text)
    return text


def find_pii(text: str):
    """Return raw PII spans found in `text` (used only by the leak test)."""
    hits = []
    for label, pat in PATTERNS:
        hits.extend((label, m.group(0)) for m in pat.finditer(text or ""))
    return hits
