"""Ingest = protect BEFORE anything else touches the data.

Structured PII fields are tokenized by name; the free-text body is scanned for
PII and tokenized in place. The `text` we hand to the embedder is category +
protected body: topic words (billing, login, refund) survive so retrieval still
works, while every name/email/SSN/phone/card is already a token.
"""
from __future__ import annotations
import json

from .pii import tokenize_text

PII_FIELDS = {"name", "email", "ssn", "phone", "dob", "address"}


def protect_record(rec: dict, protector) -> dict:
    out: dict = {}
    for k, v in rec.items():
        if k in PII_FIELDS and isinstance(v, str):
            out[k] = protector.protect(v)
        elif k == "body" and isinstance(v, str):
            out[k] = tokenize_text(v, protector)
        else:
            out[k] = v  # non-PII passthrough (id, category, priority, created...)
    # Retrievable text = category + protected customer handle + protected body.
    # Topic words survive (retrieval works); every identifier is already a token.
    out["text"] = (
        f"[{out.get('category', 'general')}] customer {out.get('name', '?')}: "
        f"{out.get('body', '')}"
    )
    return out


def load_and_protect(path: str, protector) -> list[dict]:
    with open(path) as f:
        records = json.load(f)
    return [protect_record(r, protector) for r in records]
