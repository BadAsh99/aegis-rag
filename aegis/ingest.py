"""Ingest = protect BEFORE anything else touches the data.

Structured PII fields are tokenized by name with the right data-element; the
free-text body goes through protect_freetext(), which is regex-based under the
mock (misses names, an honest, tested gap) and NER-based under real Protegrity
(find_and_protect catches PERSON). The `text` we embed is category + protected
customer handle + protected body: topic words survive so retrieval works, and
every detected identifier is already a token.
"""
from __future__ import annotations
import json

PII_FIELDS = {"name", "email", "ssn", "phone", "dob", "address"}

# map each field to its Protegrity data-element (ignored by the mock)
FIELD_ELEMENT = {
    "name": "name", "email": "email", "ssn": "ssn",
    "phone": "phone", "dob": "datetime", "address": "address",
}


def protect_record(rec: dict, protector) -> dict:
    owner = rec.get("id")  # every token from this record is stamped with its owner
    out: dict = {}
    for k, v in rec.items():
        if k in PII_FIELDS and isinstance(v, str):
            out[k] = protector.protect(v, data_element=FIELD_ELEMENT.get(k, "text"), owner=owner)
        elif k == "body" and isinstance(v, str):
            out[k] = protector.protect_freetext(v, owner=owner)
        else:
            out[k] = v  # non-PII passthrough (id, category, priority, created...)
    out["text"] = (
        f"[{out.get('category', 'general')}] customer {out.get('name', '?')}: "
        f"{out.get('body', '')}"
    )
    return out


def protect_records(records: list[dict], protector) -> list[dict]:
    return [protect_record(r, protector) for r in records]


def load_and_protect(path: str, protector) -> list[dict]:
    with open(path) as f:
        records = json.load(f)
    return protect_records(records, protector)
