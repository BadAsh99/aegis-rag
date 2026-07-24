"""The core security assertion, as an automated test.

If any of these fail, the pipeline leaked raw PII somewhere it shouldn't. Run:

    pytest -q          # from the repo root
"""
import json
import os

from aegis.pii import find_pii
from aegis.pipeline import Aegis
from aegis.policy import Principal

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data", "sample_records.json")

with open(DATA) as _f:
    RAW = json.load(_f)


def raw_pii_values():
    """Every raw sensitive value in the source data (structured + in-body)."""
    vals = set()
    for r in RAW:
        for k in ("name", "email", "phone", "ssn"):
            if r.get(k):
                vals.add(r[k])
        for _label, span in find_pii(r.get("body", "")):
            vals.add(span)
    return {v for v in vals if v}


def fresh():
    a = Aegis()
    a.ingest(DATA)
    return a


def test_no_raw_pii_in_vector_store():
    blob = json.dumps(fresh().store.dump())
    leaked = sorted(v for v in raw_pii_values() if v in blob)
    assert not leaked, f"raw PII leaked into the vector store: {leaked}"


def test_no_raw_pii_in_llm_prompt():
    res = fresh().answer("billing refund complaint", Principal("anonymous", "none"))
    leaked = sorted(v for v in raw_pii_values() if v in res["prompt"])
    assert not leaked, f"raw PII leaked into the LLM prompt: {leaked}"


def test_unauthorized_caller_gets_no_raw_pii():
    res = fresh().answer("billing", Principal("anonymous", "none"))
    assert res["authorized"] is False
    leaked = sorted(v for v in raw_pii_values() if v in res["final_answer"])
    assert not leaked, f"unauthorized caller saw raw PII: {leaked}"


def test_authorized_caller_can_detokenize():
    res = fresh().answer("billing refund", Principal("support_agent", "authorized_response"))
    assert res["authorized"] is True
    # detokenization changed the answer (a token was resolved to a raw value)
    assert res["final_answer"] != res["llm_answer"]
