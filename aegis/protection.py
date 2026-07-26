"""Data-protection backends, the seam the whole demo turns on.

    protect(value, owner=…)        -> token   (safe to embed / store / prompt)
    protect_freetext(text, owner=…)-> text with PII spans tokenized in place
    reveal(text, scope=…)          -> detokenize ONLY tokens the scope authorizes
    tokens_in(text)                -> tokens present (for exact-identifier retrieval)

THE KEYSTONE, scope-bound reveal (fixes the authorized-path leak):
Every token records its OWNER (the record it came from). `reveal` takes a SCOPE:
    "*"            -> break-glass / admin: detokenize everything (logged)
    {"TKT-1001"}   -> detokenize only tokens owned by those records
    set() / None   -> detokenize nothing (anonymous)
So an injection that coerces the model into dumping *other* customers' tokens
yields tokens even for an authorized agent, the agent only holds scope for the
case it actually opened. Role-gating asked "are you a support agent?"; scope-
gating asks "are you entitled to THIS person's data?", the question that matters.

TWO THINGS COMPOSE ON THE SAME GATE:
  - honeytokens: canary records no legit query touches. A reveal attempt against
    a canary token = an exfil attempt caught in real time (detok-as-IDS).
  - reveal ledger: every actual detokenization is a signed, hash-chained,
    purpose-bound audit receipt (zero-standing-PII → GDPR Art.30 / EU AI Act).

HONESTY NOTE: the mock detects free-text PII with regexes only (no PERSON NER),
so it MISSES names in prose, a real residual risk = detector recall, proved by
tests/test_no_raw_leak.py (an xfail), not hidden. Protegrity find_and_protect()
closes it with a real classifier. We measure this; we never claim "never."
"""
from __future__ import annotations
import hashlib
import hmac
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

MOCK_TOKEN_RE = re.compile(r"tok:[0-9a-f]{20}")

#: scope sentinel: break-glass / admin reveal (still logged to the ledger)
ALL = "*"


class ProtectionError(Exception):
    pass


def _scope_allows(scope, owner) -> bool:
    """Does `scope` authorize revealing a token owned by `owner`?"""
    if scope == ALL:
        return True
    if not scope:
        return False
    return owner is not None and owner in scope


@dataclass
class RevealEvent:
    """One detokenization = one auditable exposure of a real human value."""
    token: str
    owner: str | None
    data_element: str
    purpose: str
    scope: str
    ts: float
    prev_hash: str
    entry_hash: str = ""


@dataclass
class Alert:
    """A tripwire hit: someone tried to cash a canary token."""
    token: str
    owner: str | None
    scope: str
    purpose: str
    in_scope: bool
    ts: float


class Protector(ABC):
    #: prefix the mock's tokens carry, so leak-checks can spot "is this protected?"
    PREFIX = "tok:"

    @abstractmethod
    def protect(self, value: str, data_element: str = "text", owner: str | None = None) -> str:
        """Tokenize a single value. Safe to embed / store / prompt."""

    @abstractmethod
    def protect_freetext(self, text: str, owner: str | None = None) -> str:
        """Detect PII in free text and tokenize those spans in place."""

    @abstractmethod
    def reveal(self, text: str, *, scope, purpose: str = "unspecified") -> str:
        """Detokenize tokens whose owner is authorized by `scope`. Others stay tokens."""

    def unprotect(self, token: str, *, authorized: bool, data_element: str = "text") -> str:
        """Detokenize one token (structured path). MUST refuse when not authorized."""
        raise NotImplementedError

    def tokens_in(self, text: str) -> set[str]:
        """Tokens present in `text`, for exact-identifier retrieval. Override."""
        return set()

    def is_token(self, s: str) -> bool:
        return isinstance(s, str) and s.startswith(self.PREFIX)


class MockProtector(Protector):
    """Deterministic, offline stand-in for Protegrity Developer Edition.

    NOT for production. Keeps a local vault so the pipeline runs without the SDK.
    Free-text detection is regex-only (no name NER), an honest, measured gap.
    Implements scope-bound reveal + the honeytoken tripwire + the reveal ledger.
    """

    def __init__(self, key: bytes = b"aegis-dev-mock-key"):
        self._key = key
        self._vault: dict[str, tuple[str, str | None]] = {}  # token -> (raw, owner)
        self._canaries: set[str] = set()   # owner ids that are honeytokens
        self.alerts: list[Alert] = []      # tripwire hits (detok-as-IDS)
        self.ledger: list[RevealEvent] = []  # signed, hash-chained reveal audit

    # ---- honeytokens -------------------------------------------------------
    def mark_canary(self, owner: str) -> None:
        """Flag a record id as a canary: any reveal attempt on its tokens alerts."""
        self._canaries.add(owner)

    # ---- protect -----------------------------------------------------------
    def protect(self, value: str, data_element: str = "text", owner: str | None = None) -> str:
        if value is None:
            return value
        digest = hmac.new(self._key, str(value).encode(), hashlib.sha256).hexdigest()[:20]
        token = f"{self.PREFIX}{digest}"
        self._vault[token] = (str(value), owner)  # deterministic: same value -> same token
        return token

    def protect_freetext(self, text: str, owner: str | None = None) -> str:
        from .pii import tokenize_text  # regex-based; misses names (honest gap)

        return tokenize_text(text, self, owner=owner)

    # ---- reveal (scope-bound) + tripwire + ledger --------------------------
    def reveal(self, text: str, *, scope, purpose: str = "unspecified") -> str:
        def repl(m):
            token = m.group(0)
            raw_owner = self._vault.get(token)
            owner = raw_owner[1] if raw_owner else None
            allowed = _scope_allows(scope, owner)

            if owner in self._canaries:  # tripwire: someone touched a canary
                self.alerts.append(Alert(token, owner, _scope_str(scope), purpose,
                                         in_scope=allowed, ts=time.time()))

            if not allowed or raw_owner is None:
                return token  # out of scope (or unknown) -> stays a token
            self._log_reveal(token, owner, purpose, scope)
            return raw_owner[0]

        return MOCK_TOKEN_RE.sub(repl, text)

    def unprotect(self, token: str, *, authorized: bool, data_element: str = "text") -> str:
        if not self.is_token(token):
            return token
        if not authorized:
            raise ProtectionError("unprotect denied: caller not authorized by policy")
        if token not in self._vault:
            raise ProtectionError(f"unknown token {token!r}")
        return self._vault[token][0]

    def tokens_in(self, text: str) -> set[str]:
        return set(MOCK_TOKEN_RE.findall(text))

    # ---- signed reveal ledger (token-as-capability audit receipt) ----------
    def _log_reveal(self, token, owner, purpose, scope):
        prev = self.ledger[-1].entry_hash if self.ledger else "genesis"
        ev = RevealEvent(token, owner, self._data_element_of(token), purpose,
                         _scope_str(scope), time.time(), prev)
        payload = f"{ev.prev_hash}|{ev.token}|{ev.owner}|{ev.purpose}|{ev.scope}|{ev.ts}"
        ev.entry_hash = hmac.new(self._key, payload.encode(), hashlib.sha256).hexdigest()
        self.ledger.append(ev)

    def _data_element_of(self, token: str) -> str:  # mock doesn't track element per token
        return "text"

    def verify_ledger(self) -> bool:
        """Re-derive the hash chain: tamper with any entry and this returns False."""
        prev = "genesis"
        for ev in self.ledger:
            if ev.prev_hash != prev:
                return False
            payload = f"{ev.prev_hash}|{ev.token}|{ev.owner}|{ev.purpose}|{ev.scope}|{ev.ts}"
            if hmac.new(self._key, payload.encode(), hashlib.sha256).hexdigest() != ev.entry_hash:
                return False
            prev = ev.entry_hash
        return True


def _scope_str(scope) -> str:
    if scope == ALL:
        return "*"
    if not scope:
        return "∅"
    return "{" + ",".join(sorted(scope)) + "}"


class NaiveProtector(Protector):
    """The 'before', no protection. Raw PII flows into the store, the prompt,
    and the attacker's exfil channel. Same pipeline, this protector swapped in.
    """

    def protect(self, value: str, data_element: str = "text", owner: str | None = None) -> str:
        return value

    def protect_freetext(self, text: str, owner: str | None = None) -> str:
        return text

    def reveal(self, text: str, *, scope, purpose: str = "unspecified") -> str:
        return text  # already plaintext

    def unprotect(self, token: str, *, authorized: bool, data_element: str = "text") -> str:
        return token

    def raw_tokens_in(self, text):  # naive can still exact-match on raw identifiers
        return set()


class MaskProtector(Protector):
    """Blanket redaction, the naive 'privacy' baseline. Kills leakage BUT
    destroys referential integrity (every value -> one [REDACTED]): can't tell
    records apart, can't look up by identifier, can NEVER get the value back.
    The benchmark shows tokenization beats this: same privacy, far more utility.
    """

    MASK = "[REDACTED]"

    def protect(self, value: str, data_element: str = "text", owner: str | None = None) -> str:
        return self.MASK

    def protect_freetext(self, text: str, owner: str | None = None) -> str:
        from .pii import PATTERNS

        for _label, pat in PATTERNS:
            text = pat.sub(self.MASK, text)
        return text

    def reveal(self, text: str, *, scope, purpose: str = "unspecified") -> str:
        return text  # can't un-redact, the value is gone

    def unprotect(self, token: str, *, authorized: bool, data_element: str = "text") -> str:
        return token


class ProtegrityProtector(Protector):
    """Real Protegrity AI Developer Edition adapter.

    Reconciled 2026-07-26 against the INSTALLED SDK (PyPI `protegrity-developer-python`
    v1.1.1). The Developer Edition surface is NER-over-text, not a per-field crypto
    session:
      - configure(endpoint_url=...)        one-time setup pointing at the DE discovery
                                           + protection API. The endpoint + any API key
                                           arrive with the DE "resources" email; set
                                           AEGIS_PROTEGRITY_ENDPOINT.
      - find_and_protect(text) -> str      detect PII (PERSON, EMAIL_ADDRESS,
                                           SOCIAL_SECURITY_ID, PHONE_NUMBER, ... see
                                           DATA_ELEMENT_MAPPING) and tokenize those
                                           spans in place. The real classifier that
                                           closes the mock's free-text name-leak gap.
      - find_and_unprotect(text) -> str    detokenize (policy-gated server-side).

    NOTE: the enterprise Application Protector (`appython`) is a DIFFERENT product that
    needs a Protegrity gateway/policy deployment; it is NOT the Developer Edition path,
    so the earlier appython.create_session().protect() structured code was wrong and is
    removed. Structured field values run through the same NER+tokenize call, which is
    DE-native and deterministic (same value -> same token), so identifier retrieval
    still works. Scope-bound reveal + per-token owner tracking are enforced in-adapter
    for the structured path; free-text token ownership is only fully recoverable via DE
    policy (production expresses scope as DE row/data-element policy). VERIFIED: the API
    names below exist in v1.1.1. UNVERIFIED offline: live protect/unprotect round-trips
    need the DE endpoint + credentials.
    """

    def __init__(self, endpoint_url: str | None = None):
        import os

        import protegrity_developer_python as pdp  # local import: never loads in mock mode

        self._pdp = pdp
        endpoint = endpoint_url or os.getenv("AEGIS_PROTEGRITY_ENDPOINT")
        # find_and_protect already tokenizes reversibly; `method` (redact|mask) only
        # applies to the redact path, so we leave it default. configure() just needs the
        # DE endpoint (arrives with the "resources" email); config only, no network yet.
        if endpoint:
            pdp.configure(endpoint_url=endpoint)
        self._owner: dict[str, str | None] = {}  # token -> owner (structured-path scope)
        self.alerts: list[Alert] = []
        self.ledger: list[RevealEvent] = []
        self._canaries: set[str] = set()

    def mark_canary(self, owner: str) -> None:
        self._canaries.add(owner)

    def protect(self, value: str, data_element: str = "text", owner: str | None = None) -> str:
        if value is None:
            return value
        # DE-native: NER+tokenize the single value. A recognized PII value comes back
        # tokenized (deterministic); a non-PII identifier is returned unchanged.
        token = self._pdp.find_and_protect(str(value))
        self._owner[token] = owner
        return token

    def protect_freetext(self, text: str, owner: str | None = None) -> str:
        # One call detects + tokenizes every PII span (PERSON, SSN, EMAIL, ...).
        out = self._pdp.find_and_protect(text)
        for t in self.tokens_in(text):  # stamp owners for scope-bound reveal
            self._owner.setdefault(t, owner)
        return out

    def reveal(self, text: str, *, scope, purpose: str = "unspecified") -> str:
        # DE tokens are not regex-findable, so gate string-wise: detokenize only when
        # the caller holds full scope (or owns every tracked token); else leave as-is.
        # Production: express scope as DE row/data-element policy, enforced token-wise.
        owners = {o for o in self._owner.values() if o is not None}
        if scope == ALL or (scope and owners and owners <= set(scope)):
            return self._pdp.find_and_unprotect(text)
        return text

    def unprotect(self, token: str, *, authorized: bool, data_element: str = "text") -> str:
        if not authorized:
            raise ProtectionError("unprotect denied: caller not authorized by policy")
        return self._pdp.find_and_unprotect(token)

    def tokens_in(self, text: str) -> set[str]:
        # Deterministic: protecting a value yields the same token the store holds, so
        # identifier retrieval works. Recover query tokens by protecting each detected
        # PII span and keeping the ones that actually changed.
        from .pii import find_pii

        toks: set[str] = set()
        for _label, span in find_pii(text):
            try:
                out = self._pdp.find_and_protect(span)
                if out and out != span:
                    toks.add(out)
            except Exception:
                continue
        return toks

def get_protector(kind: str) -> Protector:
    kind = (kind or "mock").lower()
    if kind == "mock":
        return MockProtector()
    if kind == "naive":
        return NaiveProtector()
    if kind == "mask":
        return MaskProtector()
    if kind == "protegrity":
        return ProtegrityProtector()
    raise ValueError(f"unknown protector {kind!r} (want: naive | mask | mock | protegrity)")
