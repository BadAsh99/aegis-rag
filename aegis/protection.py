"""Data-protection backends — the seam the whole demo turns on.

    protect(value, owner=…)        -> token   (safe to embed / store / prompt)
    protect_freetext(text, owner=…)-> text with PII spans tokenized in place
    reveal(text, scope=…)          -> detokenize ONLY tokens the scope authorizes
    tokens_in(text)                -> tokens present (for exact-identifier retrieval)

THE KEYSTONE — scope-bound reveal (fixes the authorized-path leak):
Every token records its OWNER (the record it came from). `reveal` takes a SCOPE:
    "*"            -> break-glass / admin: detokenize everything (logged)
    {"TKT-1001"}   -> detokenize only tokens owned by those records
    set() / None   -> detokenize nothing (anonymous)
So an injection that coerces the model into dumping *other* customers' tokens
yields tokens even for an authorized agent — the agent only holds scope for the
case it actually opened. Role-gating asked "are you a support agent?"; scope-
gating asks "are you entitled to THIS person's data?" — the question that matters.

TWO THINGS COMPOSE ON THE SAME GATE:
  - honeytokens: canary records no legit query touches. A reveal attempt against
    a canary token = an exfil attempt caught in real time (detok-as-IDS).
  - reveal ledger: every actual detokenization is a signed, hash-chained,
    purpose-bound audit receipt (zero-standing-PII → GDPR Art.30 / EU AI Act).

HONESTY NOTE: the mock detects free-text PII with regexes only (no PERSON NER),
so it MISSES names in prose — a real residual risk = detector recall, proved by
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
    Free-text detection is regex-only (no name NER) — an honest, measured gap.
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
    """The 'before' — no protection. Raw PII flows into the store, the prompt,
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
    """Blanket redaction — the naive 'privacy' baseline. Kills leakage BUT
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
        return text  # can't un-redact — the value is gone

    def unprotect(self, token: str, *, authorized: bool, data_element: str = "text") -> str:
        return token


class ProtegrityProtector(Protector):
    """Real Protegrity Developer Edition adapter.

    Implemented against the published API (PyPI `protegrity-developer-python`,
    developer.docs.protegrity.com). Two surfaces:
      - free text:  protegrity_developer_python.find_and_protect / find_and_unprotect
                    (built-in PII NER incl. PERSON -> closes the name-leak gap)
      - structured: appython.Protector().create_session(user).protect/unprotect(v, data_element)
                    (RBAC policy engine enforces who may unprotect)

    Scope-bound reveal maps onto Protegrity's policy engine: production scoping is
    row/data-element policy (the session's authorized user + purpose), so an
    out-of-scope token detokenizes to itself. Here we enforce scope in-adapter
    (owner map) and use the session only for the crypto, which is the honest
    division until DE policies are authored.

    Requires: `pip install protegrity-developer-python`, DE registration, creds in
    env (DEV_EDITION_EMAIL / DEV_EDITION_PASSWORD / DEV_EDITION_API_KEY). Crypto is
    a hosted API call (NOT local), rate-limited (10k req/day, 1MB) — batch large
    ingests. Verify exact method names against the installed SDK version.
    """

    def __init__(self, policy_user: str | None = None):
        import os

        import protegrity_developer_python as pdp  # noqa: local import (mock mode never hits this)
        from appython import Protector as PtyProtector

        self._pdp = pdp
        self._user = policy_user or os.getenv("AEGIS_POLICY_USER", "superuser")
        self._session = PtyProtector().create_session(self._user)
        self._owner: dict[str, str | None] = {}  # token -> owner (scope enforcement)
        self.alerts: list[Alert] = []
        self.ledger: list[RevealEvent] = []
        self._canaries: set[str] = set()

    def mark_canary(self, owner: str) -> None:
        self._canaries.add(owner)

    def protect(self, value: str, data_element: str = "text", owner: str | None = None) -> str:
        if value is None:
            return value
        token = self._session.protect(str(value), data_element)
        self._owner[token] = owner
        return token

    def protect_freetext(self, text: str, owner: str | None = None) -> str:
        # NER + tokenize PII spans (PERSON, SSN, EMAIL, ...) in one call.
        return self._pdp.find_and_protect(text)

    def reveal(self, text: str, *, scope, purpose: str = "unspecified") -> str:
        # Deterministic FPE tokens aren't regex-findable, so reveal the whole
        # string only when the caller holds full scope; otherwise leave tokenized.
        # (Production: express scope as Protegrity row/data-element policy so this
        # is enforced token-by-token by the policy engine, not string-wise.)
        if scope == ALL or (scope and self._owner and set(self._owner.values()) <= set(scope)):
            return self._pdp.find_and_unprotect(text)
        return text

    def unprotect(self, token: str, *, authorized: bool, data_element: str = "text") -> str:
        if not authorized:
            raise ProtectionError("unprotect denied: caller not authorized by policy")
        return self._session.unprotect(token, data_element)

    def tokens_in(self, text: str) -> set[str]:
        # Protegrity FPE is deterministic: same value -> same token. So identifier
        # retrieval works by tokenizing the query's identifier with the same data
        # element and exact-matching the resulting token against the store. We
        # recover query tokens by protecting candidate identifier spans, so this is
        # NOT empty on the real backend (the earlier stub was the mock-only gap).
        from .pii import PATTERNS

        toks: set[str] = set()
        for label, pat in PATTERNS:
            for m in pat.findall(text):
                try:
                    toks.add(self._session.protect(m, label))
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
