"""Data-protection backends.

`Protector` is the seam the whole demo turns on:
    protect(value)          -> token   (safe to embed / store / send to an LLM)
    protect_freetext(text)  -> text with PII spans tokenized in place
    reveal(text, authorized)-> text with tokens detokenized (policy-gated)
    tokens_in(text)         -> the tokens present (for exact-identifier retrieval)

MockProtector runs offline today. ProtegrityProtector is the real Developer
Edition adapter, implemented against the published API — instantiated only when
AEGIS_PROTECTOR=protegrity, so its imports never load in mock mode.

HONESTY NOTE (this is the whole point): the mock detects free-text PII with
regexes only (no PERSON NER), so it MISSES names in prose. That is a real
residual risk = detector recall — see tests/test_no_raw_leak.py, which proves
the gap rather than hiding it. Protegrity's find_and_protect() closes it with a
real classifier. We measure this; we never claim "never."
"""
from __future__ import annotations
import hashlib
import hmac
import re
from abc import ABC, abstractmethod

MOCK_TOKEN_RE = re.compile(r"tok:[0-9a-f]{20}")


class ProtectionError(Exception):
    pass


class Protector(ABC):
    #: prefix the mock's tokens carry, so leak-checks can spot "is this protected?"
    PREFIX = "tok:"

    @abstractmethod
    def protect(self, value: str, data_element: str = "text") -> str:
        """Tokenize a single value. Safe to embed / store / prompt."""

    @abstractmethod
    def unprotect(self, token: str, *, authorized: bool, data_element: str = "text") -> str:
        """Detokenize one token. MUST refuse when not authorized."""

    @abstractmethod
    def protect_freetext(self, text: str) -> str:
        """Detect PII in free text and tokenize those spans in place."""

    @abstractmethod
    def reveal(self, text: str, *, authorized: bool) -> str:
        """Detokenize every token in `text` — policy-gated. Denied -> unchanged."""

    def tokens_in(self, text: str) -> set[str]:
        """Tokens present in `text`, for exact-identifier retrieval. Override."""
        return set()

    def is_token(self, s: str) -> bool:
        return isinstance(s, str) and s.startswith(self.PREFIX)


class MockProtector(Protector):
    """Deterministic, offline stand-in for Protegrity Developer Edition.

    NOT for production. Keeps a local vault so the pipeline runs without the SDK.
    Free-text detection is regex-only (no name NER) — an honest, measured gap.
    """

    def __init__(self, key: bytes = b"aegis-dev-mock-key"):
        self._key = key
        self._vault: dict[str, str] = {}  # token -> raw  (stands in for Protegrity's store)

    def protect(self, value: str, data_element: str = "text") -> str:
        if value is None:
            return value
        digest = hmac.new(self._key, str(value).encode(), hashlib.sha256).hexdigest()[:20]
        token = f"{self.PREFIX}{digest}"
        self._vault[token] = str(value)  # deterministic: same value -> same token
        return token

    def unprotect(self, token: str, *, authorized: bool, data_element: str = "text") -> str:
        if not self.is_token(token):
            return token
        if not authorized:
            raise ProtectionError("unprotect denied: caller not authorized by policy")
        if token not in self._vault:
            raise ProtectionError(f"unknown token {token!r}")
        return self._vault[token]

    def protect_freetext(self, text: str) -> str:
        from .pii import tokenize_text  # regex-based; misses names (honest gap)

        return tokenize_text(text, self)

    def reveal(self, text: str, *, authorized: bool) -> str:
        def repl(m):
            try:
                return self.unprotect(m.group(0), authorized=authorized)
            except ProtectionError:
                return m.group(0)  # denial -> stays a token

        return MOCK_TOKEN_RE.sub(repl, text)

    def tokens_in(self, text: str) -> set[str]:
        return set(MOCK_TOKEN_RE.findall(text))


class NaiveProtector(Protector):
    """The 'before' — no protection at all. This is the baseline the attack
    defeats: identical pipeline, this protector swapped in, and raw PII flows
    into the store, the prompt, and the attacker's exfil channel. Proving AEGIS
    is a one-line drop-in is the whole point of using the same pipeline code.
    """

    def protect(self, value: str, data_element: str = "text") -> str:
        return value

    def unprotect(self, token: str, *, authorized: bool, data_element: str = "text") -> str:
        return token

    def protect_freetext(self, text: str) -> str:
        return text

    def reveal(self, text: str, *, authorized: bool) -> str:
        return text

    def tokens_in(self, text: str) -> set[str]:
        return set()


class MaskProtector(Protector):
    """Blanket redaction — the naive 'privacy' baseline. Kills leakage BUT
    destroys referential integrity (every PII value collapses to one [REDACTED]),
    so you can't tell records apart, can't look up by identifier, and can NEVER
    get the value back (irreversible). The benchmark exists to show tokenization
    beats this on the privacy/utility frontier: same privacy, far more utility.
    """

    MASK = "[REDACTED]"

    def protect(self, value: str, data_element: str = "text") -> str:
        return self.MASK

    def unprotect(self, token: str, *, authorized: bool, data_element: str = "text") -> str:
        return token  # masking is one-way; nothing to reverse

    def protect_freetext(self, text: str) -> str:
        from .pii import PATTERNS

        for _label, pat in PATTERNS:
            text = pat.sub(self.MASK, text)
        return text

    def reveal(self, text: str, *, authorized: bool) -> str:
        return text  # can't un-redact — the value is gone

    def tokens_in(self, text: str) -> set[str]:
        return set()


class ProtegrityProtector(Protector):
    """Real Protegrity Developer Edition adapter.

    Implemented against the published API (PyPI `protegrity-developer-python`,
    developer.docs.protegrity.com). Two surfaces:
      - free text:  protegrity_developer_python.find_and_protect / find_and_unprotect
                    (built-in PII NER incl. PERSON -> closes the name-leak gap)
      - structured: appython.Protector().create_session(user).protect/unprotect(v, data_element)
                    (RBAC policy engine enforces who may unprotect)

    Requires: `pip install protegrity-developer-python`, DE registration, and the
    hosted-service creds in env (DEV_EDITION_EMAIL / DEV_EDITION_PASSWORD /
    DEV_EDITION_API_KEY). The tokenize/detokenize crypto is a hosted API call
    (NOT local) and is rate-limited (10k req/day, 1MB payload) — batch via the
    bulk API for large ingests. Verify exact method names against the installed
    SDK version; this is written to the documented interface.
    """

    def __init__(self, policy_user: str | None = None):
        import os

        import protegrity_developer_python as pdp  # noqa: local import (mock mode never hits this)
        from appython import Protector as PtyProtector

        self._pdp = pdp
        self._user = policy_user or os.getenv("AEGIS_POLICY_USER", "superuser")
        self._session = PtyProtector().create_session(self._user)

    def protect(self, value: str, data_element: str = "text") -> str:
        if value is None:
            return value
        return self._session.protect(str(value), data_element)

    def unprotect(self, token: str, *, authorized: bool, data_element: str = "text") -> str:
        if not authorized:
            raise ProtectionError("unprotect denied: caller not authorized by policy")
        return self._session.unprotect(token, data_element)

    def protect_freetext(self, text: str) -> str:
        # NER + tokenize PII spans (PERSON, SSN, EMAIL, ...) in one call.
        return self._pdp.find_and_protect(text)

    def reveal(self, text: str, *, authorized: bool) -> str:
        if not authorized:
            return text  # policy denies detokenization -> tokens stay
        return self._pdp.find_and_unprotect(text)

    def tokens_in(self, text: str) -> set[str]:
        # Protegrity FPE tokens look like real data, so they aren't regex-findable.
        # Exact-identifier retrieval relies on deterministic-token equality between
        # the protected query and the protected store (same value -> same token),
        # done by tokenizing the query and substring-matching. When token spans
        # aren't separately recoverable, hybrid retrieval falls back to semantic.
        return set()


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
