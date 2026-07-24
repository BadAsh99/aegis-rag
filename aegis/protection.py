"""Data-protection backends.

`Protector` is the seam the whole demo turns on:
    protect(value)   -> token          (safe to embed / store / send to an LLM)
    unprotect(token) -> value          (policy-gated; authorized callers only)

MockProtector runs offline today so the pipeline is demoable end-to-end.
ProtegrityProtector is the real Developer Edition adapter — a drop-in swap
once registration is approved and the SDK/API is in hand (see the TODOs).
"""
from __future__ import annotations
import hashlib
import hmac
from abc import ABC, abstractmethod


class ProtectionError(Exception):
    pass


class Protector(ABC):
    #: prefix every token carries, so leak-detection can spot "is this protected?"
    PREFIX = "tok:"

    @abstractmethod
    def protect(self, value: str) -> str:
        """Return a token for `value`. The token is safe to embed/store/prompt."""

    @abstractmethod
    def unprotect(self, token: str, *, authorized: bool) -> str:
        """Return the raw value for `token`. MUST refuse when not authorized."""

    def is_token(self, s: str) -> bool:
        return isinstance(s, str) and s.startswith(self.PREFIX)


class MockProtector(Protector):
    """Deterministic, offline stand-in for Protegrity Developer Edition.

    NOT for production — this keeps a local vault so the pipeline is fully
    runnable without the SDK. The *security property we demonstrate* (no raw
    PII in the vector store / prompt) holds identically under the real backend.
    """

    def __init__(self, key: bytes = b"aegis-dev-mock-key"):
        self._key = key
        self._vault: dict[str, str] = {}  # token -> raw  (Protegrity's protected store)

    def protect(self, value: str) -> str:
        if value is None:
            return value
        digest = hmac.new(self._key, str(value).encode(), hashlib.sha256).hexdigest()[:20]
        token = f"{self.PREFIX}{digest}"
        self._vault[token] = str(value)  # deterministic: same value -> same token
        return token

    def unprotect(self, token: str, *, authorized: bool) -> str:
        if not self.is_token(token):
            return token  # not protected; nothing to do
        if not authorized:
            raise ProtectionError("unprotect denied: caller not authorized by policy")
        if token not in self._vault:
            raise ProtectionError(f"unknown token {token!r}")
        return self._vault[token]


class ProtegrityProtector(Protector):
    """Real Protegrity Developer Edition adapter.

    TODO(access): wire this up once the registration is approved and Developer
    Edition access + docs land (Docs / Configure Application / API Playground).
    Expected shape (CONFIRM against the actual Developer Edition API):

        from protegrity import Client                      # or the DE SDK import
        self._c = Client(endpoint=..., api_key=...)
        token = self._c.protect(value, data_element="pii_text")
        value = self._c.unprotect(token, data_element="pii_text")  # policy-enforced

    Authorization: prefer to let Protegrity's *own* policy engine enforce
    unprotect (roles/purposes configured in Developer Edition) rather than the
    demo's local policy.py — mention that in the writeup as the production story.
    """

    def __init__(self, *args, **kwargs):
        raise NotImplementedError(
            "ProtegrityProtector not wired yet. Set AEGIS_PROTECTOR=mock until "
            "Developer Edition access lands, then implement protect/unprotect here."
        )

    def protect(self, value: str) -> str:  # pragma: no cover
        raise NotImplementedError

    def unprotect(self, token: str, *, authorized: bool) -> str:  # pragma: no cover
        raise NotImplementedError


def get_protector(kind: str) -> Protector:
    kind = (kind or "mock").lower()
    if kind == "mock":
        return MockProtector()
    if kind == "protegrity":
        return ProtegrityProtector()
    raise ValueError(f"unknown protector {kind!r} (want: mock | protegrity)")
