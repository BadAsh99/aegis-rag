"""The second layer: gate the ACTION, not just the data.

Scope-bound reveal shrinks the blast radius of an injection, but one residual
remains by design, a compromised, already-authorized session can detokenize its
own scope. The answer to that residual is defense-in-depth at the layer the data-
gate can't cover: the outbound ACTION.

This is Simon Willison's "lethal trifecta" made operational, an exfiltration
needs (1) access to private data, (2) exposure to untrusted content, and (3) a
way to send data out. AEGIS's data-gate attacks leg (1). The action-gate attacks
leg (3), and every proposed egress runs through three checks, in order:

  1. destination allowlist: least privilege, the agent may only ever send to
     pre-approved channels. Exact match; no prefix or look-alike tricks.
  2. taint: a turn whose context included untrusted retrieved content may only
     use in-channel egress kinds (a reply into the allowlisted thread). It may
     not POST, email, or call out. Taint is DERIVED by the pipeline from what
     was retrieved and recorded per turn (`Aegis.answer` / `Aegis.act`).
  3. payload inspection: raw PII in the outbound payload is checked against the
     caller's reveal scope. PII owned by another case, or PII the protector
     cannot attribute to the caller, is denied. A reply carrying the agent's
     own customer's details to that customer's thread is allowed; the same
     reply carrying anyone else's is not.

Every decision, allow or deny, is recorded. Kin to DeepMind CaMeL / the
Dual-LLM pattern, scoped to a deterministic egress policy.

Limits, stated: payload inspection is only as good as the PII detector. Under
the mock that is regex, so reformatted PII (spaced or spelled-out emails,
undashed SSNs, base64, values split across actions) and names are NOT seen. The
allowlist is exact-string. Break-glass scope (ALL) skips the payload check by
design, it is logged on the reveal ledger instead.
"""
from __future__ import annotations
from dataclasses import dataclass, field

from .pii import find_pii
from .protection import ALL

#: egress kinds that stay inside the conversation channel (no new destination)
IN_CHANNEL_KINDS = frozenset({"reply"})


@dataclass(frozen=True)
class Action:
    kind: str        # "reply" | "http_post" | "email" | ...
    target: str      # destination host / channel
    payload: str     # what would be sent


@dataclass
class Decision:
    allowed: bool
    reason: str
    check: str = ""   # which check decided: allowlist | taint | payload | pass


class ActionGate:
    """Least-privilege, taint-aware, payload-inspecting egress policy."""

    def __init__(self, allowed_targets, protector=None):
        self.allowed = set(allowed_targets)
        self.protector = protector   # needed for payload attribution (owner of a value)
        self.decisions: list[tuple[Action, Decision]] = []

    @property
    def denied(self) -> list[tuple[Action, str]]:
        return [(a, d.reason) for a, d in self.decisions if not d.allowed]

    def check(self, action: Action, *, tainted: bool, scope=frozenset()) -> Decision:
        d = self._decide(action, tainted=tainted, scope=scope)
        self.decisions.append((action, d))
        return d

    def _decide(self, action: Action, *, tainted: bool, scope) -> Decision:
        if action.target not in self.allowed:
            return Decision(False, f"destination {action.target!r} not on the egress allowlist", "allowlist")
        if tainted and action.kind not in IN_CHANNEL_KINDS:
            return Decision(False, f"{action.kind!r} egress from a turn tainted by untrusted "
                                   "retrieved content (lethal-trifecta leg 3)", "taint")
        foreign = self._out_of_scope_pii(action.payload, scope)
        if foreign:
            return Decision(False, f"payload carries PII outside the caller's scope: "
                                   f"{', '.join(label for label, _ in foreign)}", "payload")
        return Decision(True, "permitted: allowlisted destination, kind allowed for this turn, "
                              "payload PII within scope", "pass")

    def _out_of_scope_pii(self, payload: str, scope):
        if scope == ALL:
            return []
        foreign = []
        for label, value in find_pii(payload):
            owner = self.protector.owner_of_value(value) if self.protector else None
            if owner is None or not scope or owner not in scope:
                foreign.append((label, value))
        return foreign
