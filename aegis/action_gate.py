"""The second layer: gate the ACTION, not just the data.

Scope-bound reveal shrinks the blast radius of an injection, but one residual
remains by design — a compromised, already-authorized session can detokenize its
own scope. The answer to that residual is defense-in-depth at the layer the data-
gate can't cover: the outbound ACTION.

This is Simon Willison's "lethal trifecta" made operational — an exfiltration
needs (1) access to private data, (2) exposure to untrusted content, and (3) a
way to send data out. AEGIS's data-gate attacks leg (1) (there's no raw data to
take). The action-gate attacks leg (3): an egress that was TRIGGERED by untrusted
retrieved content is denied, and any egress to a non-allowlisted destination is
denied — regardless of whether the payload is tokenized or plaintext.

So even a fully compromised, detokenized answer cannot leave the building through
an agent tool-call. Pairs with (not replaces) the data-gate; together they close
the injection→exfil path from both ends. Kin to DeepMind CaMeL / the Dual-LLM
pattern, scoped to a demoable egress policy.
"""
from __future__ import annotations
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Action:
    kind: str        # "reply" | "http_post" | "email" | ...
    target: str      # destination host / channel
    payload: str     # what would be sent


@dataclass
class Decision:
    allowed: bool
    reason: str


class ActionGate:
    """Least-privilege egress policy over agent tool-calls."""

    def __init__(self, allowed_targets):
        self.allowed = set(allowed_targets)
        self.denied: list[tuple[Action, str]] = []

    def check(self, action: Action, *, triggered_by_untrusted: bool = False) -> Decision:
        # Leg (3) of the lethal trifecta: no egress triggered by untrusted content.
        if triggered_by_untrusted and action.kind != "reply":
            d = Decision(False, "egress triggered by untrusted retrieved content (lethal-trifecta leg 3)")
        # Least privilege: only pre-approved destinations, ever.
        elif action.target not in self.allowed:
            d = Decision(False, f"destination {action.target!r} not on the egress allowlist")
        else:
            d = Decision(True, "permitted: trusted trigger + allowlisted destination")
        if not d.allowed:
            self.denied.append((action, d.reason))
        return d
