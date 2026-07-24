"""Authorization policy for detokenization — SCOPE-bound, not just role-bound.

The finding that reshaped this: a role check ("are you a support agent?") lets an
injected agent reveal EVERY customer's tokens in the retrieved context. The fix is
to authorize by SCOPE — the specific records the caller legitimately opened — so an
injection that dumps other people's tokens yields tokens even for an authorized
agent. A support agent working ticket TKT-1001 holds scope {"TKT-1001"}; break-glass
admin holds ALL (still logged to the reveal ledger).

In production, express this as Protegrity Developer Edition policy (roles /
purposes / data-elements / row filters) so the decision lives with the data-
protection layer, not the app.
"""
from __future__ import annotations
from dataclasses import dataclass, field

from .protection import ALL

AUTHORIZED_ROLES = {"support_agent", "admin"}
AUTHORIZED_PURPOSES = {"authorized_response", "case_review", "break_glass"}


@dataclass(frozen=True)
class Principal:
    role: str
    purpose: str
    #: the records this caller is entitled to detokenize. "*" (ALL) = break-glass.
    scope: object = field(default_factory=frozenset)

    @property
    def reveal_scope(self):
        """Effective reveal scope, after role/purpose gating. Denied -> reveals nothing."""
        if self.role not in AUTHORIZED_ROLES or self.purpose not in AUTHORIZED_PURPOSES:
            return frozenset()
        return self.scope


def anonymous() -> Principal:
    return Principal("anonymous", "none", frozenset())


def agent_for(*ticket_ids: str) -> Principal:
    """A support agent scoped to exactly the case(s) they opened."""
    return Principal("support_agent", "authorized_response", frozenset(ticket_ids))


def admin() -> Principal:
    """Break-glass: full reveal, but every detokenization is logged to the ledger."""
    return Principal("admin", "break_glass", ALL)


def is_authorized(principal: Principal) -> bool:
    """Back-compat convenience: does this principal have ANY reveal scope?"""
    s = principal.reveal_scope
    return s == ALL or bool(s)
