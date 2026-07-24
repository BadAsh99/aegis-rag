"""Authorization policy for detokenization.

Demo-simple on purpose. In production, prefer Protegrity Developer Edition's own
policy engine (roles / purposes / data-elements) so the authorization decision
lives with the data-protection layer, not the app.
"""
from dataclasses import dataclass

AUTHORIZED_ROLES = {"support_agent", "admin"}
AUTHORIZED_PURPOSES = {"authorized_response", "case_review"}


@dataclass(frozen=True)
class Principal:
    role: str
    purpose: str


def is_authorized(principal: Principal) -> bool:
    return (
        principal.role in AUTHORIZED_ROLES
        and principal.purpose in AUTHORIZED_PURPOSES
    )
