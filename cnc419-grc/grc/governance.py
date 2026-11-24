"""Human-in-the-loop governance.

The AI may *recommend* risk acceptance or a policy exception, but it can never
authorise one. A designated human Risk Owner or CISO must formally sign off, and
the ledger records who approved what and when — an auditable control that the
automation cannot bypass.
"""
from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import Optional

_AUTHORISED_ROLES = {"CISO", "RiskOwner"}


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class SignOff:
    decision_id: str
    kind: str                       # risk_acceptance | policy_exception
    description: str
    risk_ref: Optional[str] = None
    recommended_by: str = "AI"
    status: str = "pending"         # pending | approved | rejected
    approver: Optional[str] = None
    approver_role: Optional[str] = None
    decided_at: Optional[str] = None

    def to_dict(self) -> dict:
        return self.__dict__.copy()


class GovernanceLedger:
    def __init__(self):
        self._items: dict[str, SignOff] = {}
        self._seq = 0

    def recommend(self, kind: str, description: str, risk_ref: Optional[str] = None) -> SignOff:
        """AI logs a recommendation. It starts PENDING — never auto-approved."""
        self._seq += 1
        decision_id = f"gov-{self._seq:04d}"
        so = SignOff(decision_id=decision_id, kind=kind, description=description, risk_ref=risk_ref)
        self._items[decision_id] = so
        return so

    def authorize(self, decision_id: str, approver: str, approver_role: str) -> SignOff:
        so = self._items[decision_id]
        if approver_role not in _AUTHORISED_ROLES:
            so.status = "rejected"
            so.decided_at = _now()
            raise PermissionError(
                f"role {approver_role!r} cannot authorise {so.kind}; requires one of {sorted(_AUTHORISED_ROLES)}")
        so.status = "approved"
        so.approver = approver
        so.approver_role = approver_role
        so.decided_at = _now()
        return so

    def pending(self) -> list[SignOff]:
        return [s for s in self._items.values() if s.status == "pending"]

    def all(self) -> list[SignOff]:
        return list(self._items.values())
