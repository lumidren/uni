"""Budget-constrained risk-treatment optimiser.

Given a prioritised risk register, a set of candidate safeguards (each with a
cost and an expected risk-reduction), and a hard budget cap, pick the subset of
safeguards that maximises total risk-reduction without exceeding budget. This is
a 0/1 knapsack, solved exactly with dynamic programming — no heuristics, so the
recommendation is optimal and explainable.

Also exposes the four treatment strategies (Mitigate / Transfer / Avoid /
Accept); Accept and policy exceptions must go through human sign-off
(``governance.py``), never the optimiser alone.
"""
from __future__ import annotations

from dataclasses import dataclass

TREATMENT_STRATEGIES = ("mitigate", "transfer", "avoid", "accept")


@dataclass
class Safeguard:
    safeguard_id: str
    name: str
    cost: float                 # currency units
    risk_reduction: float       # total residual-risk points removed
    covers_risks: tuple[str, ...] = ()
    strategy: str = "mitigate"

    @property
    def roi(self) -> float:
        return self.risk_reduction / self.cost if self.cost else float("inf")


@dataclass
class OptimizationResult:
    selected: list[Safeguard]
    total_cost: float
    total_reduction: float
    budget: float

    @property
    def budget_remaining(self) -> float:
        return round(self.budget - self.total_cost, 2)

    def report(self) -> dict:
        return {
            "budget": self.budget,
            "selected": [s.safeguard_id for s in self.selected],
            "total_cost": round(self.total_cost, 2),
            "total_risk_reduction": round(self.total_reduction, 2),
            "budget_remaining": self.budget_remaining,
            "selected_detail": [
                {"id": s.safeguard_id, "name": s.name, "cost": s.cost,
                 "reduction": s.risk_reduction, "roi": round(s.roi, 3)}
                for s in self.selected
            ],
        }


def optimize(safeguards: list[Safeguard], budget: float, scale: int = 1) -> OptimizationResult:
    """Exact 0/1 knapsack. Costs are scaled to integers for the DP table."""
    items = [(int(round(s.cost * scale)), s.risk_reduction, s) for s in safeguards]
    cap = int(round(budget * scale))
    n = len(items)
    # dp[i][c] = best reduction using first i items within capacity c
    dp = [[0.0] * (cap + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        cost_i, red_i, _ = items[i - 1]
        for c in range(cap + 1):
            dp[i][c] = dp[i - 1][c]
            if cost_i <= c:
                cand = dp[i - 1][c - cost_i] + red_i
                if cand > dp[i][c]:
                    dp[i][c] = cand
    # backtrack
    selected: list[Safeguard] = []
    c = cap
    for i in range(n, 0, -1):
        if dp[i][c] != dp[i - 1][c]:
            cost_i, _, sg = items[i - 1]
            selected.append(sg)
            c -= cost_i
    selected.reverse()
    total_cost = sum(s.cost for s in selected)
    total_red = sum(s.risk_reduction for s in selected)
    return OptimizationResult(selected, total_cost, total_red, budget)
