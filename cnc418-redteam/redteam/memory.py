"""Attack state & memory — what lets a multi-step chain actually chain.

The agent needs to remember three things across requests:
  * **Artefacts** it extracted (leaked ids, tokens, credentials, cookies) so a
    later step can use what an earlier step produced.
  * **Attempts** it already made, keyed by (vector, target), so it never loops
    on a payload that already failed (noise control).
  * **Observations** about the target (which endpoints exist, which reflect
    input) gathered during reconnaissance.

Deliberately a plain in-memory object — easy to snapshot into a report and easy
to explain line-by-line in the defence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AttackMemory:
    artefacts: dict[str, Any] = field(default_factory=dict)
    attempts: set[tuple[str, str]] = field(default_factory=set)
    observations: dict[str, Any] = field(default_factory=dict)
    session_headers: dict[str, str] = field(default_factory=dict)

    # -- artefacts gathered from earlier steps ------------------------------ #
    def remember(self, key: str, value: Any) -> None:
        self.artefacts[key] = value

    def recall(self, key: str, default: Any = None) -> Any:
        return self.artefacts.get(key, default)

    # -- de-dup so the agent does not repeat a failed payload --------------- #
    def already_tried(self, vector: str, target: str) -> bool:
        return (vector, target) in self.attempts

    def mark_tried(self, vector: str, target: str) -> None:
        self.attempts.add((vector, target))

    # -- recon notes -------------------------------------------------------- #
    def observe(self, key: str, value: Any) -> None:
        self.observations[key] = value

    def snapshot(self) -> dict[str, Any]:
        """JSON-friendly view for the run report."""
        return {
            "artefacts": self.artefacts,
            "attempts": sorted(f"{v}@{t}" for v, t in self.attempts),
            "observations": self.observations,
        }
