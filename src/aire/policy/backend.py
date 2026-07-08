"""Backend interface the policy engine evaluates expressions through.

v1 ships a CEL backend (:mod:`aire.policy.cel_backend`). The interface exists
so an OPA/Rego backend can be added without touching the engine or the YAML
surface.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ExpressionCompileError(Exception):
    """The expression is syntactically or semantically invalid."""


class ExpressionEvalError(Exception):
    """The expression could not be evaluated against this input."""


class CompiledExpression(ABC):
    @abstractmethod
    def evaluate(self, variables: dict[str, Any]) -> bool:
        """Evaluate against JSON-able variables; must return a real bool.

        Raises :class:`ExpressionEvalError` on any evaluation failure,
        including a non-boolean result.
        """


class PolicyBackend(ABC):
    name: str

    @abstractmethod
    def compile(self, expression: str) -> CompiledExpression:
        """Compile an expression, raising :class:`ExpressionCompileError`."""
