"""CEL policy backend (cel-python, in-process — no external binaries)."""

from __future__ import annotations

from typing import Any

import celpy

from aire.policy.backend import (
    CompiledExpression,
    ExpressionCompileError,
    ExpressionEvalError,
    PolicyBackend,
)


class _CELExpression(CompiledExpression):
    def __init__(self, program: Any, source: str) -> None:
        self._program = program
        self._source = source

    def evaluate(self, variables: dict[str, Any]) -> bool:
        try:
            context = {name: celpy.json_to_cel(value) for name, value in variables.items()}
            result = self._program.evaluate(context)
        except celpy.CELEvalError as exc:
            raise ExpressionEvalError(str(exc)) from exc
        except Exception as exc:  # e.g. non-JSON-able variable
            raise ExpressionEvalError(f"{type(exc).__name__}: {exc}") from exc
        if not isinstance(result, celpy.celtypes.BoolType):
            raise ExpressionEvalError(
                f"expression must evaluate to a boolean, got {type(result).__name__}: {result!r}"
            )
        return bool(result)


class CELBackend(PolicyBackend):
    name = "cel"

    def __init__(self) -> None:
        self._env = celpy.Environment()

    def compile(self, expression: str) -> CompiledExpression:
        try:
            ast = self._env.compile(expression)
        except celpy.CELParseError as exc:
            raise ExpressionCompileError(str(exc)) from exc
        return _CELExpression(self._env.program(ast), expression)
