"""Exceptions raised by the evaluator."""

from __future__ import annotations

from typing import Any

__all__ = ["PolicyError"]


class PolicyError(Exception):
    """A policy could not be loaded or evaluated.

    ``details`` carries the individual problems found, so a caller can report
    every invalid statement in a policy set rather than only the first.
    """

    def __init__(self, message: str, details: list[Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details: list[Any] = list(details or ())

    def __str__(self) -> str:
        if not self.details:
            return self.message
        return f"{self.message}: " + "; ".join(str(detail) for detail in self.details)


class ExpressionError(PolicyError):
    """An `Expr` condition could not be read.

    Raised while tokenising or parsing. The evaluator treats a condition it
    cannot read as a non-match, so a malformed expression denies.
    """
