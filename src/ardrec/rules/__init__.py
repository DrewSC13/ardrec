"""Núcleo tipado A1 para desarrollo, sin autoridad operacional."""
from .kernel import (A1Error, Decision, compile_expression, decide, evaluate,
                     guard_allows)

__all__ = ("A1Error", "Decision", "compile_expression", "decide", "evaluate", "guard_allows")
