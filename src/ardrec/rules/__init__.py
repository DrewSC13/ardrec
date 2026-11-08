"""A1 isolated deterministic rule-evaluation primitives (not the complete A1 engine)."""
from .core import RuleDecision, RuleError, decide, evaluate_expression

__all__ = ['RuleDecision', 'RuleError', 'decide', 'evaluate_expression']
