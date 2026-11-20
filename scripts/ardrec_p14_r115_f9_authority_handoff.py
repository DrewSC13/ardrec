#!/usr/bin/env python3
"""Operator-facing authority handoff CLI. No VM actions or authorization issuance."""
from ardrec.coordination.r115_f9_authority_handoff import main

if __name__ == '__main__':
    raise SystemExit(main())
