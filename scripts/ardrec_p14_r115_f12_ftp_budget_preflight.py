#!/usr/bin/env python3
"""Offline F12 proposal; never connects, starts guests, or issues P8 release."""
from ardrec.coordination.r115_f12_ftp_budget_preflight import main

if __name__ == '__main__':
    raise SystemExit(main())
