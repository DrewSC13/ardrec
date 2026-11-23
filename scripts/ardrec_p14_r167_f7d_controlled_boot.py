#!/usr/bin/env python3
"""R167-F7D: versioned SSH controller with signed release admission."""
from ardrec.coordination import r167_f7d_release_gate as release
from ardrec.coordination.r167_f7d_controlled_boot import main

if __name__ == "__main__":
    try:
        release.source_admission()
    except (release.Stop, ValueError, OSError) as exc:
        print(
            "R167_F7D_SOURCE_STOP=" +
            type(exc).__name__ + ":" + str(exc)[:160]
        )
        raise SystemExit(23)
    raise SystemExit(main())
