"""R101: fail-closed case-bound authorization proposal tests."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import os
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from ardrec.coordination import r100_ssh_a5_bridge as r100
from ardrec.coordination import r101_ssh_authority as gate


def fixture():
    return {
        "schema": r100.R99_SCHEMA,
        "transport": "REAL_TCP_IPV4_LOOPBACK_ONLY",
        "identification": "SSH-2.0-ARDREC_R99_LOCAL",
        "banner_sha256": r100.sha(r100.BANNER),
        "bytes_received": len(r100.BANNER),
        "elapsed_ms": 5,
        "tcp_connections": 1,
        "ssh_authentication": False,
        "remote_commands": 0,
        "a5_operational_attempts": 0,
        "a6_classification": "ND",
        "rf_confirmed": None,
        "evidence_accredited": False,
        "dispatch_allowed": False,
        "p8_operational": "NO-GO",
    }


class R101Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.case = Path(self.temp.name) / "case-r100"
        self.case.mkdir(mode=0o700)
        self.review_root = Path(self.temp.name) / "review-r101"
        self.review_root.mkdir(mode=0o700)

        r100.create(
            self.case, fixture(), "a" * 64,
            "R100_012345ABCDEF",
        )
        self.proposal = gate.make_proposal(
            self.case,
            request_id="REQ_" + "A" * 24,
            not_before_utc="2026-11-19T02:00:00Z",
            ttl_seconds=120,
        )

    def test_valid_proposal_still_denied(self):
        decision = gate.review(self.case, self.proposal)
        self.assertFalse(decision["authorized"])
        self.assertFalse(decision["dispatch_allowed"])
        self.assertEqual(
            tuple(decision["blockers"]), gate.BLOCKERS
        )
        self.assertEqual(decision["a6_classification"], "ND")

    def test_exact_scope(self):
        self.assertEqual(
            self.proposal["guest"],
            "ardrec-r33-dev-ssh",
        )
        self.assertEqual(self.proposal["port"], 22)
        self.assertEqual(
            self.proposal["session_id"],
            "R100_012345ABCDEF",
        )

    def test_ttl_limits(self):
        for seconds in (0, 301, -1, True):
            with self.subTest(value=seconds):
                with self.assertRaises(gate.AuthorityError):
                    gate.make_proposal(
                        self.case,
                        request_id="REQ_" + "A" * 24,
                        not_before_utc="2026-11-19T02:00:00Z",
                        ttl_seconds=seconds,
                    )

    def test_target_and_port_rejected(self):
        for field, value in (
            ("guest", "ardrec-r33-dev-ftp"),
            ("port", 2222),
            ("method_id", "SSH_PASSWORD_TEST"),
        ):
            with self.subTest(field=field):
                proposal = dict(self.proposal)
                proposal[field] = value
                with self.assertRaises(gate.AuthorityError):
                    gate.review(self.case, proposal)

    def test_spoofed_authority_rejected(self):
        for field, value in (
            ("approved", True),
            ("operational_dispatch", True),
            ("p8_operational", "GO"),
            ("external_authority_receipt_sha256", "a" * 64),
        ):
            with self.subTest(field=field):
                proposal = dict(self.proposal)
                proposal[field] = value
                proposal["sha256"] = gate.a5.digest({
                    k: v for k, v in proposal.items()
                    if k != "sha256"
                })
                with self.assertRaises(gate.AuthorityError):
                    gate.review(self.case, proposal)

    def test_case_binding_rejected(self):
        proposal = dict(self.proposal)
        proposal["r100_manifest_sha256"] = "b" * 64
        with self.assertRaises(gate.AuthorityError):
            gate.review(self.case, proposal)

    def test_expiry_tamper_rejected(self):
        proposal = dict(self.proposal)
        proposal["expires_utc"] = "2026-11-19T03:00:00Z"
        with self.assertRaises(gate.AuthorityError):
            gate.review(self.case, proposal)

    def test_persist_and_readback(self):
        first = gate.persist(
            self.case, self.review_root, self.proposal
        )
        second = gate.verify_stored(
            self.case, self.review_root
        )
        self.assertEqual(first, second)
        self.assertEqual(len(list(self.review_root.iterdir())), 2)
        self.assertFalse(second["authorized"])

    def test_review_tamper_rejected(self):
        gate.persist(
            self.case, self.review_root, self.proposal
        )
        files = list(self.review_root.glob("r101-review-*"))
        self.assertEqual(len(files), 1)
        files[0].write_bytes(files[0].read_bytes() + b" ")
        with self.assertRaises(ValueError):
            gate.verify_stored(self.case, self.review_root)

    def test_extra_file_rejected(self):
        gate.persist(
            self.case, self.review_root, self.proposal
        )
        (self.review_root / "extra").write_bytes(b"x")
        with self.assertRaises(gate.AuthorityError):
            gate.verify_stored(self.case, self.review_root)


if __name__ == "__main__":
    unittest.main()
