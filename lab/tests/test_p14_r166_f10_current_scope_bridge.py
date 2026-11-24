"""R166-F10: current HEAD route, Ed25519 and fail-closed regression."""
from __future__ import annotations

import copy
from datetime import timedelta
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch

from ardrec.coordination import r115_f7_controlled_boot as f7
from ardrec.coordination import r115_f6_signed_scope_and_activation as f6
from ardrec.coordination import r115_f3_f11_authority as f3
from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r116_f2_current_pilot_gate as current

from test_p14_r116_f2_current_pilot_gate import fixture
from test_p14_r115_f11_p8_signed_window import (
    HEAD, NOW, CATALOG, signed,
)

REPO = Path(__file__).resolve().parents[2]


class CurrentHeadBridgeTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.valid = fixture()

    def route(self, case=None, *, head=HEAD, now=NOW,
              branch=None, missing_trust=False):
        case = copy.deepcopy(
            self.valid if case is None else case
        )
        branch = branch or f7.ACTIVE_BRANCH

        def fake_git_command(args):
            self.assertEqual(
                args, ("git", "branch", "--show-current")
            )
            return {
                "stdout": branch,
                "stderr": "",
                "rc": 0,
                "timeout": False,
                "truncated": False,
            }

        original = current.current_scope_review

        def reviewed(contract_raw, auth_raw, *,
                     catalog_raw, now, head):
            def root_loader(path):
                if missing_trust:
                    raise FileNotFoundError(path)
                return case["root"][path]

            return original(
                contract_raw,
                auth_raw,
                catalog_raw=catalog_raw,
                now=now,
                head=head,
                root_loader=root_loader,
            )

        with patch.object(
            f7, "_run", side_effect=fake_git_command
        ), patch.object(
            f7, "git_guard", return_value=head
        ), patch.object(
            current, "current_scope_review",
            side_effect=reviewed
        ), patch.object(f6, "scope") as historical:
            result = f7.scope_required(
                case["contract_raw"],
                case["auth_raw"],
                now=now,
            )
            historical.assert_not_called()
            return result

    def test_01_current_signed_scope_passes(self):
        result = self.route()
        self.assertEqual(result[0], "VERDADERO")
        self.assertEqual(
            result[1],
            "R116_CURRENT_HEAD_ROOT_SCOPE_AT_REVIEW_ONLY",
        )
        self.assertEqual(
            result[2],
            f1.digest(self.valid["auth_raw"]),
        )

    def test_02_different_head_rejected(self):
        wrong = "0" * 40 if HEAD != "0" * 40 else "1" * 40
        with self.assertRaises(f7.Stop):
            self.route(head=wrong)

    def test_03_changed_signature_rejected(self):
        case = copy.deepcopy(self.valid)
        document = copy.deepcopy(case["auth"])
        document["signature_b64"] = "AAAA"
        case["auth_raw"] = f1.canonical(document)
        with self.assertRaises(f7.Stop):
            self.route(case)

    def test_04_signed_revocation_rejected(self):
        case = copy.deepcopy(self.valid)
        document = json.loads(
            case["root"][f6.REVOCATION]
        )
        statement = document["statement"]
        statement["revoked"] = True

        revoked = signed(
            statement,
            case["keys"][1],
            case["public"][1],
            f3.PREFIX_REVOKE,
        )

        case["root"][f6.REVOCATION] = f1.canonical(revoked)

        with self.assertRaises(f7.Stop):
            self.route(case)

    def test_05_stale_revocation_rejected(self):
        with self.assertRaises(f7.Stop):
            self.route(now=NOW + timedelta(seconds=35))

    def test_06_expired_scope_rejected(self):
        with self.assertRaises(f7.Stop):
            self.route(now=NOW + timedelta(days=2))

    def test_07_missing_root_trust_rejected(self):
        with self.assertRaises(f7.Stop):
            self.route(missing_trust=True)

    def test_08_historical_branch_still_uses_f6(self):
        historical_result = (
            "VERDADERO", "HISTORICAL_SCOPE", "a" * 64
        )

        command = {
            "stdout": f7.BRANCH,
            "stderr": "",
            "rc": 0,
            "timeout": False,
            "truncated": False,
        }

        with patch.object(
            f7, "_run", return_value=command
        ), patch.object(
            f7, "git_guard", return_value=f7.BASE
        ), patch.object(
            f6, "scope", return_value=historical_result
        ) as historical, patch.object(
            current, "current_scope_review"
        ) as modern:
            result = f7.scope_required(
                b"historical-contract",
                b"historical-authorization",
                now=NOW,
            )

            self.assertEqual(result, historical_result)
            historical.assert_called_once()
            modern.assert_not_called()

    def test_09_unsigned_head_rejected(self):
        command = {
            "stdout": f7.ACTIVE_BRANCH,
            "stderr": "",
            "rc": 0,
            "timeout": False,
            "truncated": False,
        }

        with patch.object(
            f7, "_run", return_value=command
        ), patch.object(
            f7, "git_guard",
            side_effect=f7.Stop("UNSIGNED_HEAD")
        ), patch.object(
            current, "current_scope_review"
        ) as modern:
            with self.assertRaises(f7.Stop):
                f7.scope_required(
                    self.valid["contract_raw"],
                    self.valid["auth_raw"],
                    now=NOW,
                )
            modern.assert_not_called()

    def test_10_signed_f3_pin_and_f13_derivative(self):
        from ardrec_p14_r116_f13_merge_gate import (
            R166_EXACT_DERIVATIVES,
        )

        rel = (
            "src/ardrec/coordination/"
            "r115_f7_controlled_boot.py"
        )
        lock_path = (
            "lab/operational-controller/"
            "r116-f3-root-source-lock-v1.json"
        )

        f7_digest = hashlib.sha256(
            (REPO / rel).read_bytes()
        ).hexdigest()

        lock_bytes = (REPO / lock_path).read_bytes()
        lock = json.loads(lock_bytes)

        self.assertEqual(
            lock["files"][
                "runtime/ardrec/coordination/"
                "r115_f7_controlled_boot.py"
            ],
            f7_digest,
        )
        self.assertEqual(
            R166_EXACT_DERIVATIVES[rel][1],
            f7_digest,
        )
        self.assertEqual(
            R166_EXACT_DERIVATIVES[lock_path][1],
            hashlib.sha256(lock_bytes).hexdigest(),
        )
        self.assertEqual(lock["p8"], "NO-GO")
        self.assertEqual(len(lock["files"]), 33)


if __name__ == "__main__":
    unittest.main()
