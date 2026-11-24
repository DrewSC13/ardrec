"""Compatibility and binding tests for R221."""

import os
import unittest

from ardrec.coordination import prospective_local_pilot as durable
from ardrec.experiments import prospective_attempt_journal as journal
from ardrec.experiments import r221_read_batch as batch


class R221Tests(unittest.TestCase):

    def plan(self, protocol, operation=None):

        now = journal.clock()

        return journal.make_plan(
            plan_id="1" * 32,
            protocol=protocol,
            operation=operation,
            head="a" * 40,
            tree="b" * 40,
            coverage_sha256="c" * 64,
            runner_sha256="d" * 64,
            fixture_sha256="e" * 64,
            operator_uid=max(os.geteuid(), 1),
            created_at=now,
            expires_at=now + 60,
        )

    def test_legacy_operations_preserved(self):

        for protocol, operation in journal.OPERATIONS.items():

            plan = self.plan(protocol)

            self.assertEqual(
                plan["operation"],
                operation,
            )

            self.assertTrue(
                journal.verify_plan(plan)
            )

    def test_new_ssh_operation(self):

        plan = self.plan(
            "SSH",
            "FIXED_SYNTHETIC_SFTP_READ",
        )

        self.assertTrue(
            journal.verify_plan(plan)
        )

    def test_new_smb_operation(self):

        plan = self.plan(
            "SMB",
            "FIXED_SYNTHETIC_SMB_READ",
        )

        self.assertTrue(
            journal.verify_plan(plan)
        )

    def test_cross_protocol_operation_rejected(self):

        with self.assertRaises(journal.Refusal):

            self.plan(
                "SSH",
                "FIXED_SYNTHETIC_SMB_READ",
            )

    def test_arbitrary_command_rejected(self):

        with self.assertRaises(journal.Refusal):

            self.plan(
                "SSH",
                "ARBITRARY_SHELL_COMMAND",
            )

    def test_ftp_scope_cannot_expand(self):

        with self.assertRaises(journal.Refusal):

            self.plan(
                "FTP",
                "FIXED_SYNTHETIC_SFTP_READ",
            )

    def test_profiles_have_distinct_identities(self):

        control = batch.fixture_identity(
            "PILOT-SSH-01",
            "SSH",
            "CONTROL",
        )

        contrast = batch.fixture_identity(
            "PILOT-SSH-02",
            "SSH",
            "CONTRAST",
        )

        self.assertNotEqual(
            control["sha256"],
            contrast["sha256"],
        )

    def test_consent_bound_to_batch(self):

        first = durable.seal({
            "schema": batch.SCHEMA + "-plan",
            "case": "FIRST",
        })

        second = durable.seal({
            "schema": batch.SCHEMA + "-plan",
            "case": "SECOND",
        })

        self.assertNotEqual(
            batch.batch_consent(first),
            batch.batch_consent(second),
        )


if __name__ == "__main__":
    unittest.main()
