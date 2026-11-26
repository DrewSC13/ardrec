"""Real admission entry points, isolated tests; runner entry replaced by a sentinel."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import local_protocol_pilot as transport
from ardrec.coordination import prospective_local_pilot as durable
from ardrec.experiments import prospective_attempt_journal as j
from ardrec.experiments import prospective_local_dispatch as d
from ardrec.experiments import r221_read_batch as b


class Sentinel(RuntimeError):
    pass


@unittest.skipIf(os.geteuid() == 0, "non-root journal contract")
class PreDispatchTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.head, self.tree = "a" * 40, "b" * 40
        self.coverage = durable.seal(dict(functional_protocols_verified=3,
            historical_authority_granted=False, experimental_observations_admitted=0,
            p8="NO-GO"))
        self.start_patch(d, "COVERAGE_PIN", self.coverage["sha256"])
        self.start_patch(d, "verify_checkout", True)
        self.start_patch(b, "checkout", (self.head, self.tree))
        self.start_patch(b, "load_prior", {})
        self.start_patch(b, "find_coverage", self.coverage)
        self.runner = self.start_patch(b.fixture, "run_fixture", None, error=Sentinel("runner sentinel"))
        self.ftp_runner = self.start_patch(d.ftp, "run", None, error=Sentinel("runner sentinel"))

    def start_patch(self, module, name, value, error=None):
        if name == "COVERAGE_PIN":
            p = patch.object(module, name, value)
        else:
            p = patch.object(module, name, return_value=value, side_effect=error)
        mock = p.start()
        self.addCleanup(p.stop)
        return mock

    def batch(self):
        folder = self.root / "batch"
        b.prepare(folder, self.root, self.root)
        batch = b.load_batch(folder)
        db = d.DispatchJournal(folder / "attempts.sqlite3")
        consent = durable.seal(dict(schema=b.SCHEMA + "-consent", batch_sha256=batch["sha256"],
            operator_uid=os.geteuid(), human_operators=1,
            consent_sha256=b.fixture.digest(b.batch_consent(batch).encode("ascii")),
            created_at_utc="2026-01-01T00:00:00Z",
            authorized_plans=[c["plan_sha256"] for c in batch["cases"]],
            historical_authority_granted=False, experimental_admission=False))
        durable.write_once(folder / "batch-consent.json", consent)
        for case in batch["cases"]:
            _, plan = b.load_case(folder, batch, case)
            db.authorize(plan["plan_id"], j.consent_for(plan))
        return db, folder, batch, batch["cases"][0], consent

    def rejected(self, args, code=None):
        db, folder, batch, case, consent = args
        if code:
            with self.assertRaisesRegex((ValueError, OSError), code):
                b.execute_case(*args)
        else:
            with self.assertRaises((ValueError, OSError)):
                b.execute_case(*args)
        self.runner.assert_not_called()
        s = db.snapshot(batch["cases"][0]["plan_id"])
        self.assertEqual(s["attempt_count"], 0)
        self.assertEqual(s["state"], "AUTHORIZED")
        self.assertFalse((folder / batch["cases"][0]["case_id"] / "dispatch-intent.json").exists())

    def test_cross_profile_pair(self):
        db, folder, batch, case, consent = self.batch()
        self.rejected((db, folder, batch, dict(case, profile="CONTRAST"), consent), "CASE_NOT_IN_BATCH")

    def test_cross_reference(self):
        args = self.batch()
        _, folder, batch, case, _ = args
        target = folder / case["case_id"] / "fixture-identity.json"
        target.write_bytes((folder / batch["cases"][1]["case_id"] / target.name).read_bytes())
        self.rejected(args, "CASE_PLAN_BINDING_INVALID")

    def test_missing_reference(self):
        args = self.batch()
        (args[1] / args[3]["case_id"] / "plan.json").unlink()
        self.rejected(args)

    def test_changed_reference(self):
        args = self.batch()
        path = args[1] / args[3]["case_id"] / "plan.json"
        path.write_bytes(b"{}\n")
        self.rejected(args)

    def test_permissions_and_alias(self):
        args = self.batch()
        path = args[1] / args[3]["case_id"] / "plan.json"
        path.chmod(0o644)
        self.rejected(args, "SOURCE_OWNER_MODE_SIZE_INVALID")
        path.chmod(0o600)
        moved = path.with_suffix(".saved")
        path.rename(moved)
        path.symlink_to(moved)
        self.rejected(args, "SOURCE_PATH_ALIAS")

    def test_consent_cross_reference(self):
        db, folder, batch, case, consent = self.batch()
        wrong = durable.seal({**{k:v for k,v in consent.items() if k!="sha256"}, "batch_sha256":"f"*64})
        self.rejected((db, folder, batch, case, wrong), "CONSENT_BINDING_INVALID")

    def test_journal_path_cross_reference(self):
        args = self.batch()
        db, folder, batch, case, consent = args
        other = d.DispatchJournal(self.root / "other.sqlite3", create=True)
        with self.assertRaisesRegex(j.Refusal, "JOURNAL_PATH_MISMATCH"):
            b.execute_case(other, folder, batch, case, consent)
        self.runner.assert_not_called()
        self.assertEqual(db.snapshot(case["plan_id"])["attempt_count"], 0)

    def test_change_after_reservation_blocks_runner(self):
        args = self.batch()
        db, folder, batch, case, consent = args
        real_write = durable.write_once
        def write_then_change(path, value):
            real_write(path, value)
            if path.name == "dispatch-intent.json":
                (path.parent / "fixture-identity.json").chmod(0o644)
        with patch.object(durable, "write_once", side_effect=write_then_change):
            with self.assertRaisesRegex(j.Refusal, "SOURCE_OWNER_MODE_SIZE_INVALID"):
                b.execute_case(*args)
        self.runner.assert_not_called()
        s = db.snapshot(case["plan_id"])
        self.assertEqual((s["state"], s["attempt_count"]), ("UNCERTAIN", 1))
        self.assertTrue((folder / case["case_id"] / "dispatch-failure.json").exists())

    def test_valid_boundary_reaches_sentinel_only(self):
        args = self.batch()
        with self.assertRaisesRegex(Sentinel, "runner sentinel"):
            b.execute_case(*args)
        self.runner.assert_called_once()
        s = args[0].snapshot(args[3]["plan_id"])
        self.assertEqual((s["state"], s["attempt_count"]), ("UNCERTAIN", 1))
        self.assertIsNone(s["receipt_sha256"])

    def ftp(self):
        db = d.DispatchJournal(self.root / "ftp.sqlite3", create=True)
        now = j.clock()
        plan = j.make_plan(plan_id="a"*32, protocol="FTP", head=self.head, tree=self.tree,
            coverage_sha256=self.coverage["sha256"], runner_sha256=d.ssh.digest(d.ftp.RUNNER.encode("ascii")),
            fixture_sha256=d.ssh.digest(d.ftp.PAYLOAD), operator_uid=os.geteuid(),
            created_at=now, expires_at=now+300)
        db.register(plan)
        consolidation = durable.seal(dict(assessments_reproduced=3, static_estimates_closed=0,
                                            experimental_observations_admitted=0))
        archive = self.root / "source.tar.gz"
        archive.write_bytes(b"synthetic source; not executed")
        archive.chmod(0o600)
        p = patch.object(transport, "FTP_SOURCE_SHA256", d.ssh.digest(archive.read_bytes()))
        p.start(); self.addCleanup(p.stop)
        folder = self.root / "ftp"
        folder.mkdir(mode=0o700)
        return db, plan, self.coverage, consolidation, archive, folder, j.consent_for(plan)

    def test_ftp_full_plan_mismatch(self):
        args = self.ftp()
        db, plan, *other = args
        forged = durable.seal(dict({k:v for k,v in plan.items() if k!="sha256"}, expires_at=plan["expires_at"]+1))
        with self.assertRaisesRegex(j.Refusal, "JOURNAL_PLAN_PIN_MISMATCH"):
            d.dispatch_ftp(db, forged, *other)
        self.ftp_runner.assert_not_called()
        self.assertEqual(db.snapshot(plan["plan_id"])["state"], "PLANNED")

    def test_ftp_changed_source_before_reservation(self):
        args = self.ftp()
        args[4].write_bytes(b"changed")
        with self.assertRaisesRegex(j.Refusal, "FTP_SOURCE_SHA256_INVALID"):
            d.dispatch_ftp(*args)
        self.ftp_runner.assert_not_called()
        self.assertEqual(args[0].snapshot(args[1]["plan_id"])["attempt_count"], 0)

    def test_transaction_plan_pin(self):
        db, plan, *_ = self.ftp()
        pid = plan["plan_id"]
        with self.assertRaisesRegex(j.Refusal, "JOURNAL_PLAN_PIN_MISMATCH"):
            db.authorize(pid, j.consent_for(plan), expected_plan_sha256="0"*64)
        db.authorize(pid, j.consent_for(plan), expected_plan_sha256=plan["sha256"])
        params = dict(head=plan["code_head"], tree=plan["code_tree"], runner_sha256=plan["runner_sha256"])
        with self.assertRaisesRegex(j.Refusal, "JOURNAL_PLAN_PIN_MISMATCH"):
            db.reserve(pid, **params, expected_plan_sha256="0"*64)
        self.assertEqual(db.snapshot(pid)["attempt_count"], 0)
        token = db.reserve(pid, **params, expected_plan_sha256=plan["sha256"])
        with self.assertRaisesRegex(j.Refusal, "JOURNAL_PLAN_PIN_MISMATCH"):
            db.claim_dispatch(pid, token, expected_plan_sha256="0"*64)
        self.assertEqual(db.snapshot(pid)["events"][-1]["action"], "ATTEMPT_RESERVED")
        self.assertTrue(db.claim_dispatch(pid, token, expected_plan_sha256=plan["sha256"]))
        self.ftp_runner.assert_not_called()

    def test_entire_batch_checked_before_consent_or_reservation(self):
        folder = self.root / "whole"
        b.prepare(folder, self.root, self.root)
        batch = b.load_batch(folder)
        last = batch["cases"][-1]
        (folder / last["case_id"] / "plan.json").chmod(0o644)
        with self.assertRaisesRegex(j.Refusal, "SOURCE_OWNER_MODE_SIZE_INVALID"):
            b.execute(folder, b.batch_consent(batch))
        db = d.DispatchJournal(folder / "attempts.sqlite3")
        for case in batch["cases"]:
            s = db.snapshot(case["plan_id"])
            self.assertEqual((s["state"], s["attempt_count"]), ("PLANNED", 0))
        self.assertFalse((folder / "batch-consent.json").exists())
        self.runner.assert_not_called()

    def test_ftp_source_change_after_claim_blocks_runner(self):
        args = self.ftp()
        real_write = durable.write_once
        def write_then_change(path, value):
            real_write(path, value)
            if path.name == "dispatch-intent.json":
                args[4].write_bytes(b"changed after claim")
        with patch.object(durable, "write_once", side_effect=write_then_change):
            with self.assertRaisesRegex(j.Refusal, "FTP_SOURCE_SHA256_INVALID"):
                d.dispatch_ftp(*args)
        self.ftp_runner.assert_not_called()
        s = args[0].snapshot(args[1]["plan_id"])
        self.assertEqual((s["state"], s["attempt_count"]), ("UNCERTAIN", 1))
        self.assertIsNone(s["receipt_sha256"])
