"""R117-F5D-C: real F5D-B signed fixtures, no host root."""
import importlib.util
import os
from pathlib import Path
import unittest

REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / (
    "scripts/ardrec_p14_r117_f5d_c_root_boundary.py"
)
OLD_TESTS = REPO / (
    "lab/tests/test_p14_r117_f5d_b_integrated_attestation.py"
)

def import_at(path, name):
    spec = importlib.util.spec_from_file_location(
        name, path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

m = import_at(SCRIPT, "r117_f5dc_boundary")
old = import_at(
    OLD_TESTS, "r117_f5db_test_fixture"
)

class BoundaryTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.old_class = old.IntegratedSnapshotTests
        cls.old_class.setUpClass()

    @classmethod
    def tearDownClass(cls):
        cls.old_class.tearDownClass()

    def setUp(self):
        fixture = self.old_class(
            "test_integrated_positive"
        )
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)

        self.fixture = fixture
        self.root = fixture.folder / "host-root"
        self.root.mkdir(mode=0o700)
        os.chmod(self.root, 0o700)

        self.pilot = self.root / m.PILOT
        self.release = self.root / m.RELEASE
        self.journal = self.root / (
            ".r117-f5b-transaction-" + "1" * 24
        )

        fixture.pilot.rename(self.pilot)
        fixture.release.rename(self.release)
        fixture.journal.rename(self.journal)

        self.trust = fixture.folder / "test-trust"
        self.trust.mkdir(mode=0o700)
        os.chmod(self.trust, 0o700)

        trust = {
            "approval.pem": fixture.approval_key,
            "revocation.pem": fixture.revocation_key,
            "revocation.json": fixture.revocation_raw,
            "revocation.sig": fixture.revocation_sig,
        }

        for name, raw in trust.items():
            target = self.trust / name
            target.write_bytes(raw)
            os.chmod(target, 0o600)

        self.root_fd = os.open(
            self.root, m.FLAGS_DIR
        )
        self.trust_fd = os.open(
            self.trust, m.FLAGS_DIR
        )

        self.addCleanup(os.close, self.root_fd)
        self.addCleanup(os.close, self.trust_fd)

    def check(self, *, head=None, uid=None):
        return m.verify_fd_boundary(
            self.root_fd,
            self.trust_fd,
            self.fixture.head
                if head is None else head,
            self.fixture.candidate,
            now=self.fixture.now,
            uid=os.geteuid()
                if uid is None else uid,
            repo=REPO,
        )

    def denied(self, *, head=None, uid=None):
        with self.assertRaises(
            (m.Stop, ValueError, OSError)
        ):
            self.check(head=head, uid=uid)

    def test_integrated_snapshot_and_untrusted_provenance(self):
        result = self.check()

        self.assertEqual(
            result["files_verified"], 39
        )
        self.assertTrue(
            result["fd_snapshot_consistent"]
        )

        for field in (
            "host_root_provenance_attested",
            "independent_trust_provisioned",
            "transaction_durability_attested",
            "root_release_accepted",
            "boot_authorized",
            "network_authorized",
        ):
            self.assertIs(result[field], False)

        self.assertEqual(result["p8"], "NO-GO")

    def test_missing_transaction_rejected(self):
        self.journal.rename(
            self.root / "old-journal"
        )
        self.denied()

    def test_two_transactions_rejected(self):
        (
            self.root /
            (".r117-f5b-transaction-" + "2" * 24)
        ).mkdir(mode=0o700)
        self.denied()

    def test_malformed_transaction_rejected(self):
        self.journal.rename(
            self.root /
            (".r117-f5b-transaction-" + "g" * 24)
        )
        self.denied()

    def test_pilot_directory_missing_rejected(self):
        self.pilot.rename(
            self.root / "pilot-not-active"
        )
        self.denied()

    def test_release_symlink_rejected(self):
        real = self.root / "real-release"
        self.release.rename(real)
        self.release.symlink_to(
            real, target_is_directory=True
        )
        self.denied()

    def test_journal_symlink_rejected(self):
        real = self.root / "real-journal"
        self.journal.rename(real)
        self.journal.symlink_to(
            real, target_is_directory=True
        )
        self.denied()

    def test_trust_extra_file_rejected(self):
        item = self.trust / "unexpected.pem"
        item.write_bytes(b"x")
        os.chmod(item, 0o600)
        self.denied()

    def test_trust_file_permissions_rejected(self):
        os.chmod(
            self.trust / "approval.pem", 0o644
        )
        self.denied()

    def test_wrong_public_key_rejected(self):
        (
            self.trust / "approval.pem"
        ).write_bytes(
            self.fixture.revocation_key
        )
        self.denied()

    def test_missing_completion_rejected(self):
        (
            self.journal / "complete.json"
        ).unlink()
        self.denied()

    def test_modified_executable_rejected(self):
        target = self.pilot / "root-pilot.py"
        target.write_bytes(
            target.read_bytes() +
            b"# violation\n"
        )
        self.denied()

    def test_wrong_uid_rejected(self):
        self.denied(uid=os.geteuid() + 1)

    def test_wrong_head_rejected(self):
        self.denied(head="b" * 40)

    def test_broken_revocation_signature_rejected(self):
        (
            self.trust / "revocation.sig"
        ).write_bytes(b"bad")
        self.denied()

    def test_unexpected_transaction_file_rejected(self):
        extra = (
            self.journal / "unexpected.json"
        )
        extra.write_bytes(b"{}\n")
        os.chmod(extra, 0o600)
        self.denied()

    def test_insecure_transaction_mode_rejected(self):
        os.chmod(self.journal, 0o755)
        self.denied()

if __name__ == "__main__":
    unittest.main()
