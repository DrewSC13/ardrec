"""P8-R5 synthetic fixtures only; no process, network, real binaries or private data."""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "verify_p8_material_attestation.py"
spec = importlib.util.spec_from_file_location("ardrec_p8_r5", SOURCE)
assert spec is not None and spec.loader is not None
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class TempMaterialTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ardrec-r5-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "bin").mkdir(mode=0o700)
        (self.root / "aux").mkdir(mode=0o700)
        self.payload = b"ARDREC-SYNTHETIC-NON-EXECUTABLE-RECORD\n" * 3
        self.helper_payload = b"SYNTHETIC-HELPER-MATERIAL\n"
        self.binary = self.write("bin/fixture", self.payload)
        self.helper = self.write("aux/fixture", self.helper_payload)

    def write(self, rel: str, data: bytes) -> Path:
        path = self.root / rel
        path.write_bytes(data)
        path.chmod(0o600)
        return path

    def attest(self, rel="bin/fixture", sha=None, size=None, *, uid=None):
        content = (self.root / rel).read_bytes()
        return V.attest_test_owned_file(self.root, rel, sha if sha is not None else digest(content),
                                         size if size is not None else len(content), expected_uid=uid)

    def bundle(self, with_helper: bool = True):
        executable = {"relative_path": "bin/fixture", "sha256": digest(self.payload), "version": "fixture-1.0"}
        helper = {"relative_path": "aux/fixture", "sha256": digest(self.helper_payload), "version": "fixture-0.9"}
        proposal = {
            "schema_version": "1.0", "stage": "dev", "profile_id": "SSH-T01-BASE",
            "case_id": "SSH-T01-S01-01", "binary": executable,
            "auxiliaries": [helper] if with_helper else [],
            "authorization_state": "UNVERIFIED_PROPOSAL", "dispatch_allowed": False,
        }
        pin = {"schema_version": "1.0", "stage": "dev", "profile_id": "SSH-T01-BASE",
               "case_id": "SSH-T01-S01-01", "binary": {**executable, "size_bytes": len(self.payload)},
               "auxiliaries": [{**helper, "size_bytes": len(self.helper_payload)}] if with_helper else [],
               "provenance_ref": "ref:private/dev/evidence/fictional", "trusted_source_attested": False}
        return proposal, pin

    def reject(self, reason, operation):
        with self.assertRaisesRegex(V.AttestationError, reason):
            operation()

    def test_synthetic_fd_hashed_bytes_success_remains_denied(self):
        r = self.attest()
        self.assertEqual(r["observed_sha256"], digest(self.payload))
        self.assertEqual(r["observed_bytes"], len(self.payload))
        self.assertEqual(r["status"], "SYNTHETIC_FD_BYTES_MATCH_DECLARATION_ONLY")
        self.assertFalse(r["provenance_verified"])
        self.assertFalse(r["future_identity_guaranteed"])
        self.assertFalse(r["authorization"])
        self.assertFalse(r["dispatch_allowed"])

    def test_synthetic_binary_and_helper_reconciled_but_denied(self):
        proposal, pin = self.bundle()
        result = V.check_synthetic_bundle(self.root, proposal, pin)
        self.assertEqual(result["observed_materials"], 2)
        self.assertFalse(result["trusted_pin_provenance"])
        self.assertFalse(result["case_authorized"])
        self.assertFalse(result["dispatch_allowed"])

    def test_synthetic_no_helpers_remains_denied(self):
        p, pin = self.bundle(False)
        self.assertEqual(V.check_synthetic_bundle(self.root, p, pin)["observed_materials"], 1)

    def test_declared_sha_only_not_enough(self):
        self.reject("digest mismatch", lambda: self.attest(sha="0" * 64))

    def test_uppercase_sha_denied(self):
        self.reject("bad sha256", lambda: self.attest(sha="A" * 64))

    def test_short_sha_denied(self):
        self.reject("bad sha256", lambda: self.attest(sha="1" * 63))

    def test_zero_length_denied(self):
        self.binary.write_bytes(b"")
        self.reject("positive and bounded", self.attest)

    def test_declared_size_mismatch(self):
        self.reject("declared material length mismatch", lambda: self.attest(size=len(self.payload) + 1))

    def test_bool_size_denied(self):
        self.reject("positive and bounded", lambda: self.attest(size=True))

    def test_large_real_file_not_read(self):
        self.binary.write_bytes(b"a" * (V.MAX_BYTES + 1))
        self.reject("positive and bounded", self.attest)

    def test_path_absolute_denied(self):
        self.reject("unsafe relative", lambda: V.attest_test_owned_file(
            self.root, str(self.binary), digest(self.payload), len(self.payload)))

    def test_path_dot_dot_denied(self):
        self.reject("unsafe relative", lambda: V.attest_test_owned_file(
            self.root, "bin/../bin/fixture", digest(self.payload), len(self.payload)))

    def test_path_dot_denied(self):
        self.reject("unsafe relative", lambda: V.attest_test_owned_file(
            self.root, "bin/./fixture", digest(self.payload), len(self.payload)))

    def test_path_double_slash_denied(self):
        self.reject("unsafe relative", lambda: V.attest_test_owned_file(
            self.root, "bin//fixture", digest(self.payload), len(self.payload)))

    def test_path_newline_denied(self):
        self.reject("unsafe relative", lambda: V.attest_test_owned_file(
            self.root, "bin/fixt\nure", digest(self.payload), len(self.payload)))

    def test_path_backslash_denied(self):
        self.reject("unsafe relative", lambda: V.attest_test_owned_file(
            self.root, r"bin\fixture", digest(self.payload), len(self.payload)))

    def test_path_depth_denied(self):
        self.reject("unsafe relative", lambda: V.attest_test_owned_file(
            self.root, "a/" * 17 + "b", digest(self.payload), len(self.payload)))

    def test_missing_file_denied(self):
        self.reject("path or read denied", lambda: V.attest_test_owned_file(
            self.root, "bin/missing", digest(self.payload), len(self.payload)))

    def test_symlink_file_denied(self):
        (self.root / "bin/symlink").symlink_to(self.binary)
        self.reject("path or read denied", lambda: V.attest_test_owned_file(
            self.root, "bin/symlink", digest(self.payload), len(self.payload)))

    def test_symlink_directory_denied(self):
        (self.root / "linked").symlink_to(self.root / "bin")
        self.reject("path or read denied", lambda: V.attest_test_owned_file(
            self.root, "linked/fixture", digest(self.payload), len(self.payload)))

    def test_root_symlink_denied(self):
        link = self.root.with_name(self.root.name + "-link")
        link.symlink_to(self.root, target_is_directory=True)
        self.addCleanup(link.unlink)
        self.reject("root must", lambda: V.attest_test_owned_file(
            link, "bin/fixture", digest(self.payload), len(self.payload)))

    def test_fifo_denied_without_block(self):
        os.mkfifo(self.root / "bin/pipe", mode=0o600)
        self.reject("regular file", lambda: V.attest_test_owned_file(
            self.root, "bin/pipe", digest(self.payload), len(self.payload)))

    def test_directory_instead_of_material_denied(self):
        self.reject("regular file", lambda: V.attest_test_owned_file(
            self.root, "bin", digest(self.payload), len(self.payload)))

    def test_group_writable_file_denied(self):
        self.binary.chmod(0o620)
        self.reject("writable by group/other", self.attest)

    def test_world_writable_file_denied(self):
        self.binary.chmod(0o602)
        self.reject("writable by group/other", self.attest)

    def test_group_writable_parent_denied(self):
        (self.root / "bin").chmod(0o770)
        self.reject("material parent: writable", self.attest)

    def test_world_writable_root_denied(self):
        self.root.chmod(0o707)
        self.reject("fixture root: writable", self.attest)

    def test_setuid_file_denied(self):
        self.binary.chmod(0o4600)
        self.reject("setuid/setgid", self.attest)

    def test_setgid_file_denied(self):
        self.binary.chmod(0o2600)
        self.reject("setuid/setgid", self.attest)

    def test_hardlink_file_denied(self):
        os.link(self.binary, self.root / "bin/linked")
        self.reject("hardlink ambiguous", self.attest)

    def test_wrong_uid_denied(self):
        self.reject("active tester", lambda: self.attest(uid=os.getuid() + 1))

    def test_bool_uid_denied(self):
        self.reject("active tester", lambda: self.attest(uid=True))

    def test_mutation_during_read_denied(self):
        original_read = os.read
        did = False
        def tamper(fd, length):
            nonlocal did
            data = original_read(fd, length)
            if data and not did:
                did = True
                self.binary.write_bytes(b"X" * len(self.payload))
            return data
        with patch.object(V.os, "read", side_effect=tamper):
            self.reject("metadata changed", self.attest)

    def test_swap_path_after_fd_read_denied(self):
        original_read = os.read
        did = False
        def change_name(fd, length):
            nonlocal did
            data = original_read(fd, length)
            if data and not did:
                did = True
                renamed = self.root / "bin/old"
                self.binary.rename(renamed)
                self.write("bin/fixture", self.payload)
            return data
        with patch.object(V.os, "read", side_effect=change_name):
            self.reject("metadata changed|name-to-inode", self.attest)

    def test_proposal_bad_schema_denied(self):
        p, pin = self.bundle()
        p["new_field"] = True
        self.reject("unexpected/missing", lambda: V.check_synthetic_bundle(self.root, p, pin))

    def test_pin_bad_schema_denied(self):
        p, pin = self.bundle()
        pin.pop("trusted_source_attested")
        self.reject("unexpected/missing", lambda: V.check_synthetic_bundle(self.root, p, pin))

    def test_cross_stage_denied(self):
        p, pin = self.bundle()
        pin["stage"] = "exp"
        self.reject("cross-stage", lambda: V.check_synthetic_bundle(self.root, p, pin))

    def test_unknown_stage_denied(self):
        p, pin = self.bundle()
        p["stage"] = pin["stage"] = "external"
        self.reject("cross-stage", lambda: V.check_synthetic_bundle(self.root, p, pin))

    def test_cross_profile_denied(self):
        p, pin = self.bundle()
        pin["profile_id"] = "SMB-T09-WRITE"
        self.reject("cross-profile", lambda: V.check_synthetic_bundle(self.root, p, pin))

    def test_unknown_profile_not_in_p8_denied(self):
        p, pin = self.bundle()
        p["profile_id"] = pin["profile_id"] = "SSH-T99-BASE"
        self.reject("cross-profile", lambda: V.check_synthetic_bundle(self.root, p, pin))

    def test_fixed_profile_count(self):
        self.assertEqual(len(V.KNOWN_PROFILES), 29)

    def test_cross_case_denied(self):
        p, pin = self.bundle()
        pin["case_id"] = "SSH-T01-S01-02"
        self.reject("cross-case", lambda: V.check_synthetic_bundle(self.root, p, pin))

    def test_wrong_family_case_denied(self):
        p, pin = self.bundle()
        p["case_id"] = pin["case_id"] = "SMB-T01-S01-01"
        self.reject("cross-case", lambda: V.check_synthetic_bundle(self.root, p, pin))

    def test_proposed_approval_denied(self):
        p, pin = self.bundle()
        p["authorization_state"] = "APPROVED"
        self.reject("cannot authorize", lambda: V.check_synthetic_bundle(self.root, p, pin))

    def test_dispatch_true_denied(self):
        p, pin = self.bundle()
        p["dispatch_allowed"] = True
        self.reject("cannot authorize", lambda: V.check_synthetic_bundle(self.root, p, pin))

    def test_pin_trusted_source_claim_denied(self):
        p, pin = self.bundle()
        pin["trusted_source_attested"] = True
        self.reject("cannot claim trusted", lambda: V.check_synthetic_bundle(self.root, p, pin))

    def test_cross_stage_provenance_denied(self):
        p, pin = self.bundle()
        pin["provenance_ref"] = "ref:private/exp/evidence/fictional"
        self.reject("provenance scope", lambda: V.check_synthetic_bundle(self.root, p, pin))

    def test_provenance_traversal_denied(self):
        p, pin = self.bundle()
        pin["provenance_ref"] = "ref:private/dev/../exp/evidence/fictional"
        self.reject("provenance scope", lambda: V.check_synthetic_bundle(self.root, p, pin))

    def test_binary_digest_mismatch_between_records_denied(self):
        p, pin = self.bundle()
        pin["binary"]["sha256"] = "a" * 64
        self.reject("changed proposed pin", lambda: V.check_synthetic_bundle(self.root, p, pin))

    def test_binary_digest_mismatch_observed_denied(self):
        p, pin = self.bundle()
        wrong = "b" * 64
        p["binary"]["sha256"] = pin["binary"]["sha256"] = wrong
        self.reject("digest mismatch", lambda: V.check_synthetic_bundle(self.root, p, pin))

    def test_binary_version_mismatch_denied(self):
        p, pin = self.bundle()
        pin["binary"]["version"] = "2"
        self.reject("changed proposed pin", lambda: V.check_synthetic_bundle(self.root, p, pin))

    def test_invalid_version_denied(self):
        p, pin = self.bundle()
        p["binary"]["version"] = pin["binary"]["version"] = "v 1"
        self.reject("changed proposed pin", lambda: V.check_synthetic_bundle(self.root, p, pin))

    def test_helper_count_mismatch_denied(self):
        p, pin = self.bundle()
        p["auxiliaries"].clear()
        self.reject("auxiliaries: length mismatch", lambda: V.check_synthetic_bundle(self.root, p, pin))

    def test_helper_digest_mismatch_denied(self):
        p, pin = self.bundle()
        p["auxiliaries"][0]["sha256"] = "a" * 64
        self.reject("changed proposed pin", lambda: V.check_synthetic_bundle(self.root, p, pin))

    def test_helper_size_mismatch_denied(self):
        p, pin = self.bundle()
        pin["auxiliaries"][0]["size_bytes"] += 1
        self.reject("declared material length", lambda: V.check_synthetic_bundle(self.root, p, pin))

    def test_duplicate_helper_path_denied(self):
        p, pin = self.bundle()
        p["auxiliaries"].append(copy.deepcopy(p["auxiliaries"][0]))
        pin["auxiliaries"].append(copy.deepcopy(pin["auxiliaries"][0]))
        self.reject("duplicate material path", lambda: V.check_synthetic_bundle(self.root, p, pin))

    def test_main_binary_repeated_as_helper_denied(self):
        p, pin = self.bundle()
        p["auxiliaries"][0] = copy.deepcopy(p["binary"])
        pin["auxiliaries"][0] = copy.deepcopy(pin["binary"])
        self.reject("duplicate material path", lambda: V.check_synthetic_bundle(self.root, p, pin))

    def test_too_many_helpers_denied(self):
        p, pin = self.bundle()
        p["auxiliaries"] *= 13
        pin["auxiliaries"] *= 13
        self.reject("auxiliaries: length mismatch", lambda: V.check_synthetic_bundle(self.root, p, pin))

    def test_non_list_helpers_denied(self):
        p, pin = self.bundle()
        p["auxiliaries"] = "aux/fixture"
        self.reject("auxiliaries: length mismatch", lambda: V.check_synthetic_bundle(self.root, p, pin))

    def test_declared_version_not_verified(self):
        p, pin = self.bundle()
        p["binary"]["version"] = pin["binary"]["version"] = "FAKE-99"
        result = V.check_synthetic_bundle(self.root, p, pin)
        self.assertTrue(result["declared_versions_not_verified"])
        self.assertFalse(result["case_authorized"])

    def test_no_external_process_api_in_module(self):
        source = SOURCE.read_text()
        self.assertNotIn("import subprocess", source)
        self.assertNotIn("import socket", source)
        self.assertNotIn("os.exec", source)
        self.assertNotIn("subprocess.run", source)

    def test_contract_anchor(self):
        self.assertEqual(V.BASE, "2030ef4fe24e3595cfb365853912548ff3294056")
        self.assertEqual(V.MAX_BYTES, 1_048_576)
        self.assertEqual(V.MAX_HELPERS, 12)
        self.assertEqual(V.R4_SOURCE_SHA256,
                         "7099a37f36096b0a50db08a88e34539b7269c9f6ee002b57f163cede0aed472a")

    def test_strict_contract_baseline_fields(self):
        source = Path(__file__).resolve().parents[1] / "p8-material-attestation-v1/contract.json"
        j = json.loads(source.read_text())
        self.assertEqual(j["checks"], V.EXPECTED_CHECKS)
        self.assertEqual(j["unverified"], V.EXPECTED_UNVERIFIED)
        self.assertFalse(j["dispatch_allowed"])
        self.assertEqual(j["real_artifacts_inspected"], 0)
        self.assertEqual(j["open_findings"], ["AL-06", "AL-07"])


if __name__ == "__main__":
    unittest.main()
