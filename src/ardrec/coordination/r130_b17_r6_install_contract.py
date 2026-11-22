"""R130/B17-R6A: immutable source-intake contract for root installation.

This module can review the exact B17-R5b source archive. It never installs
root code, provisions trust, signs approval, enables network or runs VMs.
The future independently authenticated installer must revalidate every input.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import zipfile

HEAD = "7cee2ebf7a27475dbfc77619edf40f82db17949b"
TREE = "c6dc04ee59b7e1d95541276a66ee155fccfae713"
PARENTS = (
    "7c1bf90c36b17ace9b670b360b6c183770297bec",
    "08f1257ee7852a6101fe3da847d168e26a43e8c2",
)
ARCHIVE_SHA = "7e57ca729dfcd01145c2d98a3dad845c180016a720768681f09bccace611a0af"
B4_SHA = "4bd6e0c19f9fe30fb7c32c2688dba1f232484d5f366760ecdcc17ef4548b444a"
B9_SHA = "8da834684d3bf6f4081b1c446df586f38f7df7c0fff9f5001dfd4451cfbb6b6a"
R116_GUARD = "c8bb29e434fcc3895ec3584e37cfd10354d2071056166d70e23526ba102e1ce7"
R116_F3 = "37dae3750a26857f63487239e790a6a5a69b6ba4199592dd968ef97629d8ba3c"

SCHEMA = "ARDREC-R130-B17-R6-INSTALL-SOURCE-INTAKE-v1"
NAMES = frozenset({
    "root-controller.py.source-only",
    "root-executor.py.source-only",
    "manifest-b4.draft.json",
    "manifest-b9.draft.json",
    "source-provenance.json",
})

EXPECTED_B4 = {
    "schema": "ARDREC-R126-B4-ROOT-DENY-SESSION-v1-root-bundle",
    "script_sha256": B4_SHA,
    "guard_sha256": R116_GUARD,
    "approved_head": None,
    "deny_only": True,
    "root_install_independent": False,
}

EXPECTED_B9 = {
    "schema": "ARDREC-R128-B9-ROOT-ONE-SESSION-FTP-T01-v1-root-bundle",
    "approved_head": None,
    "script_sha256": B9_SHA,
    "r126_deny_controller_sha256": B4_SHA,
    "legacy_f3_sha256": R116_F3,
    "guard_sha256": R116_GUARD,
    "root_staged_independently": False,
    "automatic_network": False,
    "p8": "NO-GO",
}

EXPECTED_PROVENANCE = {
    "schema": "ARDREC-B17-R5-REVIEW-SOURCES-v1",
    "source_commit": HEAD,
    "source_tree": TREE,
    "source_parents": list(PARENTS),
    "github_signature_verified": True,
    "local_gpg_signature_verified": False,
    "post_merge_ci": "PASS",
    "r116_guard_sha256": R116_GUARD,
    "r116_f3_sha256": R116_F3,
    "r126_b4_sha256": B4_SHA,
    "r128_b9_sha256": B9_SHA,
    "install_authorized": False,
    "independent_release_present": False,
    "root_install_performed": False,
    "physical_pilot_performed": False,
    "a6": "ND",
    "a9": None,
    "p8": "NO-GO",
}

class Stop(ValueError):
    pass

def need(ok, code):
    if not ok:
        raise Stop(code)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def canon(value):
    return (
        json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=True, allow_nan=False
        ) + "\n"
    ).encode("ascii")

def parse(raw):
    need(type(raw) is bytes and 0 < len(raw) < 16384, "DOCUMENT_SIZE")

    def unique(pairs):
        data = {}
        for key, value in pairs:
            need(key not in data, "DUPLICATE_JSON_KEY")
            data[key] = value
        return data

    try:
        data = json.loads(
            raw,
            object_pairs_hook=unique,
            parse_constant=lambda _: need(False, "NONFINITE_JSON"),
        )
    except Stop:
        raise
    except (ValueError, TypeError, UnicodeError) as exc:
        raise Stop("INVALID_JSON") from exc

    need(type(data) is dict, "DOCUMENT_OBJECT_REQUIRED")
    need(canon(data) == raw, "DOCUMENT_NONCANONICAL")
    return data

def review_entries(entries):
    """Validate source-only entries; no document can grant installation."""
    need(type(entries) is dict and set(entries) == NAMES,
         "SOURCE_ENTRY_SCOPE")

    need(all(type(v) is bytes and 0 < len(v) < 131072
             for v in entries.values()), "SOURCE_ENTRY_BYTES")

    b4 = entries["root-controller.py.source-only"]
    b9 = entries["root-executor.py.source-only"]

    need(sha(b4) == B4_SHA, "SOURCE_B4_SHA_MISMATCH")
    need(sha(b9) == B9_SHA, "SOURCE_B9_SHA_MISMATCH")

    need(parse(entries["manifest-b4.draft.json"]) == EXPECTED_B4,
         "B4_DRAFT_CONTRACT_CHANGED")
    need(parse(entries["manifest-b9.draft.json"]) == EXPECTED_B9,
         "B9_DRAFT_CONTRACT_CHANGED")
    need(parse(entries["source-provenance.json"]) == EXPECTED_PROVENANCE,
         "SOURCE_PROVENANCE_CHANGED")

    result = {
        "schema": SCHEMA,
        "approved_source_head": HEAD,
        "source_tree": TREE,
        "source_b4_sha256": B4_SHA,
        "source_b9_sha256": B9_SHA,
        "installed_r116_guard_expected_sha256": R116_GUARD,
        "installed_r116_f3_expected_sha256": R116_F3,
        "archive_claims_are_not_operational_authority": True,
        "requires_new_independent_install_approval": True,
        "requires_root_owned_installer_and_trust": True,
        "requires_fresh_signed_revocation": True,
        "transactional_install_implemented": False,
        "root_install_authorized": False,
        "root_install_executed": False,
        "physical_ftp_executed": False,
        "a6": "ND",
        "a9": None,
        "p8": "NO-GO",
    }
    result["sha256"] = sha(canon(result))
    return result

def review_archive(raw):
    """Accept only the exact private R5b ZIP; reject repacked substitutes."""
    need(type(raw) is bytes and 0 < len(raw) < 262144,
         "ARCHIVE_SIZE")
    need(sha(raw) == ARCHIVE_SHA, "ARCHIVE_SHA256_MISMATCH")

    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            members = z.infolist()
            need(len(members) == len(NAMES), "ARCHIVE_ENTRY_COUNT")
            need({x.filename for x in members} == NAMES,
                 "ARCHIVE_ENTRY_NAMES")
            need(len({x.filename for x in members}) == len(members),
                 "ARCHIVE_DUPLICATE_ENTRY")

            for item in members:
                mode = item.external_attr >> 16
                need(not item.is_dir() and item.create_system == 3,
                     "ARCHIVE_ENTRY_TYPE")
                need(stat.S_IFMT(mode) == stat.S_IFREG and
                     stat.S_IMODE(mode) == 0o600,
                     "ARCHIVE_ENTRY_MODE")
                need(0 < item.file_size < 131072,
                     "ARCHIVE_ENTRY_TOO_LARGE")

            need(z.testzip() is None, "ARCHIVE_CRC_INVALID")
            entries = {item.filename: z.read(item) for item in members}
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        raise Stop("ARCHIVE_INVALID") from exc

    result = review_entries(entries)
    result["archive_sha256"] = ARCHIVE_SHA
    result["sha256"] = sha(canon({
        k: v for k, v in result.items() if k != "sha256"
    }))
    return result

def read_private(path):
    need(isinstance(path, Path) and path.is_absolute() and
         not path.is_symlink(), "ARCHIVE_PATH_UNSAFE")

    parent = path.parent
    p = parent.lstat()
    need(stat.S_ISDIR(p.st_mode) and not parent.is_symlink() and
         p.st_uid == os.geteuid() and
         stat.S_IMODE(p.st_mode) == 0o700,
         "PRIVATE_PARENT_REQUIRED")

    s = path.lstat()
    need(stat.S_ISREG(s.st_mode) and s.st_uid == os.geteuid() and
         s.st_nlink == 1 and stat.S_IMODE(s.st_mode) == 0o600 and
         0 < s.st_size < 262144, "PRIVATE_ARCHIVE_REQUIRED")

    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        need((before.st_dev, before.st_ino, before.st_size) ==
             (s.st_dev, s.st_ino, s.st_size), "ARCHIVE_REPLACED")
        data = os.read(fd, 262144)
        after = os.fstat(fd)
        need(len(data) == s.st_size and
             (before.st_size, before.st_mtime_ns, before.st_ino) ==
             (after.st_size, after.st_mtime_ns, after.st_ino),
             "ARCHIVE_CHANGED_DURING_READ")
        return data
    finally:
        os.close(fd)

def capabilities():
    return {
        "schema": SCHEMA + "-capabilities",
        "exact_source_archive_sha256": ARCHIVE_SHA,
        "offline_source_review": True,
        "requires_external_signed_install_approval": True,
        "can_install_root": False,
        "can_enable_traffic": False,
        "can_start_vm": False,
        "can_sign_authority": False,
        "p8": "NO-GO",
    }

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--capabilities", action="store_true")
    modes.add_argument("--inspect-archive", type=Path)
    args = parser.parse_args(argv)

    try:
        result = (
            capabilities() if args.capabilities else
            review_archive(read_private(args.inspect_archive))
        )
        print(canon(result).decode("ascii").strip())
        return 0
    except (Stop, OSError, ValueError, TypeError) as exc:
        print("R130_INSTALL_CONTRACT_STOP=" +
              type(exc).__name__ + ":" + str(exc)[:160])
        print("R130_P8=NO-GO")
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
