"""R72-F4: operator-observed serialized systemd drop-in, read-only and fail-closed."""
from __future__ import annotations
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

BASE = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    'r72_f11p', BASE / 'scripts/ardrec_p14_r58a_f11p_boot_readiness.py')
f11 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(f11)
OLD = importlib.util.spec_from_file_location(
    'r72_old_fixtures', BASE / 'lab/tests/test_p14_r58a_f11p_boot_readiness.py')
old = importlib.util.module_from_spec(OLD)
OLD.loader.exec_module(old)


def demo_bytes():
    return (b'# ARDREC R60-D4 -- source candidate is NOT physical authorization\n'
            b'[Service]\nExecStart=\n' + f11.SERIALIZED_EXECSTART.encode() + b'\n')


def make_doc(original: bytes, added: bytes = None):
    if added is None:
        added = demo_bytes()
    return original + b'\n' + f11.SERIALIZED_HEADER + added


class R72PinnedUnit(unittest.TestCase):
    def setUp(self):
        self.f = old.fixtures()
        self.blob = demo_bytes()
        self.pin = patch.object(f11, 'SERIALIZED_DROPIN_SHA256', hashlib.sha256(self.blob).hexdigest())
        self.pin.start()
        self.addCleanup(self.pin.stop)
        self.unit = make_doc(self.f['unit_text'], self.blob)

    def failed(self, reason, unit=None, blob=None):
        with self.assertRaises(f11.Blocked) as e:
            f11.audit_unit_text(self.unit if unit is None else unit, serialized_raw=blob)
        self.assertEqual(str(e.exception), reason)

    def test_01_old_unit_still_accepted(self):
        self.assertEqual(f11.audit_unit_text(self.f['unit_text']),
                         'EXACT_EXPECTED_BOOT_EXECSTART_AND_ROOT_CONTRACT')

    def test_02_exact_one_pinned_dropin_accepted(self):
        self.assertEqual(f11.audit_unit_text(self.unit, serialized_raw=self.blob),
                         'PINNED_SERIALIZED_DROPIN_READONLY')

    def test_03_no_external_bytes_is_refused(self):
        self.failed('UNIT_OR_DROPIN_DRIFT')

    def test_04_unrelated_dropin_rejected(self):
        other = self.f['unit_text'] + b'\n# /etc/systemd/system/ardrec-r34-boot-deny.service.d/override.conf\n[Service]\nExecStart=\n'
        self.failed('UNIT_OR_DROPIN_DRIFT', other, None)

    def test_05_duplicate_pinned_fragment_rejected(self):
        self.failed('UNIT_OR_DROPIN_DRIFT', self.unit + b'\n' + f11.SERIALIZED_HEADER + self.blob,
                    self.blob)

    def test_06_wrong_sha_rejected(self):
        with patch.object(f11, 'SERIALIZED_DROPIN_SHA256', '0'*64):
            self.failed('SERIALIZED_DROPIN_SHA_DRIFT', self.unit, self.blob)

    def test_07_invalid_effective_exec_even_rehashed_rejected(self):
        changed = self.blob.replace(b'--timeout 30', b'--timeout 31')
        with patch.object(f11, 'SERIALIZED_DROPIN_SHA256', hashlib.sha256(changed).hexdigest()):
            self.failed('SERIALIZED_DROPIN_EXECSTART_DRIFT', make_doc(self.f['unit_text'], changed), changed)

    def test_08_bad_unit_main_still_rejected(self):
        oldbad = self.f['unit_text'].replace(b'ProtectSystem=strict', b'ProtectSystem=full')
        self.failed('UNIT_CONTRACT_DRIFT', make_doc(oldbad), self.blob)

    def test_09_second_service_in_main_rejected(self):
        oldbad = self.f['unit_text'] + b'[Service]\nExecStart=/bin/true\n'
        self.failed('UNIT_OR_DROPIN_DRIFT', make_doc(oldbad), self.blob)

    def test_10_extra_execstart_in_dropin_rejected_even_rehashed(self):
        changed = self.blob + b'ExecStartPre=/bin/true\n'
        with patch.object(f11, 'SERIALIZED_DROPIN_SHA256', hashlib.sha256(changed).hexdigest()):
            self.failed('SERIALIZED_DROPIN_EXECSTART_DRIFT', make_doc(self.f['unit_text'], changed), changed)

    def test_11_printed_and_read_file_mismatch_rejected(self):
        self.failed('SERIALIZED_DROPIN_SYSTEMCTL_MISMATCH', self.unit + b'extra\n', self.blob)

    def test_12_unrequested_blob_refused(self):
        self.failed('SERIALIZED_DROPIN_NOT_ACTIVE', self.f['unit_text'], self.blob)

    def test_13_hypothetical_full_assess_keeps_no_go(self):
        r = f11.assess(
            **{**self.f, 'unit_text': self.unit}, serialized_raw=self.blob)
        self.assertEqual(r['boot_serialized_dropin_sha256'], hashlib.sha256(self.blob).hexdigest())
        self.assertEqual(r['boot_unit_source_contract'], 'PINNED_SERIALIZED_DROPIN_READONLY')
        self.assertEqual(r['p8'], 'NO-GO')
        self.assertFalse(r['first_boot_attested'])
        self.assertFalse(r['manual_vm_boot_block_attested'])
        self.assertFalse(r['independent_runtime_watchdog_attested'])

    def test_14_header_with_one_newline_accepted(self):
        body = self.f['unit_text'] + f11.SERIALIZED_HEADER + self.blob
        self.assertEqual(f11.audit_unit_text(body, serialized_raw=self.blob),
                         'PINNED_SERIALIZED_DROPIN_READONLY')

    def test_15_tampered_comment_rejected_without_changed_pin(self):
        changed = self.blob.replace(b'NOT physical', b'NOT local')
        self.failed('SERIALIZED_DROPIN_SYSTEMCTL_MISMATCH', make_doc(self.f['unit_text'], changed), self.blob)

    def test_16_legacy_existing_f11p_dropin_refusal_remains(self):
        oldbad = self.f['unit_text'] + b'\n# /etc/systemd/system/ardrec-r34-boot-deny.service.d/unpinned.conf\n'
        self.failed('UNIT_OR_DROPIN_DRIFT', oldbad, None)

    def test_17_reject_bad_source_schema_even_if_pin_matches(self):
        bad = self.f['unit_text'].replace(b'User=root', b'User=nobody')
        self.failed('UNIT_CONTRACT_DRIFT', make_doc(bad), self.blob)

    def effective(self, *, extra='', argv=None, path=None, reload='no'):
        args = f11.SERIALIZED_EXECSTART.split('=', 1)[1] if argv is None else argv
        p = str(f11.SERIALIZED_DROPIN_PATH) if path is None else path
        return (f'DropInPaths={p}\nNeedDaemonReload={reload}\n'
                f'ExecStart={{ path=/usr/bin/flock ; argv[]={args} ; ignore_errors=no ; '
                f'start_time=[Tue 2026-11-17 09:18:22 -04] ; '
                f'stop_time=[Tue 2026-11-17 09:18:22 -04] ; '
                f'pid=1298 ; code=exited ; status=0 }}\n' + extra).encode()

    def test_19_exact_effective_loaded_exec(self):
        self.assertEqual(f11.audit_effective_serialized_unit(self.effective()),
                         'PINNED_SERIALIZED_EFFECTIVE_UNIT_READONLY')

    def test_20_extra_loaded_dropin_rejected(self):
        with self.assertRaisesRegex(f11.Blocked, 'SERIALIZED_EFFECTIVE_DROPIN_DRIFT'):
            f11.audit_effective_serialized_unit(self.effective(path='/etc/unknown.conf'))

    def test_21_unknown_effective_exec_rejected(self):
        with self.assertRaisesRegex(f11.Blocked, 'SERIALIZED_EFFECTIVE_EXECSTART_DRIFT'):
            f11.audit_effective_serialized_unit(self.effective(argv='/usr/bin/python3 -B /bin/true'))

    def test_22_unreloaded_effective_unit_rejected(self):
        with self.assertRaisesRegex(f11.Blocked, 'SERIALIZED_EFFECTIVE_DROPIN_DRIFT'):
            f11.audit_effective_serialized_unit(self.effective(reload='yes'))

    def test_23_duplicate_effective_field_rejected(self):
        with self.assertRaisesRegex(f11.Blocked, 'SERIALIZED_EFFECTIVE_SHOW_FIELDS'):
            f11.audit_effective_serialized_unit(self.effective(extra='NeedDaemonReload=no\n'))

    def test_24_second_execstart_record_rejected(self):
        with self.assertRaisesRegex(f11.Blocked, 'SERIALIZED_EFFECTIVE_EXECSTART_DRIFT'):
            f11.audit_effective_serialized_unit(self.effective().replace(b'status=0 }',
                                                    b'status=0 } { path=/bin/true }'))

    def test_18_effective_fragment_with_additional_unit_rejected(self):
        bad = self.blob + b'[Install]\nWantedBy=network-online.target\n'
        with patch.object(f11, 'SERIALIZED_DROPIN_SHA256', hashlib.sha256(bad).hexdigest()):
            self.failed('SERIALIZED_DROPIN_EXECSTART_DRIFT', make_doc(self.f['unit_text'], bad), bad)


    def test_25_host_readonly_forwards_verified_dropin_to_assess(self):
        """Regression: the host wrapper must forward its pinned source bytes.

        Reproduces R72-F4D: audit_unit_text succeeds standalone, but a
        missing serialized_raw keyword in host_readonly previously failed.
        All host I/O is mocked; no systemd, sudo, libvirt or nft calls.
        """
        with tempfile.TemporaryDirectory() as directory:
            link = Path(directory) / 'enabled'
            link.symlink_to(f11.UNIT_PATH)
            calls = []

            def host_read(argv):
                calls.append(argv)
                if argv[-2:] == ['rev-parse', 'HEAD']:
                    return (f11.ANCESTOR + '\n').encode()
                if 'merge-base' in argv:
                    return b''
                if argv[:2] == ['systemctl', 'show']:
                    if argv[2] == f11.BOOT:
                        return (self.effective() if '-pExecStart' in argv
                                else self.f['boot_show'])
                    return self.f['libvirt_show']
                if argv[:2] == ['systemctl', 'cat']:
                    return self.unit
                if '/usr/bin/sha256sum' in argv:
                    return self.f['hashes']
                if '/usr/bin/stat' in argv:
                    return self.f['root_stat']
                if '/usr/sbin/nft' in argv:
                    return self.f['nft_first']
                if argv[-2:] == ['nwfilter-dumpxml', f11.FILTER]:
                    return self.f['filter_xml']
                if argv[-2:] == ['net-list', '--name']:
                    return b''
                if argv[-2] == 'domstate':
                    return b'shut off\n'
                self.fail('unexpected host command in mocked test')

            with patch.object(f11, 'REPO', BASE), \
                 patch.object(f11, 'LINK', link), \
                 patch.object(f11, 'run_readonly', side_effect=host_read), \
                 patch.object(f11, 'read_pinned_serialized_dropin',
                              return_value=self.blob):
                result = f11.host_readonly()

            self.assertEqual(result['boot_unit_source_contract'],
                             'PINNED_SERIALIZED_DROPIN_READONLY')
            self.assertEqual(result['boot_serialized_dropin_sha256'],
                             hashlib.sha256(self.blob).hexdigest())
            self.assertEqual(result['p8'], 'NO-GO')
            self.assertFalse(result['first_boot_attested'])
            self.assertFalse(result['manual_vm_boot_block_attested'])
            self.assertFalse(result['independent_runtime_watchdog_attested'])
            self.assertEqual(result['host_mutations'], 0)
            self.assertEqual(len([x for x in calls
                                  if '-pExecStart' in x]), 1)


if __name__ == '__main__':
    unittest.main()
