"""R42.2-D1 isolated passive observer diagnostic safety tests (no real VM/network)."""
from pathlib import Path
import hashlib
import json
import io
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'scripts'))
import ardrec_p14_r422_observer_diagnostic as diag
from ardrec.coordination import r422_independent_packet_witness as r422


class DiagnosticTests(unittest.TestCase):
    def test_exact_tcpdump_command_and_no_guest_exec(self):
        argv = diag.capture_command('tap','/usr/bin/tcpdump','/usr/bin/sudo')
        self.assertEqual(argv, ['/usr/bin/sudo','-n','--','/usr/bin/timeout',
            '-s','INT','18','/usr/bin/tcpdump','-n','-p','-i','a33d30t',
            '-s','128','-U','-c','12','-w','-',r422.FILTER])
        self.assertNotIn('virsh', ' '.join(argv))
        self.assertNotIn('ping', ' '.join(argv))

    def test_reject_unapproved_interfaces_and_binaries(self):
        for bad in ('eth0','any','none','ssh'):
            with self.assertRaises(ValueError):
                diag.capture_command(bad,'/usr/bin/tcpdump','/usr/bin/sudo')
        with self.assertRaises(ValueError):
            diag.capture_command('tap','/tmp/tcpdump','/usr/bin/sudo')
        with self.assertRaises(ValueError):
            diag.capture_command('tap','/usr/bin/tcpdump','/tmp/sudo')

    def test_header_classic_pcap_only(self):
        import struct
        valid=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,128,1)
        self.assertTrue(diag.classic_header_valid(valid))
        self.assertFalse(diag.classic_header_valid(valid[:-1]))
        self.assertFalse(diag.classic_header_valid(valid[:16]+b'\0'*8))
        self.assertFalse(diag.classic_header_valid(b'X'*24))

    def test_stderr_reason_categories(self):
        pairs=[
            (b'sudo: a password is required','SUDO_NONINTERACTIVE_AUTH_REQUIRED'),
            (b'sudo: user is not allowed to execute command','SUDO_EXEC_DENIED'),
            (b'tcpdump: a33d30t: Permission denied','CAPTURE_PERMISSION_DENIED'),
            (b'tcpdump: a33d30t: No such device exists','CAPTURE_INTERFACE_UNAVAILABLE'),
            (b'tcpdump: syntax error in filter','CAPTURE_FILTER_INVALID'),
            (b'command not found','CAPTURE_EXECUTABLE_MISSING'),
            (b'other failure','UNCLASSIFIED'),(b'','NO_STDERR')]
        for raw,code in pairs:
            self.assertEqual(diag.categorize(raw),code)

    def _fake_launcher(self, script):
        def launcher(argv, **opts):
            self.assertIn('/usr/bin/timeout',argv)
            self.assertEqual(opts.get('process_group'), 0)
            self.assertNotIn('start_new_session', opts)
            return subprocess.Popen([sys.executable,'-B','-c',script], **opts)
        return launcher

    def test_launch_success_header_without_real_tcpdump(self):
        script="import sys,struct;sys.stdout.buffer.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,128,1));sys.stdout.buffer.flush()"
        def completed_launcher(argv, **opts):
            # Keep fake successful completion deterministic before SIGINT cleanup.
            proc=self._fake_launcher(script)(argv, **opts)
            proc.wait(timeout=2)
            return proc
        row=diag.probe('tap','/usr/bin/tcpdump','/usr/bin/sudo',
                       launcher=completed_launcher,wait_ready=2)
        self.assertEqual(row['status'],'PCAP_HEADER_READY')
        self.assertTrue(row['pcap_header_valid'])
        self.assertEqual(row['stdout_bytes'],24)
        self.assertEqual(row['interface'],'a33d30t')

    def test_passive_probe_uses_separate_group_same_terminal_session(self):
        # No real packet-capture process is invoked.
        import os
        script = ("import sys,struct,time;"
                  "sys.stdout.buffer.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,128,1));"
                  "sys.stdout.buffer.flush();time.sleep(8)")
        launched = []
        def launcher(argv, **opts):
            self.assertEqual(opts.get('process_group'),0)
            self.assertNotIn('start_new_session',opts)
            proc = subprocess.Popen([sys.executable,'-B','-c',script],**opts)
            launched.append(proc)
            self.assertEqual(os.getpgid(proc.pid),proc.pid)
            self.assertEqual(os.getsid(proc.pid),os.getsid(0))
            return proc
        row=diag.probe('tap','/usr/bin/tcpdump','/usr/bin/sudo',
                       launcher=launcher,wait_ready=2)
        self.assertEqual(row['status'],'PCAP_HEADER_READY')
        self.assertEqual(len(launched),1)
        self.assertIsNotNone(launched[0].poll())

    def test_header_with_failed_exit_is_not_ready(self):
        script=("import sys,struct;"
                "sys.stdout.buffer.write(struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,128,1));"
                "sys.stdout.buffer.flush();sys.stderr.write('fatal failed after header\\n');sys.exit(1)")
        def completed_launcher(argv, **opts):
            proc=self._fake_launcher(script)(argv, **opts)
            proc.wait(timeout=2)
            return proc
        row=diag.probe('tap','/usr/bin/tcpdump','/usr/bin/sudo',
                       launcher=completed_launcher,wait_ready=2)
        self.assertTrue(row['pcap_header_valid'])
        self.assertEqual(row['exit_code'],1)
        self.assertEqual(row['status'],'OBSERVER_STARTUP_FAILED')

    def test_launch_fail_captures_stderr_before_header(self):
        script="import sys;sys.stderr.write('sudo: a password is required\\n');sys.exit(1)"
        row=diag.probe('tap','/usr/bin/tcpdump','/usr/bin/sudo',
                       launcher=self._fake_launcher(script),wait_ready=2)
        self.assertEqual(row['status'],'OBSERVER_STARTUP_FAILED')
        self.assertEqual(row['exit_code'],1)
        self.assertEqual(row['stderr_class'],'SUDO_NONINTERACTIVE_AUTH_REQUIRED')
        self.assertFalse(row['pcap_header_valid'])
        self.assertIn('password',row['stderr_excerpt'])

    def test_run_writes_private_report_and_no_qga(self):
        source={'source_r421_report_sha256':r422.R421_REPORT_PIN}
        def passive_fake(label,tcpdump,sudo):
            return {'status':'PCAP_HEADER_READY', 'interface':r422.INTERFACES[label]}
        with tempfile.TemporaryDirectory() as root, \
            mock.patch.object(r422,'preflight',return_value={
               'status':'READY_FOR_SEPARATE_EXPLICIT_CAPTURED_ICMP_ATTEMPT',
               'tcpdump_binary':'/usr/bin/tcpdump'}):
            dest=Path(root)/'receipt'
            doc=diag.run(source=source,receipt_dir=dest,host=object(),factory=passive_fake)
            self.assertEqual(doc['status'],'PASSIVE_OBSERVERS_READY_NO_GO')
            self.assertFalse(doc['qemu_guest_agent_contacted'])
            self.assertFalse(doc['guest_exec_attempted'])
            self.assertEqual(dest.stat().st_mode&0o777,0o700)
            raw=(dest/diag.REPORT).read_bytes()
            self.assertEqual((dest/diag.REPORT).stat().st_mode&0o777,0o600)
            self.assertEqual((dest/'SHA256SUMS').read_text(),
                             hashlib.sha256(raw).hexdigest()+'  '+diag.REPORT+'\n')
            self.assertEqual(json.loads(raw)['sha256'],doc['sha256'])

    def test_failure_is_evidenced_not_promoted(self):
        with tempfile.TemporaryDirectory() as root, \
            mock.patch.object(r422,'preflight',return_value={
               'status':'READY_FOR_SEPARATE_EXPLICIT_CAPTURED_ICMP_ATTEMPT',
               'tcpdump_binary':'/usr/bin/tcpdump'}):
            def fail_tap(label,tcpdump,sudo):
                if label=='tap': raise RuntimeError('simulated capture exit')
                return {'status':'PCAP_HEADER_READY'}
            doc=diag.run(source={'source_r421_report_sha256':r422.R421_REPORT_PIN},
                 receipt_dir=Path(root)/'receipt',factory=fail_tap)
            self.assertEqual(doc['status'],'PASSIVE_OBSERVER_STARTUP_FAILURE_NO_GO')
            self.assertEqual(doc['interfaces']['tap']['status'],'OBSERVER_DIAGNOSTIC_ERROR')
            self.assertEqual(doc['p8_operational'],'NO-GO')

    def test_wrong_source_prevents_capture(self):
        with tempfile.TemporaryDirectory() as root, \
            mock.patch.object(r422,'preflight',side_effect=AssertionError('host called')):
            with self.assertRaisesRegex(ValueError,'source_r421_receipt_not_pinned'):
                diag.run(source={'source_r421_report_sha256':'bad'},
                    receipt_dir=Path(root)/'receipt',factory=lambda *a:None)
            self.assertFalse((Path(root)/'receipt').exists())

    def test_cli_needs_separate_authorization(self):
        with self.assertRaises(SystemExit) as ctx, mock.patch('sys.stderr',io.StringIO()):
            diag.main(['--r421-result','/tmp/a','--r420-baseline','/tmp/b',
                 '--r411-observation','/tmp/c','--r41-preflight','/tmp/d',
                 '--r40-preflight','/tmp/e','--r39-reconciliation','/tmp/f',
                 '--r365-preflight','/tmp/g','--r365-first-boot','/tmp/h',
                 '--receipt-dir','/tmp/receipt'])
        self.assertEqual(ctx.exception.code,2)

if __name__ == '__main__':
    unittest.main()
