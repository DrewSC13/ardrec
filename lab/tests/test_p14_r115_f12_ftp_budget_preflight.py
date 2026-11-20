"""F12 offline conformance; no actual network traffic, only injected socket fixtures."""
import copy
import hashlib
import json
import socket
import unittest
from pathlib import Path

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f10_ftp_a5_transport as f10
from ardrec.coordination import r115_f12_ftp_budget_preflight as m

ROOT = Path(__file__).resolve().parents[2]
CATALOG_RAW = (ROOT/'lab/operational-catalog-v1/catalog.json').read_bytes()
HEAD = 'a6dc82ae8d40091483c8195bd326caf3f44e2104'


class FixtureSocket:
    family = socket.AF_INET
    type = socket.SOCK_STREAM

    def __init__(self, parts=(b'220 Greeting\r\n',), *, fail=None):
        self.parts = list(parts)
        self.calls = 0
        self.fail = fail
        self.timeout = None

    def getpeername(self):
        return ('10.203.31.2', 21)

    def settimeout(self, value):
        self.timeout = value

    def recv(self, size):
        self.calls += 1
        if self.fail is not None:
            raise self.fail
        if not self.parts:
            return b''
        part = self.parts.pop(0)
        if len(part) > size:
            self.parts.insert(0, part[size:])
        return part[:size]


class TickClock:
    def __init__(self):
        self.t = 0.0
    def __call__(self):
        self.t += 0.001
        return self.t


def profile(**overrides):
    result = m.DRAFT_BUDGET.copy()
    result.update(overrides)
    return result


def candidate(parts=(b'220 Greeting\r\n',), **overrides):
    budget = profile(**overrides)
    raw_sock = FixtureSocket(parts)
    metered = m.MeteredSocket(raw_sock, budget)
    result = f10.receive_control_reply(
        metered, current_p8_guard=lambda: True,
        limits=f10.Limits(timeout_seconds=budget['timeout_seconds'],
                          max_bytes=budget['max_recv_bytes'],
                          max_lines=budget['max_lines'], read_size=budget['read_size']),
        monotonic=TickClock())
    return result, metered, budget, raw_sock


class ProfileTests(unittest.TestCase):
    def test_01_profile_pass(self):
        self.assertEqual(m.validate_profile(profile()), profile())

    def test_02_no_mutation(self):
        p=profile(); m.validate_profile(p); self.assertEqual(p,profile())

    def test_03_missing_key(self):
        p=profile(); p.pop('memory_mib');
        with self.assertRaises(m.Stop): m.validate_profile(p)

    def test_04_extra_key(self):
        with self.assertRaises(m.Stop): m.validate_profile(profile(hidden_retry=1))

    def test_05_bool_rejected(self):
        with self.assertRaises(m.Stop): m.validate_profile(profile(max_connections=True))

    def test_06_unbounded_time(self):
        with self.assertRaises(m.Stop): m.validate_profile(profile(timeout_seconds=999))

    def test_07_retries(self):
        with self.assertRaises(m.Stop): m.validate_profile(profile(additional_attempts=1))

    def test_08_multiple_connections(self):
        with self.assertRaises(m.Stop): m.validate_profile(profile(max_connections=2))

    def test_09_short_recv_capacity(self):
        with self.assertRaises(m.Stop): m.validate_profile(profile(max_recv_calls=2))

    def test_10_invalid_read_size(self):
        with self.assertRaises(m.Stop): m.validate_profile(profile(read_size=999))

    def test_11_contract_ceiling(self):
        contract={'limits':{'timeout_seconds':5,'transfer_bytes':4096,
                            'output_bytes':8192,'memory_mib':512,
                            'request_count':16,'operation_count':1}}
        with self.assertRaises(m.Stop): m.validate_profile(profile(),contract)
        self.assertEqual(m.validate_profile(profile(timeout_seconds=5),contract)['timeout_seconds'],5)


class MeterTests(unittest.TestCase):
    def test_12_realistic_greeting(self):
        r,meter,b,s=candidate()
        self.assertTrue(r['greeting_220_observed'])
        u=meter.seal()
        a=m.audit_f10_candidate(r,u,b)
        self.assertEqual(a['p8'],'NO-GO')
        self.assertEqual(a['a6'],'ND')
        self.assertFalse(a['pilot_completed'])
        self.assertFalse(a['physical_origin_attested'])
        self.assertEqual(s.calls,1)

    def test_13_multiline(self):
        r,meter,b,_=candidate((b'220-Hello\r\n', b'220 Ready\r\n'))
        self.assertTrue(m.audit_f10_candidate(r,meter.seal(),b)['reply_complete_220'])

    def test_14_negative_reply(self):
        r,meter,b,_=candidate((b'421 Temporarily unavailable\r\n',))
        self.assertFalse(m.audit_f10_candidate(r,meter.seal(),b)['reply_complete_220'])

    def test_15_receive_call_counter_precedes_timeout(self):
        s=FixtureSocket(fail=socket.timeout())
        meter=m.MeteredSocket(s,profile())
        with self.assertRaises(socket.timeout):meter.recv(1)
        self.assertEqual(meter.seal()['recv_calls'],1)

    def test_16_one_extra_call_denied_before_io(self):
        b=profile(max_recv_calls=2,max_recv_bytes=1024,read_size=512)
        s=FixtureSocket((b'1',b'2',b'3'))
        meter=m.MeteredSocket(s,b)
        meter.recv(1);meter.recv(1)
        with self.assertRaisesRegex(m.Stop,'RECV_CALL_BUDGET_EXHAUSTED'):meter.recv(1)
        self.assertEqual(s.calls,2)

    def test_17_byte_budget_denied_before_io(self):
        b=profile(max_recv_calls=2,max_recv_bytes=2,read_size=1)
        s=FixtureSocket((b'1',b'2',b'3'))
        meter=m.MeteredSocket(s,b)
        meter.recv(1);meter.recv(1)
        with self.assertRaises(m.Stop):meter.recv(1)
        self.assertEqual(s.calls,2)

    def test_18_oversized_request_rejected_before_io(self):
        s=FixtureSocket();meter=m.MeteredSocket(s,profile())
        with self.assertRaises(m.Stop):meter.recv(513)
        self.assertEqual(s.calls,0)

    def test_19_invalid_request_type(self):
        s=FixtureSocket();meter=m.MeteredSocket(s,profile())
        with self.assertRaises(m.Stop):meter.recv(True)
        self.assertEqual(s.calls,0)

    def test_20_socket_can_not_be_used_after_seal(self):
        s=FixtureSocket();meter=m.MeteredSocket(s,profile());meter.seal()
        with self.assertRaises(m.Stop):meter.recv(1)
        self.assertEqual(s.calls,0)

    def test_21_double_seal_fails(self):
        meter=m.MeteredSocket(FixtureSocket(),profile());meter.seal()
        with self.assertRaises(m.Stop):meter.seal()

    def test_22_timeout_cap(self):
        s=FixtureSocket();meter=m.MeteredSocket(s,profile())
        with self.assertRaises(m.Stop):meter.settimeout(11)

    def test_23_returned_bytes_cannot_exceed_requested(self):
        class Broken(FixtureSocket):
            def recv(self,size): self.calls+=1;return b'X'*(size+1)
        s=Broken();meter=m.MeteredSocket(s,profile())
        with self.assertRaises(m.Stop):meter.recv(2)
        self.assertEqual(s.calls,1)

    def test_24_counter_mismatch(self):
        r,meter,b,_=candidate();u=meter.seal();u['recv_calls']+=1
        with self.assertRaises(m.Stop):m.audit_f10_candidate(r,u,b)

    def test_25_budget_hash_mismatch(self):
        r,meter,b,_=candidate();u=meter.seal();u['budget_sha256']='0'*64
        with self.assertRaises(m.Stop):m.audit_f10_candidate(r,u,b)

    def test_26_raw_tamper(self):
        r,meter,b,_=candidate();u=meter.seal();r['raw_sha256']='0'*64
        with self.assertRaises(m.Stop):m.audit_f10_candidate(r,u,b)

    def test_27_false_origin(self):
        r,meter,b,_=candidate();u=meter.seal();r['a5_physical_origin_independently_attested']=True
        with self.assertRaises(m.Stop):m.audit_f10_candidate(r,u,b)

    def test_28_output_cap(self):
        r,meter,b,_=candidate();u=meter.seal();b['max_output_bytes']=1
        # Draft profile's hash must match supplied budget, so a new meter is necessary.
        s=FixtureSocket((b'220 Hello\r\n',));meter=m.MeteredSocket(s,b)
        r=f10.receive_control_reply(meter,current_p8_guard=lambda:True,
            limits=f10.Limits(timeout_seconds=b['timeout_seconds'],max_bytes=b['max_recv_bytes'],
                              max_lines=b['max_lines'],read_size=b['read_size']),
            monotonic=TickClock())
        with self.assertRaises(m.Stop):m.audit_f10_candidate(r,meter.seal(),b)

    def test_29_guards_still_mandatory(self):
        s=FixtureSocket();meter=m.MeteredSocket(s,profile())
        with self.assertRaises(f10.Stop):
            f10.receive_control_reply(meter,current_p8_guard=lambda:False,monotonic=TickClock())
        self.assertEqual(s.calls,0)

    def test_30_none_socket_rejected(self):
        with self.assertRaises(m.Stop):m.MeteredSocket(None,profile())


class PrepilotTests(unittest.TestCase):
    def test_31_catalog_inventory_and_no_go(self):
        report=m.prepilot_review(CATALOG_RAW,head=HEAD)
        self.assertEqual(report['status'],'PROFILE_PROPOSED_NOT_CALIBRATED')
        self.assertFalse(report['pilot_completed'])
        self.assertFalse(report['catalog_frozen'])
        self.assertFalse(report['execution_enabled'])
        self.assertEqual(report['physical_measurements'],[])
        self.assertEqual(report['p8'],'NO-GO')

    def test_32_preflight_deterministic(self):
        self.assertEqual(m.prepilot_review(CATALOG_RAW,head=HEAD),
                         m.prepilot_review(CATALOG_RAW,head=HEAD))

    def test_33_catalog_is_not_written(self):
        before=hashlib.sha256(CATALOG_RAW).hexdigest()
        m.prepilot_review(CATALOG_RAW,head=HEAD)
        self.assertEqual(hashlib.sha256(CATALOG_RAW).hexdigest(),before)

    def test_34_catalog_drift_rejected(self):
        cat=json.loads(CATALOG_RAW)
        cat['pilot_completed']=True
        with self.assertRaises(m.Stop):m.prepilot_review(f1.canonical(cat),head=HEAD)

    def test_35_target_family_mutation_rejected(self):
        cat=json.loads(CATALOG_RAW)
        next(f for f in cat['families'] if f['id']=='FTP-T01')['required_supports']=[]
        with self.assertRaises(m.Stop):m.prepilot_review(f1.canonical(cat),head=HEAD)

    def test_36_duplicate_family_rejected(self):
        cat=json.loads(CATALOG_RAW)
        cat['families'][0]['id']='FTP-T01'
        with self.assertRaises(m.Stop):m.prepilot_review(f1.canonical(cat),head=HEAD)

    def test_37_future_head_not_accepted_as_format(self):
        with self.assertRaises(m.Stop):m.prepilot_review(CATALOG_RAW,head='abc')

    def test_38_preflight_profile_bound(self):
        with self.assertRaises(m.Stop):m.prepilot_review(CATALOG_RAW,
                                profile=profile(timeout_seconds=11),head=HEAD)

    def test_39_safe_root_refused_in_report(self):
        original=m.os.geteuid
        try:
            m.os.geteuid=lambda:0
            with self.assertRaises(m.Stop):m.persist(m.prepilot_review(CATALOG_RAW,head=HEAD))
        finally:
            m.os.geteuid=original

    def test_40_report_rejects_unsafe_promotion(self):
        x=m.prepilot_review(CATALOG_RAW,head=HEAD)
        x['pilot_completed']=True
        with self.assertRaises(m.Stop):m.persist(x)


if __name__ == '__main__':
    unittest.main()
