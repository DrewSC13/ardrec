"""Contract and deterministic fake-socket tests; zero network connections."""
import base64
import socket
import unittest
from ardrec.coordination import r115_f10_ftp_a5_transport as m


class Fake:
    family = socket.AF_INET
    type = socket.SOCK_STREAM
    def __init__(self, chunks=(b'220 Hello\r\n',), peer=(m.TARGET_IP,21)):
        self.chunks = list(chunks)
        self.peer = peer
        self.reads = []
        self.timeouts = []
        self.sends = 0
    def getpeername(self): return self.peer
    def settimeout(self, t): self.timeouts.append(t)
    def recv(self, n):
        self.reads.append(n)
        if not self.chunks: return b''
        head = self.chunks.pop(0)
        if isinstance(head, Exception): raise head
        if len(head) > n:
            self.chunks.insert(0,head[n:])
            return head[:n]
        return head
    def send(self, data):
        self.sends += 1
        raise AssertionError('send forbidden')


class F10TransportTests(unittest.TestCase):
    def run_one(self, sock=None, **kwargs):
        s = sock or Fake()
        r = m.receive_control_reply(s, current_p8_guard=lambda: True, **kwargs)
        self.assertEqual(s.sends,0)
        return r, s

    def test_01_220_received(self):
        r,s=self.run_one()
        self.assertEqual(r['ftp_reply_code'],220)
        self.assertTrue(r['greeting_220_observed'])
        self.assertEqual(base64.b64decode(r['raw_b64']),b'220 Hello\r\n')
        self.assertEqual(len(s.reads),1)

    def test_02_421_rejected_as_220(self):
        r,_=self.run_one(Fake([b'421 Service not available\r\n']))
        self.assertFalse(r['greeting_220_observed'])
        self.assertEqual(r['ftp_reply_code'],421)
        self.assertEqual(r['a6_classification'],'ND')

    def test_03_multi_line_reply(self):
        r,_=self.run_one(Fake([b'220-Hello\r\n', b'Interim\r\n220 Ready\r\n']))
        self.assertTrue(r['greeting_220_observed'])
        self.assertEqual(r['recv_calls'],2)

    def test_04_broken_multi_line(self):
        r,_=self.run_one(Fake([b'220-Hello\r\n', b'Other line\r\n', b'']))
        self.assertEqual(r['reply_status'],'CONNECTION_CLOSED')
        self.assertFalse(r['greeting_220_observed'])

    def test_05_incomplete(self):
        r,_=self.run_one(Fake([b'220 Welcome',b'']))
        self.assertEqual(r['reply_status'],'CONNECTION_CLOSED')

    def test_06_invalid_code(self):
        r,_=self.run_one(Fake([b'000 Unsupported\r\n']))
        self.assertEqual(r['reply_status'],'MALFORMED_REPLY')

    def test_07_control_byte(self):
        r,_=self.run_one(Fake([b'220\x00 Hello\r\n']))
        self.assertEqual(r['reply_status'],'MALFORMED_REPLY')

    def test_08_byte_budget(self):
        r,s=self.run_one(Fake([b'220-hello' * 100]),limits=m.Limits(max_bytes=64,read_size=32))
        self.assertEqual(r['reply_status'],'BYTE_LIMIT_REACHED')
        self.assertEqual(r['received_bytes'],64)
        self.assertEqual(s.reads,[32,32])

    def test_09_line_budget(self):
        r,_=self.run_one(Fake([b'220-Hello\r\nabc\r\ndef\r\n']),
                         limits=m.Limits(max_lines=2))
        self.assertEqual(r['reply_status'],'LINE_LIMIT_REACHED')

    def test_10_timeout(self):
        r,_=self.run_one(Fake([socket.timeout()]))
        self.assertEqual(r['reply_status'],'DEADLINE_REACHED')

    def test_11_socket_error(self):
        r,_=self.run_one(Fake([OSError('blocked')]))
        self.assertEqual(r['reply_status'],'SOCKET_READ_ERROR')

    def test_12_guard_denied_before_recv(self):
        s=Fake()
        with self.assertRaisesRegex(m.Stop,'AUTHORITY_GUARD_DENIED'):
            m.receive_control_reply(s,current_p8_guard=lambda:False)
        self.assertEqual(len(s.reads),0)

    def test_13_guard_revoke_after_first_read(self):
        s=Fake([b'220 Ready\r\n'])
        state={'calls':0}
        def g():
            state['calls']+=1
            return state['calls'] < 3
        with self.assertRaisesRegex(m.Stop,'AUTHORITY_GUARD_DENIED'):
            m.receive_control_reply(s,current_p8_guard=g)
        self.assertEqual(len(s.reads),1)

    def test_14_guard_exception(self):
        with self.assertRaisesRegex(m.Stop,'AUTHORITY_GUARD_FAILED'):
            m.receive_control_reply(Fake(),current_p8_guard=lambda:1/0)

    def test_15_missing_guard(self):
        with self.assertRaisesRegex(m.Stop,'AUTHORITY_GUARD_MISSING'):
            m.receive_control_reply(Fake(),current_p8_guard=None)

    def test_16_wrong_ip(self):
        with self.assertRaisesRegex(m.Stop,'PEER_OUT_OF_AUTHORIZED_SCOPE'):
            m.receive_control_reply(Fake(peer=('192.0.2.1',21)),current_p8_guard=lambda:True)

    def test_17_wrong_port(self):
        with self.assertRaisesRegex(m.Stop,'PEER_OUT_OF_AUTHORIZED_SCOPE'):
            m.receive_control_reply(Fake(peer=(m.TARGET_IP,2121)),current_p8_guard=lambda:True)

    def test_18_unconnected(self):
        s=Fake()
        s.getpeername=lambda: (_ for _ in ()).throw(OSError('unconnected'))
        with self.assertRaisesRegex(m.Stop,'SOCKET_NOT_CONNECTED'):
            m.receive_control_reply(s,current_p8_guard=lambda:True)

    def test_19_udp_rejected(self):
        s=Fake();s.type=socket.SOCK_DGRAM
        with self.assertRaisesRegex(m.Stop,'SOCKET_NOT_TCP_STREAM'):
            m.receive_control_reply(s,current_p8_guard=lambda:True)

    def test_20_bool_limits_rejected(self):
        with self.assertRaisesRegex(m.Stop,'LIMIT_TYPE_timeout_seconds'):
            m.receive_control_reply(Fake(),current_p8_guard=lambda:True,
                                    limits=m.Limits(timeout_seconds=True))

    def test_21_large_limits_rejected(self):
        with self.assertRaisesRegex(m.Stop,'BYTE_LIMIT'):
            m.receive_control_reply(Fake(),current_p8_guard=lambda:True,
                                    limits=m.Limits(max_bytes=m.MAX_BYTES+1))

    def test_22_budget_no_access(self):
        s=Fake()
        with self.assertRaisesRegex(m.Stop,'LIMITS_TYPE'):
            m.receive_control_reply(s,current_p8_guard=lambda:True,limits={})
        self.assertEqual(s.reads,[])

    def test_23_never_a6_admission(self):
        r,_=self.run_one()
        self.assertIsNone(r['a7_confirmed_risk'])
        self.assertIsNone(r['a9_published_generation'])
        self.assertFalse(r['a5_physical_origin_independently_attested'])
        self.assertFalse(r['p8_review_performed_by_this_module'])

    def test_24_static_cli_no_connect(self):
        c=m.declared_capabilities()
        self.assertFalse(c['network_connect'])
        self.assertFalse(c['p8_approval'])

    def test_25_invalid_guard_return(self):
        with self.assertRaisesRegex(m.Stop,'AUTHORITY_GUARD_DENIED'):
            m.receive_control_reply(Fake(),current_p8_guard=lambda:1)

    def test_26_denied_before_socket_timeout(self):
        s=Fake()
        with self.assertRaises(m.Stop):
            m.receive_control_reply(s,current_p8_guard=lambda:False)
        self.assertEqual(s.timeouts,[])

    def test_27_no_seconds_reuse(self):
        x=[1.0,1.0,9.0]
        def clock():return x.pop(0) if x else 9.0
        r,_=self.run_one(Fake([b'220 incomplete']),monotonic=clock)
        self.assertIn(r['reply_status'],('DEADLINE_REACHED','CONNECTION_CLOSED'))

    def test_28_schema_has_no_authority(self):
        r,_=self.run_one()
        self.assertEqual(r['network_connections_created_by_this_module'],0)
        self.assertEqual(r['client_bytes_transmitted_by_this_module'],0)
        self.assertEqual(r['a6_classification'],'ND')

if __name__=='__main__':unittest.main()
