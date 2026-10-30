"""Credenciales reales, política explícita y diarios intactos ante rechazo."""
from dataclasses import FrozenInstanceError
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from ardrec.peer_identity import PeerError, PeerIdentity, authenticate_peer
from ardrec.reconciliation import inspect_recovery
from ardrec.reconciliation_transport import ExchangeError, exchange_query
from test_persistence import DurableStore, INITIAL, prepare, reserve
from test_reconciliation import query

def expected():
    return PeerIdentity(os.getpid(), os.geteuid(), os.getegid())

class PeerIdentityTests(unittest.TestCase):
    def pair(self):
        client, peer = socket.socketpair()
        client.settimeout(5); peer.settimeout(5)
        self.addCleanup(client.close); self.addCleanup(peer.close)
        return client, peer

    def test_exact_credentials(self):
        client,_=self.pair()
        self.assertEqual(authenticate_peer(client,expected()),expected())

    def test_no_consumption_or_write(self):
        client,peer=self.pair();peer.sendall(b'x')
        authenticate_peer(client,expected())
        self.assertEqual(client.recv(1),b'x');peer.setblocking(False)
        with self.assertRaises(BlockingIOError):peer.recv(1)

    def test_policy_immutable(self):
        policy=expected()
        with self.assertRaises(FrozenInstanceError):policy.uid=1

    def test_invalid_pid(self):
        for pid in (0,-1,True,1.0,'1',2**31,None):
            with self.subTest(pid=pid),self.assertRaises(PeerError):PeerIdentity(pid,0,0)

    def test_invalid_accounts(self):
        for value in (-1,True,1.0,'0',2**32-1,None):
            for field in ('uid','gid'):
                with self.subTest(field=field,value=value),self.assertRaises(PeerError):
                    PeerIdentity(**{'pid':1,'uid':0,'gid':0,field:value})

    def mismatch(self,policy):
        client,_=self.pair()
        with self.assertRaisesRegex(PeerError,'peer_identity_mismatch'):authenticate_peer(client,policy)

    def test_pid_mismatch(self):self.mismatch(PeerIdentity(os.getpid()+1,os.geteuid(),os.getegid()))
    def test_uid_mismatch(self):self.mismatch(PeerIdentity(os.getpid(),os.geteuid()^1,os.getegid()))
    def test_gid_mismatch(self):self.mismatch(PeerIdentity(os.getpid(),os.geteuid(),os.getegid()^1))

    def test_policy_required(self):
        client,_=self.pair()
        for value in (None,{'pid':os.getpid()},(os.getpid(),os.geteuid(),os.getegid())):
            with self.assertRaisesRegex(PeerError,'peer_identity_required'):authenticate_peer(client,value)

    def test_platform_unsupported(self):
        client,_=self.pair()
        with patch('ardrec.peer_identity.sys.platform','other'),self.assertRaisesRegex(PeerError,'unsupported'):
            authenticate_peer(client,expected())

    def test_wrong_socket_family(self):
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as connection,self.assertRaisesRegex(PeerError,'unix_stream_required'):
            authenticate_peer(connection,expected())

    def test_wrong_socket_type(self):
        with socket.socket(socket.AF_UNIX,socket.SOCK_DGRAM) as connection,self.assertRaisesRegex(PeerError,'unix_stream_required'):
            authenticate_peer(connection,expected())

    def test_unconnected_socket(self):
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection,self.assertRaisesRegex(PeerError,'unavailable'):
            authenticate_peer(connection,expected())

    def test_closed_socket(self):
        client,_=self.pair();client.close()
        with self.assertRaisesRegex(PeerError,'unavailable'):authenticate_peer(client,expected())

    def test_kernel_error_has_no_fallback(self):
        client,_=self.pair()
        with patch.object(socket.socket,'getsockopt',side_effect=OSError('denied')),self.assertRaisesRegex(PeerError,'unavailable'):
            authenticate_peer(client,expected())

    def test_short_credential_record(self):
        client,_=self.pair()
        with patch.object(socket.socket,'getsockopt',side_effect=[socket.SOCK_STREAM,b'bad']),self.assertRaisesRegex(PeerError,'invalid'):
            authenticate_peer(client,expected())

    def test_missing_policy_closes_without_touching_store(self):
        client,peer=self.pair()
        with self.assertRaisesRegex(ExchangeError,'peer_identity_required'):exchange_query(object(),client)
        self.assertEqual(client.fileno(),-1);self.assertEqual(peer.recv(1),b'')

    def test_rejected_peer_preserves_durable_query_and_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'store'
            with DurableStore.create(path,INITIAL) as store:
                prepare(store);reserve(store);query(store)
                before={p.relative_to(path):p.read_bytes() for p in path.rglob('*') if p.is_file()}
                decision=inspect_recovery(store);client,peer=self.pair()
                with self.assertRaisesRegex(ExchangeError,'peer_identity_mismatch'):
                    exchange_query(store,client,expected_peer=PeerIdentity(os.getpid()+1,os.geteuid(),os.getegid()))
                self.assertEqual(peer.recv(1),b'');self.assertEqual(inspect_recovery(store),decision)
                self.assertFalse(decision.new_execution_authorized)
                self.assertEqual(before,{p.relative_to(path):p.read_bytes() for p in path.rglob('*') if p.is_file()})

    def test_connected_child_identity_not_parent(self):
        with tempfile.TemporaryDirectory() as directory,socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
            path=str(Path(directory)/'socket');listener.bind(path);listener.listen(1);listener.settimeout(5)
            child=subprocess.Popen([sys.executable,'-c',
                'import socket,sys; s=socket.socket(socket.AF_UNIX); s.settimeout(5); s.connect(sys.argv[1]); s.recv(1)',path],
                stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                connection,_=listener.accept()
                with connection:
                    connection.settimeout(5)
                    identity=PeerIdentity(child.pid,os.geteuid(),os.getegid())
                    self.assertEqual(authenticate_peer(connection,identity),identity)
                    with self.assertRaisesRegex(PeerError,'mismatch'):authenticate_peer(connection,expected())
                    connection.sendall(b'x')
                out,err=child.communicate(timeout=5);self.assertEqual(child.returncode,0,(out,err))
            finally:
                if child.poll() is None:child.kill()
                child.communicate(timeout=5)

    def test_inherited_socket_preserves_creator_credentials(self):
        client,peer=self.pair()
        child=subprocess.Popen([sys.executable,'-c',
            'import socket; s=socket.socket(fileno=0); s.settimeout(5); s.sendall(b"x"); s.recv(1)'],
            stdin=peer,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        peer.close()
        try:
            self.assertEqual(client.recv(1),b'x');self.assertEqual(authenticate_peer(client,expected()),expected())
            with self.assertRaisesRegex(PeerError,'mismatch'):authenticate_peer(client,PeerIdentity(child.pid,os.geteuid(),os.getegid()))
            client.sendall(b'x');child.communicate(timeout=5);self.assertEqual(child.returncode,0)
        finally:
            if child.poll() is None:child.kill()
            child.communicate(timeout=5)

if __name__=='__main__':unittest.main(verbosity=2)
