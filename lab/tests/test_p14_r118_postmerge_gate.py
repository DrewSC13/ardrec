"""R118: tests de autenticidad, frescura, identidad y denegación, sin VM/red."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from ardrec.coordination import r118_postmerge_gate as g

ROOT = Path(__file__).resolve().parents[2]
CLOSURE = (ROOT/'lab/operational-controller/r117-f5b-physical-closure-v3.json').read_bytes()
NOW = datetime(2026, 11, 21, 16, 0, 0, tzinfo=timezone.utc)
HEAD = 'cdeb6ab831c473349f03a1d75a56c034bb951e5b'


def stamp(ts):
    return ts.strftime('%Y-%m-%dT%H:%M:%SZ')


class PureGate(unittest.TestCase):
    def setUp(self):
        self.closure = CLOSURE
        self.sources = {s:(s+'\n').encode() for s in g.SOURCES}
        self.lineage = {
            'schema':g.SCHEMA,
            'candidate_head':g.closure_status(CLOSURE)['candidate_head'],
            'candidate_sha256':g.closure_status(CLOSURE)['candidate_sha256'],
            'integrated_head':HEAD,
            'source_sha256':{s:g.sha(v) for s,v in self.sources.items()},
            'issued_at':stamp(NOW-timedelta(seconds=30)),
            'valid_until':stamp(NOW+timedelta(seconds=60)),
            'scope':'SOURCE_CONTINUITY_ONLY',
            'p8':'NO-GO','boot_authorized':False,'network_authorized':False,
        }
        self.approval = {'statement':self.lineage, 'signature_b64':base64.b64encode(b'A'*64).decode()}
        self.revocation = {'statement':{
            'schema':g.REVOKE_SCHEMA,'lineage_sha256':g.sha(g.canonical(self.approval)),
            'integrated_head':HEAD,
            'issued_at':stamp(NOW-timedelta(seconds=10)),
            'valid_until':stamp(NOW+timedelta(seconds=50)),
            'revoked':False,'p8':'NO-GO',
        },'signature_b64':base64.b64encode(b'B'*64).decode()}

    def verify(self, **updates):
        args={'closure_raw':self.closure,'integrated_head':HEAD,
              'source_bytes':self.sources,
              'approval_raw':g.canonical(self.approval),
              'revocation_raw':g.canonical(self.revocation),
              'approval_public':b'first-root-pinned',
              'revocation_public':b'second-root-pinned',
              'now':NOW,'verifier':lambda *_:None}
        args.update(updates)
        return g.verify_lineage(**args)

    def expect(self, code, **kw):
        with self.assertRaises(g.Stop) as exc:
            self.verify(**kw)
        self.assertEqual(str(exc.exception),code)

    def test_closure_is_source_only(self):
        c=g.closure_status(CLOSURE)
        self.assertEqual(c['p8'],'NO-GO')
        self.assertFalse(c['boot_authorized'])
        self.assertFalse(c['network_authorized'])

    def test_valid_lineage_grants_no_operation(self):
        doc=self.verify()
        self.assertTrue(doc['source_continuity_verified'])
        self.assertFalse(doc['host_installation_currently_verified'])
        self.assertFalse(doc['runtime_started'])
        self.assertFalse(doc['boot_authorized'])
        self.assertFalse(doc['network_authorized'])
        self.assertEqual(doc['p8'],'NO-GO')

    def test_duplicate_json_fails_closed(self):
        with self.assertRaisesRegex(g.Stop,'DUPLICATE_JSON_FIELD'):
            g.strict(b'{"x":1,"x":2}\n')

    def test_noncanonical_fails_closed(self):
        with self.assertRaisesRegex(g.Stop,'NONCANONICAL_JSON'):
            g.strict(b'{"b":1, "a":2}\n')

    def test_no_signature_is_rejected(self):
        self.approval['signature_b64']=''
        self.expect('SIGNATURE_ENCODING')

    def test_changed_main_is_rejected(self):
        self.expect('LINEAGE_SCOPE',integrated_head='f'*40)

    def test_changed_release_candidate_fails(self):
        self.lineage['candidate_sha256']='a'*64
        self.expect('LINEAGE_SCOPE')

    def test_changed_source_fails(self):
        src=dict(self.sources)
        src[g.SOURCES[0]]=b'new unapproved bytes'
        self.expect('SOURCE_MISMATCH',source_bytes=src)

    def test_incomplete_source_set_fails(self):
        self.expect('SOURCE_SET',source_bytes={g.SOURCES[0]:b'only'})

    def test_too_old_or_future_grant_fails(self):
        self.lineage['valid_until']=stamp(NOW-timedelta(seconds=1))
        self.expect('FRESHNESS_REQUIRED')

    def test_very_long_grant_fails(self):
        self.lineage['valid_until']=stamp(NOW+timedelta(hours=1))
        self.expect('FRESHNESS_REQUIRED')

    def test_revoked_fails_closed(self):
        self.revocation['statement']['revoked']=True
        self.expect('LINEAGE_REVOKED_OR_MISMATCH')

    def test_revocation_too_old_fails(self):
        self.revocation['statement']['issued_at']=stamp(NOW-timedelta(seconds=91))
        self.revocation['statement']['valid_until']=stamp(NOW+timedelta(seconds=5))
        self.expect('FRESHNESS_REQUIRED')

    def test_revocation_wrong_head_fails(self):
        self.revocation['statement']['integrated_head']='a'*40
        self.expect('LINEAGE_REVOKED_OR_MISMATCH')

    def test_same_signing_identity_fails(self):
        self.expect('TRUST_IDENTITIES_NOT_DISTINCT',
                    revocation_public=b'first-root-pinned')

    def test_invalid_signature_fails(self):
        def reject(*_):
            raise ValueError('bad signature')
        self.expect('LINEAGE_SIGNATURE_INVALID',verifier=reject)

    def test_revocation_signature_invalid_fails(self):
        n=[0]
        def second_reject(*_):
            n[0]+=1
            if n[0]==2: raise ValueError('invalid revocation signature')
        self.expect('REVOCATION_SIGNATURE_INVALID',verifier=second_reject)

    def test_edited_closure_fails(self):
        c=g.closure_status(self.closure)
        c['network_authorized']=True
        self.expect('CLOSURE_DIGEST_CHANGED',closure_raw=g.canonical(c))

    def test_null_source_fails(self):
        s=dict(self.sources)
        s[g.SOURCES[0]]=None
        self.expect('SOURCE_BYTES_'+g.SOURCES[0],source_bytes=s)

    def test_nonfinite_rejected(self):
        with self.assertRaisesRegex(g.Stop,'NONFINITE_JSON'):
            g.strict(b'{"x":NaN}\n')


@unittest.skipUnless(os.name == 'posix' and hasattr(os,'memfd_create') and
                     shutil.which('openssl'), 'OpenSSL Ed25519 requiere Linux')
class AuthenticSignature(unittest.TestCase):
    """Prueba real del algoritmo Ed25519, sin material persistente/versionado."""

    def test_real_openssl_signed_lineage_and_independent_revocation(self):
        example=PureGate()
        example.setUp()
        with tempfile.TemporaryDirectory(prefix='ardrec-r118-crypto-') as tmp:
            folder=Path(tmp)
            keys=[]
            for n in (1,2):
                key=folder/f'private{n}.pem'
                pub=folder/f'public{n}.pem'
                subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',str(key)],
                               capture_output=True,check=True,timeout=10)
                subprocess.run(['openssl','pkey','-in',str(key),'-pubout','-out',str(pub)],
                               capture_output=True,check=True,timeout=10)
                keys.append((key,pub))
            for env,prefix,key in ((example.approval,g.PREFIX,keys[0][0]),
                                   (example.revocation,g.REVOCATION_PREFIX,keys[1][0])):
                msg=folder/'message.bin'
                sig=folder/'signature.bin'
                msg.write_bytes(prefix+g.canonical(env['statement']))
                subprocess.run(['openssl','pkeyutl','-sign','-rawin','-inkey',str(key),
                                '-in',str(msg),'-out',str(sig)],
                               capture_output=True,check=True,timeout=10)
                env['signature_b64']=base64.b64encode(sig.read_bytes()).decode()
                if env is example.approval:
                    example.revocation['statement']['lineage_sha256']=g.sha(g.canonical(env))
            proof=example.verify(approval_public=keys[0][1].read_bytes(),
                                 revocation_public=keys[1][1].read_bytes(),
                                 verifier=g.crypto._ed25519_verify)
            self.assertTrue(proof['source_continuity_verified'])
            self.assertFalse(proof['boot_authorized'])


if __name__ == '__main__':
    unittest.main()
