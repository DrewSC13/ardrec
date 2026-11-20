"""R115-F11 P8 safety, root trust and F10 A5 candidate integrity boundaries."""
import base64
import copy
import datetime as dt
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import subprocess
from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f3_f11_authority as f3
from ardrec.coordination import r115_f10_ftp_a5_transport as f10
from ardrec.coordination import r115_f11_p8_signed_window as m

ROOT = Path(__file__).resolve().parents[2]
CATALOG = (ROOT/'lab/operational-catalog-v1/catalog.json').read_bytes()
NOW = dt.datetime(2026,11,20,17,0,tzinfo=dt.timezone.utc)
HEAD = 'e0bb0bb3dabfb14ff64292bb3b2aa9a76fa3ad2b'


def contract():
    return {'schema':f1.SCHEMA,'case_id':'FTP-T01-R115-DEV',
            'family_id':'FTP-T01','stage':'DEV',
            'created_at':'2026-11-20T16:30:00Z',
            'valid_from':'2026-11-20T16:30:00Z',
            'valid_until':'2026-11-20T17:30:00Z',
            'source_commit':HEAD,'catalog_sha256':f1.digest(CATALOG),
            'target':{'vm':'ardrec-r33-dev-ftp','ip':'10.203.31.2',
                      'port':21,'mac':'52:54:00:00:00:01',
                      'network':'ardrec-r33-dev-net-ftp'},
            **{x:{'id':'R115-REFERENCE','sha256':'a'*64}
               for x in ('client','profile','authority','isolation','service')},
            'limits':{'ordinary_attempts':1,'additional_attempts':0,
                      'timeout_seconds':10,'operation_count':1,'request_count':16,
                      'transfer_bytes':4096,'output_bytes':8192,'memory_mib':64}}


def budget():
    return {'max_connections':1,'ordinary_attempts':1,'additional_attempts':0,
            'timeout_seconds':5,'max_recv_bytes':1024,'max_recv_calls':8,
            'read_size':256,'max_lines':10,'max_output_bytes':2048,
            'memory_mib':32}


class _Ed25519FixtureKey:
    """Only a test fixture: OpenSSL is the existing F3 verification backend.

    No application-side private key is generated, persisted or accepted here.
    Each fixture's ephemeral private key is kept in memory between test signs;
    temporary files are private (0700 directory / 0600 key) and deleted.
    """
    def __init__(self, private_pem):
        self._private_pem = private_pem

    def sign(self, data):
        if type(data) is not bytes:
            raise TypeError('TEST_SIGN_BYTES_REQUIRED')
        with tempfile.TemporaryDirectory(prefix='ardrec-r115-f11-sign-') as dirname:
            folder = Path(dirname)
            key = folder / 'key.pem'
            message = folder / 'message.bin'
            key.write_bytes(self._private_pem)
            key.chmod(0o600)
            message.write_bytes(data)
            signature = subprocess.run(
                ['/usr/bin/openssl','pkeyutl','-sign','-rawin',
                 '-inkey',str(key),'-in',str(message)],
                check=True, capture_output=True, timeout=10).stdout
            if len(signature) != 64:
                raise ValueError('ED25519_TEST_SIGNATURE_NOT_64_BYTES')
            return signature


def keypair(id):
    private = subprocess.run(
        ['/usr/bin/openssl','genpkey','-algorithm','Ed25519'],
        check=True, capture_output=True, timeout=10).stdout
    public = subprocess.run(
        ['/usr/bin/openssl','pkey','-pubout'], input=private,
        check=True, capture_output=True, timeout=10).stdout.decode('ascii')
    return _Ed25519FixtureKey(private), {'key_id':id,'public_key_pem':public}


def signed(statement, key, signer, prefix):
    sig=key.sign(prefix+f1.canonical(statement))
    return {'statement':statement,'signer_key_id':signer['key_id'],
            'signature_b64':base64.b64encode(sig).decode('ascii')}


def fixtures():
    a,ap=keypair('p8.window.signer')
    b,bp=keypair('p8.revocation.signer')
    trust={'schema':m.TRUST_SCHEMA,'window_signer':ap,'revocation_signer':bp}
    c=contract(); auth=b'opaque-signed-authorization'
    stmt={'schema':m.WINDOW_SCHEMA,'window_id':'P8-FTP-T01-ONE',
          'case_id':c['case_id'],'family_id':'FTP-T01','stage':'DEV',
          'head':HEAD,'catalog_sha256':f1.digest(CATALOG),
          'contract_sha256':f1.digest(f1.canonical(c)),
          'scope_authorization_sha256':f1.digest(auth),'target':copy.deepcopy(c['target']),
          'valid_from':'2026-11-20T16:59:30Z',
          'valid_until':'2026-11-20T17:00:30Z',
          'action':'ONE_FTP_CONTROL_GREETING_READ_ONLY',
          'budget':budget(),'network_traffic_requested':True}
    window=signed(stmt,a,ap,m.WINDOW_PREFIX)
    rev_stmt={'schema':m.REV_SCHEMA,'window_sha256':f1.digest(f1.canonical(window)),
              'window_id':stmt['window_id'],'issued_at':'2026-11-20T16:59:40Z',
              'valid_until':'2026-11-20T17:00:40Z',
              'revoked':False,'reason_code':'CURRENT_CLEAR'}
    rev=signed(rev_stmt,b,bp,m.REV_PREFIX)
    root={m.TRUST:f1.canonical(trust),m.REVOCATION:f1.canonical(rev)}
    return c,auth,window,root,a,ap,b,bp


def candidate(raw=b'220 FTP ready\r\n'):
    return {'schema':f10.SCHEMA,'family_id':'FTP-T01',
            'target':{'ip':'10.203.31.2','port':21},
            'transport':'TCP_IPV4_EXISTING_CONNECTION_READ_ONLY',
            'limits':{'timeout_seconds':5,'max_bytes':1024,'max_lines':10,'read_size':256},
            'recv_calls':1,'received_bytes':len(raw),
            'raw_b64':base64.b64encode(raw).decode('ascii'),
            'raw_sha256':hashlib.sha256(raw).hexdigest(),
            'reply_status':'REPLY_COMPLETE','ftp_reply_code':220,
            'greeting_220_observed':True,'socket_opened_by_this_module':False,
            'network_connections_created_by_this_module':0,
            'client_bytes_transmitted_by_this_module':0,
            'a5_physical_origin_independently_attested':False,
            'a6_classification':'ND','p8_review_performed_by_this_module':False}


def signed_review(c,a,w,root,now=NOW):
    with patch.object(m.f6,'scope',return_value=('VERDADERO','SIGNED',f1.digest(a))):
        return m.signed_window_review(f1.canonical(c),a,f1.canonical(w),
                                      now=now,loader=lambda p:root[p],
                                      catalog_raw=CATALOG)


class P8DocumentTests(unittest.TestCase):
    def test_budget_baseline(self):
        self.assertEqual(m.validate_budget(budget(),contract()),budget())

    def test_budget_zero_max(self):
        for name in m.BUDGET_KEYS-{'additional_attempts'}:
            with self.subTest(name=name):
                b=budget();b[name]=0
                with self.assertRaises(m.Stop):m.validate_budget(b,contract())

    def test_budget_bool_and_float(self):
        for name in m.BUDGET_KEYS:
            for invalid in (True,False,1.25,None,'5'):
                with self.subTest(name=name,invalid=str(invalid)):
                    b=budget();b[name]=invalid
                    with self.assertRaises(m.Stop):m.validate_budget(b,contract())

    def test_budget_no_retry_and_one_connection(self):
        for name,value in [('ordinary_attempts',2),('additional_attempts',1),
                           ('max_connections',2)]:
            b=budget();b[name]=value
            with self.assertRaises(m.Stop):m.validate_budget(b,contract())

    def test_budget_contract_caps(self):
        for k,ckey in [('timeout_seconds','timeout_seconds'),
                       ('max_recv_bytes','transfer_bytes'),
                       ('max_output_bytes','output_bytes'),
                       ('memory_mib','memory_mib')]:
            c=contract();c['limits'][ckey]=1
            with self.subTest(k=k),self.assertRaises(m.Stop):m.validate_budget(budget(),c)

    def test_budget_internal_consistency(self):
        b=budget();b['max_recv_calls']=2
        with self.assertRaises(m.Stop):m.validate_budget(b,contract())

    def test_signed_window_documentary_only(self):
        c,a,w,root,*_=fixtures()
        r=signed_review(c,a,w,root)
        self.assertEqual(r['status'],'DOCUMENT_SIGNED')
        self.assertEqual(r['reason'],'DOCUMENT_ONLY_NOT_P8_RELEASE')
        self.assertEqual(r['head'],HEAD)

    def test_scope_missing_does_not_validate_window(self):
        c,a,w,root,*_=fixtures()
        with patch.object(m.f6,'scope',return_value=('ND','MISSING',None)):
            with self.assertRaises(m.Stop):m.signed_window_review(
                f1.canonical(c),a,f1.canonical(w),now=NOW,
                loader=lambda p:root[p],catalog_raw=CATALOG)

    def test_window_expired_future(self):
        c,a,w,root,*_=fixtures()
        for offset in (-90,90):
            with self.subTest(offset=offset),self.assertRaises(m.Stop):
                signed_review(c,a,w,root, NOW+dt.timedelta(seconds=offset))

    def test_window_changed_signed_statement(self):
        c,a,w,root,*_=fixtures();w['statement']['target']['ip']='10.203.99.9'
        with self.assertRaises(m.Stop):signed_review(c,a,w,root)

    def test_window_head_changed(self):
        c,a,w,root,sk,sp,*_=fixtures()
        w['statement']['head']='f'*40
        w=signed(w['statement'],sk,sp,m.WINDOW_PREFIX)
        rev=f1.load(root[m.REVOCATION]);rev['statement']['window_sha256']=f1.digest(f1.canonical(w))
        with self.assertRaises(m.Stop):signed_review(c,a,w,root)

    def test_window_wrong_key(self):
        c,a,w,root,*_=fixtures();w['signer_key_id']='other.key'
        with self.assertRaises(f3.Stop):signed_review(c,a,w,root)

    def test_window_signature_tampered(self):
        c,a,w,root,*_=fixtures();w['signature_b64']=base64.b64encode(b'x'*64).decode()
        with self.assertRaises(f3.Stop):signed_review(c,a,w,root)

    def test_revoked_rejects(self):
        c,a,w,root,_,_,rkey,rpub=fixtures()
        rev=f1.load(root[m.REVOCATION])
        rev['statement']['revoked']=True
        root[m.REVOCATION]=f1.canonical(signed(rev['statement'],rkey,rpub,m.REV_PREFIX))
        self.assertEqual(signed_review(c,a,w,root)['status'],'FALSO')

    def test_revocation_signature_mismatch(self):
        c,a,w,root,*_=fixtures()
        doc=f1.load(root[m.REVOCATION]);doc['statement']['revoked']=True
        root[m.REVOCATION]=f1.canonical(doc)
        with self.assertRaises(f3.Stop):signed_review(c,a,w,root)

    def test_revocation_stale(self):
        c,a,w,root,_,_,rkey,rpub=fixtures()
        d=f1.load(root[m.REVOCATION]);d['statement']['issued_at']='2026-11-20T16:58:00Z'
        root[m.REVOCATION]=f1.canonical(signed(d['statement'],rkey,rpub,m.REV_PREFIX))
        with self.assertRaises(m.Stop):signed_review(c,a,w,root)

    def test_revocation_wrong_window(self):
        c,a,w,root,_,_,rkey,rpub=fixtures()
        d=f1.load(root[m.REVOCATION]);d['statement']['window_sha256']='a'*64
        root[m.REVOCATION]=f1.canonical(signed(d['statement'],rkey,rpub,m.REV_PREFIX))
        with self.assertRaises(m.Stop):signed_review(c,a,w,root)

    def test_distinct_signers(self):
        _,_,_,root,*_=fixtures()
        t=f1.load(root[m.TRUST]);t['revocation_signer']=t['window_signer']
        with self.assertRaises(f3.Stop):m.trust_check(t)

    def test_no_local_root_override(self):
        with self.assertRaises(m.Stop):m._root_file(Path('/tmp/forged-root.json'))


class F10CandidateTests(unittest.TestCase):
    def test_valid_220_is_only_candidate(self):
        r=m.validate_transport_candidate(candidate())
        self.assertTrue(r['observed_220']);self.assertEqual(r['a6'],'ND')
        self.assertFalse(r['transport_origin_attested'])
        self.assertEqual(r['p8'],'NO-GO')

    def test_candidate_changed_bytes(self):
        r=candidate();r['raw_b64']=base64.b64encode(b'220 other\r\n').decode()
        with self.assertRaises(m.Stop):m.validate_transport_candidate(r)

    def test_candidate_wrong_peer(self):
        r=candidate();r['target']['ip']='192.0.2.10'
        with self.assertRaises(m.Stop):m.validate_transport_candidate(r)

    def test_candidate_no_self_authorization(self):
        for field,val in [('a6_classification','POSITIVO_VALIDO'),
                          ('p8_review_performed_by_this_module',True),
                          ('a5_physical_origin_independently_attested',True),
                          ('client_bytes_transmitted_by_this_module',1)]:
            r=candidate();r[field]=val
            with self.subTest(field=field),self.assertRaises(m.Stop):
                m.validate_transport_candidate(r)

    def test_candidate_over_budget(self):
        r=candidate();r['limits']['max_bytes']=4096
        with self.assertRaises(m.Stop):m.validate_transport_candidate(r,max_bytes=1024)

    def test_candidate_bad_complete_code(self):
        r=candidate();r['ftp_reply_code']=421
        with self.assertRaises(m.Stop):m.validate_transport_candidate(r)

    def test_candidate_bad_220_claim(self):
        r=candidate();r['greeting_220_observed']=False
        with self.assertRaises(m.Stop):m.validate_transport_candidate(r)

    def test_candidate_duplicate_base64(self):
        r=candidate();r['raw_b64']+='=='
        with self.assertRaises(m.Stop):m.validate_transport_candidate(r)

    def test_candidate_bool_counts(self):
        r=candidate();r['received_bytes']=True
        with self.assertRaises(m.Stop):m.validate_transport_candidate(r)


class DecisionTests(unittest.TestCase):
    def handoff(self):
        return {'schema':m.f9.SCHEMA,'repo_head':HEAD,
                'catalog_sha256':f1.digest(CATALOG),
                'scope_review':{'status':'ND'},
                'scope_trust':{'status':'ABSENT'},
                'boot_trust':{'status':'ABSENT'}}

    def test_policy_denies_absent(self):
        r=m.policy_report(head=HEAD,catalog_raw=CATALOG,handoff=self.handoff())
        self.assertEqual((r['p8'],r['a5'],r['a6']),('NO-GO','NO-GO','ND'))
        self.assertIn('P7_DRAFT_NOT_EXECUTABLE',r['blockers'])

    def test_even_signed_window_not_go(self):
        h=self.handoff();h['scope_review']['status']='VERDADERO'
        h['scope_trust']['status']='STRUCTURE_MATCH';h['boot_trust']['status']='STRUCTURE_MATCH'
        r=m.policy_report(head=HEAD,catalog_raw=CATALOG,handoff=h,
                          window={'status':'DOCUMENT_SIGNED','head':HEAD})
        self.assertEqual((r['p8'],r['a5'],r['a6']),('NO-GO','NO-GO','ND'))
        self.assertIn('P8_ROOT_EXECUTOR_NOT_IMPLEMENTED',r['blockers'])

    def test_wrong_head_rejected(self):
        with self.assertRaises(m.Stop):m.policy_report(head='b'*40,
                         catalog_raw=CATALOG,handoff=self.handoff())

    def test_draft_catalog_hash_change_rejected(self):
        c=f1.load(CATALOG);c['execution_enabled']=True
        with self.assertRaises(m.Stop):m.policy_report(head=HEAD,
                  catalog_raw=f1.canonical(c),handoff=self.handoff())

    def test_no_network_in_review(self):
        fake=self.handoff()
        with patch.object(m.f9,'evaluate',return_value=fake):
            with patch.object(m.f9,'source_guard',return_value=HEAD):
                r=m.review_current(source_check=lambda:HEAD)
        self.assertEqual(r['network_connections'],0)
        self.assertEqual(r['p8'],'NO-GO')

    def test_partial_inputs_rejected(self):
        with self.assertRaises(m.Stop):
            m.review_current(window_path=Path('/tmp/x'),source_check=lambda:HEAD)

    def test_deterministic_policy(self):
        a=m.policy_report(head=HEAD,catalog_raw=CATALOG,handoff=self.handoff())
        b=m.policy_report(head=HEAD,catalog_raw=CATALOG,handoff=self.handoff())
        self.assertEqual(f1.canonical(a),f1.canonical(b))


if __name__=='__main__':unittest.main()
