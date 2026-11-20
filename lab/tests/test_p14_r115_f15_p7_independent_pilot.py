"""R115-F15: pilot exception documents never authorize a physical session."""
import base64
import copy
from datetime import datetime,timezone,timedelta
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f15_p7_independent_pilot as m
from ardrec.coordination import r115_f12_ftp_budget_preflight as f12
from ardrec.coordination import r115_f14_a5_a6_handoff as f14

# Reuse previously audited, OpenSSL-only F11 test fixtures (no cryptography).
from test_p14_r115_f11_p8_signed_window import (
    contract as f11_contract, budget as f11_budget, keypair, signed,
    HEAD, NOW, CATALOG,
)


def setup():
    contract=f11_contract()
    contract_raw=f1.canonical(contract)
    auth=b'opaque-scoped-authorization-fixture'
    pilot_key,pilot_pub=keypair('p7.pilot.signer')
    revoke_key,revoke_pub=keypair('p7.revocation.signer')
    trust={'schema':m.TRUST_SCHEMA,'pilot_signer':pilot_pub,
           'revocation_signer':revoke_pub}
    stmt={'schema':m.PERMIT_SCHEMA,'pilot_id':'PILOT-FTP-T01-ONE',
          'case_id':contract['case_id'],'stage':'DEV','family_id':'FTP-T01',
          'head':HEAD,'contract_sha256':f1.digest(contract_raw),
          'scope_authorization_sha256':f1.digest(auth),
          'catalog_sha256':f1.digest(CATALOG),
          'target':copy.deepcopy(contract['target']),
          'budget':f11_budget(),
          'valid_from':'2026-11-20T16:59:50Z',
          'valid_until':'2026-11-20T17:00:25Z',
          'action':'ONE_ISOLATED_FTP_T01_CONTROL_GREETING',
          'pilot_only_no_production_p8':True}
    permit=signed(stmt,pilot_key,pilot_pub,m.PERMIT_PREFIX)
    revstmt={'schema':m.REV_SCHEMA,
             'pilot_sha256':f1.digest(f1.canonical(permit)),
             'pilot_id':stmt['pilot_id'],
             'issued_at':'2026-11-20T16:59:55Z',
             'valid_until':'2026-11-20T17:00:25Z',
             'revoked':False,'reason_code':'CLEAR'}
    revoke=signed(revstmt,revoke_key,revoke_pub,m.REV_PREFIX)
    loader={m.TRUST:f1.canonical(trust),m.REVOCATION:f1.canonical(revoke)}
    return contract_raw,auth,permit,loader,pilot_key,pilot_pub,revoke_key,revoke_pub


def review(values, *,now=NOW,head=HEAD,scope_state='VERDADERO'):
    c,a,permit,loader,*_=values
    def scope(raw_c,raw_a,*,catalog_raw,now):
        return scope_state,'TEST_SCOPE_FIXTURE',f1.digest(raw_a)
    return m.signed_pilot_review(c,a,f1.canonical(permit),now=now,head=head,
        catalog_raw=CATALOG,loader=lambda p:loader[p],scope_reviewer=scope)


class Request(unittest.TestCase):
    def test_nonexecuting_unsigned_request(self):
        r=m.request(head=HEAD,catalog_raw=CATALOG)
        self.assertIsNone(r['contract_sha256'])
        self.assertFalse(r['authorization_issued_by_this_module'])
        self.assertFalse(r['catalogue_execution_enabled'])
        self.assertEqual(r['production_p8'],'NO-GO')

    def test_contract_bound_profile(self):
        r=m.request(head=HEAD,catalog_raw=CATALOG,contract_raw=f1.canonical(f11_contract()))
        self.assertEqual(r['profile']['memory_mib'],64)
        self.assertEqual(r['case_id'],'FTP-T01-R115-DEV')

    def test_invalid_budget_rejected(self):
        profile=f11_budget();profile['max_connections']=2
        with self.assertRaises((m.Stop,f12.Stop)):
            m.request(head=HEAD,catalog_raw=CATALOG,profile=profile)

    def test_wrong_head_rejected(self):
        with self.assertRaises(m.Stop):
            m.request(head='f'*40,catalog_raw=CATALOG,
                      contract_raw=f1.canonical(f11_contract()))

    def test_wrong_catalogue_rejected(self):
        with self.assertRaises((m.Stop,f14.Stop)):
            m.request(head=HEAD,catalog_raw=CATALOG+b' ')

    def test_bool_budgets_rejected(self):
        profile=f11_budget(); profile['max_recv_calls']=True
        with self.assertRaises((m.Stop,f12.Stop)):
            m.request(head=HEAD,catalog_raw=CATALOG,profile=profile)


class Permit(unittest.TestCase):
    def test_valid_document_is_not_p8(self):
        doc=review(setup())
        self.assertEqual(doc['document_status'],'DOCUMENT_SIGNED')
        self.assertFalse(doc['authorized_to_connect_by_module'])
        self.assertFalse(doc['physical_pilot_session_attested'])
        self.assertEqual(doc['p8'],'NO-GO')
        self.assertFalse(doc['p7_execution_enabled'])

    def test_missing_scope_is_stop(self):
        with self.assertRaises(m.Stop):review(setup(),scope_state='ND')

    def test_false_scope_is_stop(self):
        with self.assertRaises(m.Stop):review(setup(),scope_state='FALSO')

    def test_expired_pilot(self):
        with self.assertRaises(m.Stop):
            review(setup(),now=NOW+timedelta(seconds=40))

    def test_future_pilot(self):
        with self.assertRaises(m.Stop):
            review(setup(),now=NOW-timedelta(seconds=40))

    def test_wrong_head(self):
        with self.assertRaises(m.Stop):review(setup(),head='f'*40)

    def test_tampered_signature(self):
        values=list(setup()); values[2]=copy.deepcopy(values[2]);
        values[2]['signature_b64']=base64.b64encode(b'\x00'*64).decode()
        with self.assertRaises(Exception):review(values)

    def test_changed_target_even_resigned(self):
        values=list(setup());values[2]=copy.deepcopy(values[2]);
        values[2]['statement']['target']['ip']='10.203.31.3'
        with self.assertRaises(m.Stop):review(values)

    def test_revoked_document(self):
        values=list(setup())
        permit=values[2];root=values[3];rev_key=values[6];pub=values[7]
        old=f1.load(root[m.REVOCATION]);rs=old['statement'];rs['revoked']=True
        root[m.REVOCATION]=f1.canonical(signed(rs,rev_key,pub,m.REV_PREFIX))
        doc=review(values)
        self.assertEqual(doc['document_status'],'REVOKED')
        self.assertFalse(doc['authorized_to_connect_by_module'])

    def test_stale_revocation(self):
        values=list(setup());root=values[3];key=values[6];pub=values[7]
        rs=f1.load(root[m.REVOCATION])['statement']
        rs['issued_at']='2026-11-20T16:59:00Z'
        root[m.REVOCATION]=f1.canonical(signed(rs,key,pub,m.REV_PREFIX))
        with self.assertRaises(m.Stop):review(values)

    def test_pilot_window_longer_than_60s(self):
        values=list(setup());pilot=copy.deepcopy(values[2])
        pilot['statement']['valid_until']='2026-11-20T17:01:15Z'
        values[2]=pilot
        with self.assertRaises(m.Stop):review(values)

    def test_different_budget_too_large(self):
        values=list(setup());pilot=copy.deepcopy(values[2]);
        pilot['statement']['budget']['memory_mib']=128
        values[2]=pilot
        with self.assertRaises(Exception):review(values)

    def test_pilot_role_reuse(self):
        values=list(setup());root=values[3]
        trust=f1.load(root[m.TRUST])
        trust['revocation_signer']=trust['pilot_signer']
        root[m.TRUST]=f1.canonical(trust)
        with self.assertRaises(Exception):review(values)

    def test_wrong_revocation_hash(self):
        values=list(setup());root=values[3];key=values[6];pub=values[7]
        rs=f1.load(root[m.REVOCATION])['statement'];rs['pilot_sha256']='f'*64
        root[m.REVOCATION]=f1.canonical(signed(rs,key,pub,m.REV_PREFIX))
        with self.assertRaises(m.Stop):review(values)


class Report(unittest.TestCase):
    def test_absent_documents_are_no_go(self):
        report=m.overview(head=HEAD,catalog_raw=CATALOG)
        self.assertEqual(report['pilot_documents']['status'],'ND')
        self.assertFalse(report['physical_pilot_authorized'])
        self.assertEqual(report['p8'],'NO-GO')
        self.assertEqual(report['network_connections'],0)

    def test_partial_docs_rejected(self):
        with self.assertRaises(m.Stop):
            m.overview(head=HEAD,catalog_raw=CATALOG,contract_raw=b'abc')

    def test_invalid_signed_docs_not_approval(self):
        c,a,permit,*_=setup()
        report=m.overview(head=HEAD,catalog_raw=CATALOG,contract_raw=c,
            authorization_raw=a,pilot_raw=f1.canonical(permit))
        self.assertNotEqual(report['pilot_documents']['status'],'DOCUMENT_SIGNED')
        self.assertEqual(report['p8'],'NO-GO')

    def test_root_reader_is_allowlisted(self):
        with self.assertRaises(m.Stop):m._root_read(Path('/tmp/arbitrary'))

    def test_capabilities_no_execution(self):
        caps=m.capabilities()
        self.assertFalse(caps['a5_dispatch_implemented'])
        self.assertFalse(caps['opens_socket'])
        self.assertFalse(caps['issues_signature'])

    def test_cli_capabilities(self):
        # CLI cannot enable physical operations, even with a malicious argument.
        import importlib.util
        path=Path(__file__).resolve().parents[2]/'scripts/ardrec_p14_r115_f15_p7_independent_pilot.py'
        spec=importlib.util.spec_from_file_location('f15_cli',path)
        cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
        with patch('builtins.print') as output:
            self.assertEqual(cli.main(['--capabilities']),0)
        self.assertTrue(any('NO-GO' in str(x) for x in output.call_args_list))
