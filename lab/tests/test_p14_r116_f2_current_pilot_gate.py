"""R116-F2: current HEAD, real signed scope+pilot, 5/1 physical readback.

Uses ephemeral OpenSSL fixture keys. No host, network, root or VM access.
"""
from __future__ import annotations
import base64
import copy
from datetime import datetime, timezone, timedelta
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f3_f11_authority as f3
from ardrec.coordination import r115_f6_signed_scope_and_activation as f6
from ardrec.coordination import r115_f15_p7_independent_pilot as f15
from ardrec.coordination import r116_f2_current_pilot_gate as m
from test_p14_r115_f11_p8_signed_window import (
    contract,budget,keypair,signed,HEAD,NOW,CATALOG)

ROOT=Path(__file__).resolve().parents[2]
CLI_PATH=ROOT/'scripts/ardrec_p14_r116_f2_current_pilot_gate.py'

def fixture():
    c=contract()
    scope_key,sp=keypair('r116.scope.signer')
    scope_revoke_key,srp=keypair('r116.scope.revoke')
    pilot_key,pp=keypair('r116.pilot.signer')
    pilot_revoke_key,prp=keypair('r116.pilot.revoke')
    st={'schema':f3.AUTH_SCHEMA,'authorization_id':'R116-FTP-T01-AUTH',
        'case_id':c['case_id'],'family_id':'FTP-T01','stage':'DEV',
        'valid_from':c['valid_from'],'valid_until':c['valid_until'],
        'target':copy.deepcopy(c['target']),
        'client_sha256':c['client']['sha256'],'profile_sha256':c['profile']['sha256'],
        'catalog_sha256':c['catalog_sha256'],'limits':copy.deepcopy(c['limits'])}
    auth=signed(st,scope_key,sp,f3.PREFIX_AUTH)
    ar=f1.canonical(auth)
    c['authority']['sha256']=f1.digest(ar)
    cr=f1.canonical(c)
    revst={'schema':f3.REVOCATION_SCHEMA,'authorization_sha256':f1.digest(ar),
        'authorization_id':st['authorization_id'],
        'issued_at':'2026-11-20T16:59:50Z',
        'valid_until':'2026-11-20T17:01:00Z',
        'revoked':False,'reason_code':'CLEAR'}
    srev=signed(revst,scope_revoke_key,srp,f3.PREFIX_REVOKE)
    scope_trust={'schema':f3.TRUST_SCHEMA,'scope_signer':sp,
                 'revocation_signer':srp}
    stmt={'schema':f15.PERMIT_SCHEMA,'pilot_id':'R116-FTP-T01-PILOT',
          'case_id':c['case_id'],'stage':'DEV','family_id':'FTP-T01',
          'head':HEAD,'contract_sha256':f1.digest(cr),
          'scope_authorization_sha256':f1.digest(ar),
          'catalog_sha256':f1.digest(CATALOG),
          'target':copy.deepcopy(c['target']),'budget':budget(),
          'valid_from':'2026-11-20T16:59:50Z',
          'valid_until':'2026-11-20T17:00:25Z',
          'action':'ONE_ISOLATED_FTP_T01_CONTROL_GREETING',
          'pilot_only_no_production_p8':True}
    permit=signed(stmt,pilot_key,pp,f15.PERMIT_PREFIX)
    prst={'schema':f15.REV_SCHEMA,
          'pilot_sha256':f1.digest(f1.canonical(permit)),
          'pilot_id':stmt['pilot_id'],
          'issued_at':'2026-11-20T16:59:55Z',
          'valid_until':'2026-11-20T17:00:25Z',
          'revoked':False,'reason_code':'CLEAR'}
    prev=signed(prst,pilot_revoke_key,prp,f15.REV_PREFIX)
    root={f6.TRUST:f1.canonical(scope_trust),
          f6.REVOCATION:f1.canonical(srev),
          f15.TRUST:f1.canonical({'schema':f15.TRUST_SCHEMA,
                              'pilot_signer':pp,'revocation_signer':prp}),
          f15.REVOCATION:f1.canonical(prev)}
    return {'contract':c,'contract_raw':cr,'auth':auth,'auth_raw':ar,
            'pilot':permit,'pilot_raw':f1.canonical(permit),'root':root,
            'keys':(scope_key,scope_revoke_key,pilot_key,pilot_revoke_key),
            'public':(sp,srp,pp,prp)}

def scope(f,**kwargs):
    return m.current_scope_review(f['contract_raw'],f['auth_raw'],
        catalog_raw=CATALOG,now=NOW,head=HEAD,
        root_loader=lambda path:f['root'][path],**kwargs)

def pilot(f):
    return m.signed_pilot(f['contract_raw'],f['auth_raw'],f['pilot_raw'],
        now=NOW,head=HEAD,catalog_raw=CATALOG,
        scope_loader=lambda path:f['root'][path],
        pilot_loader=lambda path:f['root'][path])

def f1_guard():
    return {'schema':m.GUARD_SCHEMA,
            'states':{'ssh':'RUNNING','runner':'RUNNING','ftp':'RUNNING','smb':'OFF'},
            'policy':{'running':['ftp','runner','ssh'],
                      'active':['ftp','runner_ftp','runner_smb','runner_ssh','ssh'],
                      'absent':['smb'],'active_count':5,'absent_count':1,
                      'allow_traffic':False,'p8':'NO-GO'},
            'deny':'MATCH','host_writes':0,'p8':'NO-GO'}

def preflight(f,**kw):
    def physical(capture,*,now):
        return {'capture_sha256':'a'*64,'active_deny_bindings':5,
                'offline_absent_bindings':1,'root_window_open':False,
                'traffic_authorized':False}
    def boot(p,b):
        return {'boot_receipt_sha256':'b'*64,
                'ftp_boot_attributed_to_ssh_runner_ftp_replay':True,
                'traffic_authorized':False}
    defaults={'head':HEAD,'catalog_raw':CATALOG,'now':NOW,'capture':{'example':'test'},
              'contract_raw':f['contract_raw'],'authorization_raw':f['auth_raw'],
              'pilot_raw':f['pilot_raw'],
              'ftp_plan_dir':Path('/tmp/nonexistent/plan-fixture'),
              'ftp_boot_dir':Path('/tmp/nonexistent/boot-fixture'),
              'root_guard_readback':f1_guard(),
              'scope_loader':lambda p:f['root'][p],
              'pilot_loader':lambda p:f['root'][p],
              'physical_checker':physical,'boot_checker':boot}
    defaults.update(kw)
    return m.preflight(**defaults)

class CurrentHead(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.f=fixture()
    def test_signed_current_scope(self):
        s=scope(self.f)
        self.assertEqual(s[0],'VERDADERO')
        self.assertEqual(s[2],f1.digest(self.f['auth_raw']))
    def test_f6_historical_base_does_not_equal_head(self):
        self.assertNotEqual(f6.BASE,HEAD)
        self.assertEqual(self.f['contract']['source_commit'],HEAD)
    def test_wrong_head_rejects(self):
        with self.assertRaises(m.Stop):m.current_scope_review(
            self.f['contract_raw'],self.f['auth_raw'],catalog_raw=CATALOG,
            now=NOW,head='f'*40,root_loader=lambda p:self.f['root'][p])
    def test_catalog_changed_rejects(self):
        with self.assertRaises(m.Stop):m.current_scope_review(
            self.f['contract_raw'],self.f['auth_raw'],catalog_raw=CATALOG+b'\n',
            now=NOW,head=HEAD,root_loader=lambda p:self.f['root'][p])
    def test_naive_clock_rejects(self):
        with self.assertRaises(m.Stop):m.current_scope_review(
            self.f['contract_raw'],self.f['auth_raw'],catalog_raw=CATALOG,
            now=datetime.now(),head=HEAD,root_loader=lambda p:self.f['root'][p])
    def test_expired_scope_rejects(self):
        with self.assertRaises(m.Stop):m.current_scope_review(
            self.f['contract_raw'],self.f['auth_raw'],catalog_raw=CATALOG,
            now=NOW+timedelta(minutes=5),head=HEAD,
            root_loader=lambda p:self.f['root'][p])
    def test_stale_revocation_rejects(self):
        with self.assertRaises(m.Stop):m.current_scope_review(
            self.f['contract_raw'],self.f['auth_raw'],catalog_raw=CATALOG,
            now=NOW+timedelta(seconds=35),head=HEAD,
            root_loader=lambda p:self.f['root'][p])
    def test_authentication_bad_signature_rejects(self):
        fake=copy.deepcopy(self.f['auth']);fake['signature_b64']=base64.b64encode(b'\0'*64).decode()
        with self.assertRaises(m.Stop):m.current_scope_review(
            self.f['contract_raw'],f1.canonical(fake),catalog_raw=CATALOG,
            now=NOW,head=HEAD,root_loader=lambda p:self.f['root'][p])
    def test_unsigned_scope_rejects(self):
        with self.assertRaises(m.Stop):m.current_scope_review(
            self.f['contract_raw'],b'{}',catalog_raw=CATALOG,
            now=NOW,head=HEAD,root_loader=lambda p:self.f['root'][p])
    def test_missing_trust_rejects(self):
        with self.assertRaises(m.Stop):m.current_scope_review(
            self.f['contract_raw'],self.f['auth_raw'],catalog_raw=CATALOG,
            now=NOW,head=HEAD,root_loader=lambda p: (_ for _ in ()).throw(FileNotFoundError()))
    def test_revoked_scope_returns_false(self):
        f=copy.deepcopy(self.f)
        stmt=f1.load(f['root'][f6.REVOCATION])['statement'];stmt['revoked']=True
        f['root'][f6.REVOCATION]=f1.canonical(signed(stmt,f['keys'][1],f['public'][1],f3.PREFIX_REVOKE))
        self.assertEqual(scope(f)[0],'FALSO')
    def test_wrong_scope_trust_rejects(self):
        f=copy.deepcopy(self.f)
        tr=f1.load(f['root'][f6.TRUST]);tr['revocation_signer']=tr['scope_signer']
        f['root'][f6.TRUST]=f1.canonical(tr)
        with self.assertRaises(m.Stop):scope(f)

class SignedPilot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.f=fixture()
    def test_real_ed25519_pilot_and_scope(self):
        result=pilot(self.f)
        self.assertEqual(result['document_status'],'DOCUMENT_SIGNED')
        self.assertFalse(result['authorized_to_connect_by_module'])
    def test_reject_wrong_pilot_head(self):
        f=copy.deepcopy(self.f); p=f['pilot'];p['statement']['head']='f'*40
        f['pilot_raw']=f1.canonical(p)
        with self.assertRaises(Exception):pilot(f)
    def test_reject_tampered_pilot_signature(self):
        f=copy.deepcopy(self.f); p=f['pilot'];p['signature_b64']=base64.b64encode(b'\x01'*64).decode()
        f['pilot_raw']=f1.canonical(p)
        with self.assertRaises(Exception):pilot(f)
    def test_reject_pilot_revoked(self):
        f=copy.deepcopy(self.f)
        st=f1.load(f['root'][f15.REVOCATION])['statement'];st['revoked']=True
        f['root'][f15.REVOCATION]=f1.canonical(signed(st,f['keys'][3],f['public'][3],f15.REV_PREFIX))
        with self.assertRaises(m.Stop):pilot(f)
    def test_reject_scope_revoked(self):
        f=copy.deepcopy(self.f)
        st=f1.load(f['root'][f6.REVOCATION])['statement'];st['revoked']=True
        f['root'][f6.REVOCATION]=f1.canonical(signed(st,f['keys'][1],f['public'][1],f3.PREFIX_REVOKE))
        with self.assertRaises(Exception):pilot(f)
    def test_reject_stale_pilot_revocation(self):
        f=copy.deepcopy(self.f)
        st=f1.load(f['root'][f15.REVOCATION])['statement'];st['issued_at']='2026-11-20T16:58:00Z'
        f['root'][f15.REVOCATION]=f1.canonical(signed(st,f['keys'][3],f['public'][3],f15.REV_PREFIX))
        with self.assertRaises(Exception):pilot(f)
    def test_reject_missing_pilot_trust(self):
        f=copy.deepcopy(self.f); f['root'].pop(f15.TRUST)
        with self.assertRaises(KeyError):pilot(f)

class FiveOne(unittest.TestCase):
    def test_real_f1_shape(self):m.check_root_guard(f1_guard())
    def test_wrong_count(self):
        a=f1_guard();a['policy']['active_count']=4
        with self.assertRaises(m.Stop):m.check_root_guard(a)
    def test_smb_running(self):
        a=f1_guard();a['states']['smb']='RUNNING'
        with self.assertRaises(m.Stop):m.check_root_guard(a)
    def test_runner_smb_missing(self):
        a=f1_guard();a['policy']['active'].remove('runner_smb')
        with self.assertRaises(m.Stop):m.check_root_guard(a)
    def test_not_all_deny(self):
        a=f1_guard();a['deny']='DRIFT'
        with self.assertRaises(m.Stop):m.check_root_guard(a)
    def test_network_authority_forged(self):
        a=f1_guard();a['policy']['allow_traffic']=True
        with self.assertRaises(m.Stop):m.check_root_guard(a)
    def test_writes_nonzero(self):
        a=f1_guard();a['host_writes']=1
        with self.assertRaises(m.Stop):m.check_root_guard(a)
    def test_bool_count_reject(self):
        a=f1_guard();a['policy']['active_count']=True
        with self.assertRaises(m.Stop):m.check_root_guard(a)
    def test_missing_field(self):
        a=f1_guard();a.pop('deny')
        with self.assertRaises(m.Stop):m.check_root_guard(a)
    def test_offline_stage_refused(self):
        a=f1_guard();a['states']={k:'OFF' for k in a['states']}
        with self.assertRaises(m.Stop):m.check_root_guard(a)

class CompletePreflight(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.f=fixture()
    def test_all_documents_and_boot_snapshot_are_still_nonexecuting(self):
        r=preflight(self.f)
        self.assertTrue(r['physical_preconditions_at_review'])
        self.assertTrue(r['ready_for_separate_root_session_review'])
        self.assertFalse(r['root_execution_permit_issued'])
        self.assertFalse(r['opens_socket'])
        self.assertEqual(r['p8'],'NO-GO')
        self.assertEqual(r['a6'],'ND')
    def test_missing_pilot_rejected(self):
        with self.assertRaises(Exception):preflight(self.f,pilot_raw=None)
    def test_missing_boot_receipts_rejected(self):
        with self.assertRaises(m.Stop):preflight(self.f,ftp_plan_dir=None)
    def test_bad_f1_readback_rejected(self):
        a=f1_guard();a['deny']='DRIFT'
        with self.assertRaises(m.Stop):preflight(self.f,root_guard_readback=a)
    def test_physical_five_binding_rejected(self):
        with self.assertRaises(m.Stop):preflight(self.f,physical_checker=lambda *a,**k:{'active_deny_bindings':4})
    def test_boot_not_proven_rejected(self):
        with self.assertRaises(m.Stop):preflight(self.f,boot_checker=lambda *a,**k:{'ftp_boot_attributed_to_ssh_runner_ftp_replay':False})
    def test_expired_pilot_rejected(self):
        with self.assertRaises(Exception):preflight(self.f,now=NOW+timedelta(minutes=1))
    def test_source_head_mismatch_rejected(self):
        with self.assertRaises(Exception):preflight(self.f,head='f'*40)
    def test_catalog_changed_rejected(self):
        with self.assertRaises(m.Stop):preflight(self.f,catalog_raw=CATALOG+b' ')

class CLI(unittest.TestCase):
    def test_capabilities_nonexecuting(self):
        spec=importlib.util.spec_from_file_location('r116_f2_cli',CLI_PATH)
        cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
        with patch('builtins.print') as out:
            self.assertEqual(cli.main(['--capabilities']),0)
        self.assertIn('NO-GO',str(out.call_args_list))
    def test_capabilities_forbids_evidence(self):
        spec=importlib.util.spec_from_file_location('r116_f2_cli2',CLI_PATH)
        cli=importlib.util.module_from_spec(spec);spec.loader.exec_module(cli)
        with self.assertRaises(SystemExit):cli.main(['--capabilities','--contract','/tmp/bad'])

if __name__=='__main__':unittest.main()
