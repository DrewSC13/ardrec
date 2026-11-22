"""R146 independent root installer: test-only ephemeral keys, no root calls."""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import os
import subprocess
import tempfile
import unittest

from ardrec.coordination import r146_independent_install as m

HEAD = 'a'*40
TREE = 'b'*40
BOOT = '0f11a1c3-0990-4000-a123-888888888888'
NOW = datetime(2026,11,22,12,0,15,tzinfo=timezone.utc)
INVENTORY = 'c'*64
AGENT = 'd'*64

class IndependentInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.keys={}
        for key in ('permit','revocation'):
            priv=cls.root/(key+'.key')
            pub=cls.root/(key+'.pub')
            subprocess.run(['/usr/bin/openssl','genpkey','-algorithm','ED25519',
                            '-out',str(priv)],check=True,capture_output=True)
            subprocess.run(['/usr/bin/openssl','pkey','-in',str(priv),'-pubout',
                            '-out',str(pub)],check=True,capture_output=True)
            cls.keys[key]={'private':priv,'public':pub.read_text()}
        cls.b4=(Path(__file__).resolve().parents[2]/'scripts/ardrec_p14_r130_b4_root_guard_v2.py').read_bytes()
        cls.b9=(Path(__file__).resolve().parents[2]/'scripts/ardrec_p14_r130_b9_ftp_executor_v2.py').read_bytes()
        assert m.sha(cls.b4)==m.B4_SHA and m.sha(cls.b9)==m.B9_SHA

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.statement={
            'schema':m.PERMIT_SCHEMA,'session':'aabb112233445566',
            'head':HEAD,'tree':TREE,'inventory_sha256':INVENTORY,
            'source_b4_sha256':m.B4_SHA,'source_b9_sha256':m.B9_SHA,
            'agent_bundle_sha256':AGENT,
            'action':'INSTALL_B4_B9_ONLY','destinations':list(m.DESTINATIONS),
            'boot_id':BOOT,'valid_from':'2026-11-22T12:00:00Z',
            'valid_until':'2026-11-22T12:08:00Z',
            'network_traffic_authorized':False,'one_shot':True,'p8':'NO-GO'}
        self.trust={'schema':m.TRUST_SCHEMA,
             'permit_signer':{'key_id':'r146-permit-key',
                  'public_key_pem':self.keys['permit']['public']},
             'revocation_signer':{'key_id':'r146-revoke-key',
                  'public_key_pem':self.keys['revocation']['public']}}
        self.resign_permit()
        self.revstatement={'schema':m.REVOKE_SCHEMA,'session':self.statement['session'],
             'permit_sha256':m.sha(self.permit_raw),'issued_at':'2026-11-22T12:00:00Z',
             'valid_until':'2026-11-22T12:00:50Z',
             'revoked':False,'reason_code':'no-revocation'}
        self.resign_rev()
        self.other=['%064x'%i for i in range(1,13)]
        self.other_ids=['operational_role_%02d'%i for i in range(12)]

    def sign(self,key,prefix,doc):
        message=self.root/(key+'-message')
        signature=self.root/(key+'-signature')
        message.write_bytes(prefix+m.canonical(doc))
        subprocess.run(['/usr/bin/openssl','pkeyutl','-sign','-inkey',
           str(self.keys[key]['private']),'-rawin','-in',str(message),
           '-out',str(signature)],check=True,capture_output=True)
        envelope={'statement':doc,'signer_key_id':self.trust[key+'_signer']['key_id'],
                  'signature_b64':base64.b64encode(signature.read_bytes()).decode()}
        return m.canonical(envelope)

    def resign_permit(self):
        self.permit_raw=self.sign('permit',m.PREFIX,self.statement)

    def resign_rev(self):
        self.revocation_raw=self.sign('revocation',m.REV_PREFIX,self.revstatement)

    def review(self,**replace):
        args=dict(trust_raw=m.canonical(self.trust),permit_raw=self.permit_raw,
             revocation_raw=self.revocation_raw,head=HEAD,tree=TREE,
             inventory_sha256=INVENTORY,boot_id=BOOT,now=NOW,
             agent_bundle_sha256=AGENT,other_signers=self.other,
             other_signer_ids=self.other_ids)
        args.update(replace)
        return m.verified_install_permit(**args)

    def deny(self,reason=None,**replace):
        with self.assertRaises((ValueError,OSError)) as caught:
            self.review(**replace)
        if reason:
            self.assertIn(reason,str(caught.exception))

    def test_01_valid_signed_install_permit(self):
        result=self.review()
        self.assertEqual(result['permit_sha256'],m.sha(self.permit_raw))
        self.assertEqual(result['agent_bundle_sha256'],AGENT)
        self.assertFalse(result['network_traffic_authorized'])

    def test_02_bad_signature(self):
        doc=m.parse(self.permit_raw)
        doc['signature_b64']=base64.b64encode(bytes(64)).decode()
        self.deny('INVALID_ED25519_SIGNATURE',permit_raw=m.canonical(doc))

    def test_03_permit_expired(self):
        self.deny('INSTALL_WINDOW_EXPIRED',now=datetime(2026,11,22,12,8,0,tzinfo=timezone.utc))

    def test_04_permit_too_short(self):
        self.statement['valid_until']='2026-11-22T12:00:19Z'
        self.resign_permit()
        self.revstatement['permit_sha256']=m.sha(self.permit_raw)
        self.resign_rev()
        self.deny('INSTALL_WINDOW_EXPIRED')

    def test_05_permit_more_than_600s(self):
        self.statement['valid_until']='2026-11-22T12:11:00Z'
        self.resign_permit()
        self.revstatement['permit_sha256']=m.sha(self.permit_raw)
        self.resign_rev()
        self.deny('INSTALL_WINDOW_EXPIRED')

    def test_06_foreign_head(self): self.deny('INSTALL_PERMISSION_SCOPE',head='b'*40)
    def test_07_foreign_tree(self): self.deny('INSTALL_PERMISSION_SCOPE',tree='c'*40)
    def test_08_foreign_boot(self): self.deny('INSTALL_PERMISSION_SCOPE',boot_id='1'*36)
    def test_09_foreign_inventory(self): self.deny('INSTALL_PERMISSION_SCOPE',inventory_sha256='e'*64)
    def test_10_foreign_agent(self): self.deny('INSTALL_PERMISSION_SCOPE',agent_bundle_sha256='e'*64)

    def test_11_network_not_allowed(self):
        self.statement['network_traffic_authorized']=True
        self.resign_permit()
        self.deny('INSTALL_PERMISSION_SCOPE')

    def test_12_root_install_action_only(self):
        self.statement['action']='RUN_FTP'
        self.resign_permit()
        self.deny('INSTALL_PERMISSION_SCOPE')

    def test_13_destinations_exact(self):
        self.statement['destinations']=['/tmp/other']
        self.resign_permit()
        self.deny('INSTALL_PERMISSION_SCOPE')

    def test_14_one_shot_only(self):
        self.statement['one_shot']=False
        self.resign_permit()
        self.deny('INSTALL_PERMISSION_SCOPE')

    def test_15_revoked(self):
        self.revstatement['revoked']=True
        self.resign_rev()
        self.deny('INSTALL_REVOKED')

    def test_16_revocation_stale(self):
        self.revstatement['issued_at']='2026-11-22T11:59:40Z'
        self.resign_rev()
        self.deny('INSTALL_REVOCATION_NOT_FRESH')

    def test_17_revocation_from_future(self):
        self.revstatement['issued_at']='2026-11-22T12:00:19Z'
        self.resign_rev()
        self.deny('INSTALL_REVOCATION_NOT_FRESH')

    def test_18_revocation_unbound(self):
        self.revstatement['permit_sha256']='1'*64
        self.resign_rev()
        self.deny('INSTALL_REVOKED_OR_UNBOUND')

    def test_19_revoke_signer_reuse(self):
        self.trust['revocation_signer']=dict(self.trust['permit_signer'])
        self.deny('INSTALL_SIGNERS_NOT_DISTINCT')

    def test_20_reuse_operational_key(self):
        self.other[0]=m.sha(m.signer(self.trust['permit_signer']))
        self.deny('INSTALL_SIGNER_REUSED_FROM_OPERATIONAL')

    def test_21_duplicate_operational_keys(self):
        self.other[0]=self.other[1]
        self.deny('INSTALL_SIGNER_REUSED_FROM_OPERATIONAL')

    def test_22_less_than_twelve_roles(self):
        self.deny('INSTALL_SIGNER_REUSED_FROM_OPERATIONAL',other_signers=self.other[:-1])

    def test_23_untrusted_pem(self):
        self.trust['permit_signer']['public_key_pem']='untrusted'
        self.deny('PUBLIC_KEY_FORMAT_INVALID')

    def test_24_noncanonical_document(self):
        self.deny('NONCANONICAL_JSON',permit_raw=self.permit_raw.replace(b'\n',b' ',1))

    def test_25_duplicate_json_key(self):
        self.deny('DUPLICATE_JSON_KEY',trust_raw=b'{"schema":"a","schema":"b"}\n')

    def test_49_install_signer_key_id_collides(self):
        self.other_ids[0]='r146-permit-key'
        self.deny('INSTALL_SIGNER_REUSED_FROM_OPERATIONAL')

    def test_50_operational_key_id_duplicate(self):
        self.other_ids[1]=self.other_ids[0]
        self.deny('INSTALL_SIGNER_REUSED_FROM_OPERATIONAL')

class InstallationTransactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo=Path(__file__).resolve().parents[2]
        cls.b4=(cls.repo/'scripts/ardrec_p14_r130_b4_root_guard_v2.py').read_bytes()
        cls.b9=(cls.repo/'scripts/ardrec_p14_r130_b9_ftp_executor_v2.py').read_bytes()
        assert m.sha(cls.b4)==m.B4_SHA and m.sha(cls.b9)==m.B9_SHA

    def setUp(self):
        self.t=tempfile.TemporaryDirectory()
        self.base=Path(self.t.name)
        self.root=self.base/'root';self.root.mkdir(mode=0o700)
        self.root.chmod(0o700)
        self.state=self.base/'state';self.state.mkdir(mode=0o700)
        self.state.chmod(0o700)
        self.allow=True
        self.phases=[]
        self.payload={}
        for role,files in (('B4',m.B4),('B9',m.B9)):
            for filename in files:
                self.payload[role+'/'+filename]=m.canonical({'dummy':role+'/'+filename})
        self.payload['B4/root-controller.py']=self.b4
        self.payload['B9/root-executor.py']=self.b9
        self.payload['B9/lock']=b'ARDREC-R128-B9-ROOT-LOCK\n'
        self.payload['B4/manifest.json']=m.canonical({
            'schema':'ARDREC-R126-B4-ROOT-DENY-SESSION-v1-root-bundle',
            'script_sha256':m.B4_SHA,'guard_sha256':m.GUARD_SHA,
            'approved_head':HEAD,'deny_only':True,'root_install_independent':True})
        self.payload['B9/manifest.json']=m.canonical({
            'schema':'ARDREC-R128-B9-ROOT-ONE-SESSION-FTP-T01-v1-root-bundle',
            'approved_head':HEAD,'script_sha256':m.B9_SHA,
            'r126_deny_controller_sha256':m.B4_SHA,
            'legacy_f3_sha256':m.F3_SHA,'guard_sha256':m.GUARD_SHA,
            'root_staged_independently':True,'automatic_network':False,'p8':'NO-GO'})

    def tearDown(self): self.t.cleanup()

    def grant(self,phase,plan):
        self.phases.append(phase)
        return self.allow

    def publish(self,**kwargs):
        options=dict(state_dir=self.state,root_parent=self.root,
             payload=self.payload,head=HEAD,tree=TREE,boot_id=BOOT,
             authorize=self.grant,install_evidence={
               'permit_sha256':'1'*64,'agent_bundle_sha256':'2'*64,
               'release_sha256':'3'*64,'initial_revocation_sha256':'4'*64})
        options.update(kwargs)
        return m.transact(**options)

    def denied(self,reason,**kwargs):
        with self.assertRaises((ValueError,OSError)) as caught:
            self.publish(**kwargs)
        self.assertIn(reason,str(caught.exception))

    def test_26_valid_durable_install(self):
        self.assertEqual(self.publish()['status'],'INSTALLED_B4_B9_VERIFIED')
        self.assertEqual(self.phases,['before_journal','before_b4','before_b9','before_receipt'])
        self.assertEqual(self.publish()['status'],'ALREADY_INSTALLED_VERIFIED')

    def test_27_after_journal_resume(self):
        self.denied('INJECTED_AFTER_JOURNAL',fail='after_journal')
        self.assertEqual(self.publish()['status'],'INSTALLED_B4_B9_VERIFIED')

    def test_28_before_b4_resume(self):
        self.denied('INJECTED_BEFORE_B4',fail='before_b4')
        self.assertEqual(self.publish()['status'],'INSTALLED_B4_B9_VERIFIED')

    def test_29_after_b4_resume(self):
        self.denied('INJECTED_AFTER_B4',fail='after_b4')
        self.assertEqual(self.publish()['status'],'INSTALLED_B4_B9_VERIFIED')

    def test_30_before_b9_resume(self):
        self.denied('INJECTED_BEFORE_B9',fail='before_b9')
        self.assertEqual(self.publish()['status'],'INSTALLED_B4_B9_VERIFIED')

    def test_31_after_b9_resume(self):
        self.denied('INJECTED_AFTER_B9',fail='after_b9')
        self.assertEqual(self.publish()['status'],'INSTALLED_B4_B9_VERIFIED')

    def test_32_before_receipt_resume(self):
        self.denied('INJECTED_BEFORE_RECEIPT',fail='before_receipt')
        self.assertEqual(self.publish()['status'],'INSTALLED_B4_B9_VERIFIED')

    def test_33_denied_second_step_preserves_b4(self):
        self.denied('INJECTED_AFTER_B4',fail='after_b4')
        self.allow=False
        self.denied('AUTHORIZATION_BEFORE_B9')
        self.assertTrue((self.root/'r126-ftp-session-guard-v1').is_dir())
        self.assertFalse((self.root/'r128-one-session-v2').exists())

    def test_34_existing_target_rejected(self):
        (self.root/'r126-ftp-session-guard-v1').mkdir()
        self.denied('PREEXISTING_SOURCE_WITHOUT_JOURNAL')

    def test_35_tampered_b4_after_partial(self):
        self.denied('INJECTED_AFTER_B4',fail='after_b4')
        file=self.root/'r126-ftp-session-guard-v1'/'grant.json'
        file.write_bytes(b'evil')
        self.denied('FILE_METADATA_INVALID')

    def test_36_source_pin_modified(self):
        self.payload['B4/root-controller.py']+=b'attack'
        self.denied('B4_SOURCE_PIN_INVALID')

    def test_37_b9_pin_modified(self):
        self.payload['B9/root-executor.py']+=b'attack'
        self.denied('B9_SOURCE_PIN_INVALID')

    def test_38_manifest_head_changed(self):
        self.payload['B4/manifest.json']=self.payload['B4/manifest.json'].replace(HEAD.encode(),('b'*40).encode())
        self.denied('B4_MANIFEST_INVALID')

    def test_39_source_symlink_destination(self):
        (self.root/'r126-ftp-session-guard-v1').symlink_to(self.state)
        self.denied('PREEXISTING_SOURCE_WITHOUT_JOURNAL')

    def test_40_unexpected_journal_entry(self):
        (self.state/'unexpected').write_text('x')
        self.denied('INSTALL_JOURNAL_SCOPE_DRIFT')

    def test_41_lock_concurrency(self):
        import fcntl
        lock=self.state/'install.lock'
        fd=os.open(lock,os.O_CREAT|os.O_RDWR,0o600)
        try:
            os.fchmod(fd,0o600)
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            self.denied('CONCURRENT_INSTALL')
        finally:os.close(fd)

    def test_42_invalid_sandbox_permissions(self):
        self.state.chmod(0o755)
        self.denied('DIRECTORY_METADATA_INVALID')

    def test_43_unauthorized_before_journal(self):
        self.allow=False
        self.denied('AUTHORIZATION_BEFORE_JOURNAL')
        self.assertFalse((self.state/'install.json').exists())

    def test_44_journal_replay_drift(self):
        self.denied('INJECTED_AFTER_JOURNAL',fail='after_journal')
        self.payload['B9/f13-handoff.json']=m.canonical({'different':'evidence'})
        self.denied('FILE_BYTES_CHANGED')

    def test_45_receipt_tampered(self):
        self.publish()
        file=self.state/'receipt.json'
        file.write_bytes(b'evil')
        self.denied('FILE_METADATA_INVALID')

    def test_46_b9_without_b4(self):
        self.denied('INJECTED_AFTER_B9',fail='after_b9')
        # Explicit tamper simulates catastrophic loss after physical publication.
        import shutil
        shutil.rmtree(self.root/'r126-ftp-session-guard-v1')
        self.denied('B9_PRESENT_WITHOUT_B4')

    def test_47_both_sources_have_mode_0600(self):
        self.publish()
        for key in ('r126-ftp-session-guard-v1','r128-one-session-v2'):
            folder=self.root/key
            self.assertEqual(folder.stat().st_mode&0o777,0o700)
            for file in folder.iterdir():
                self.assertEqual(file.stat().st_mode&0o777,0o600)

    def test_48_no_root_traffic_capability(self):
        self.assertFalse(m.capabilities()['network_traffic_authorized'])
        self.assertFalse(m.capabilities()['root_install_run_from_checkout'])

    def test_51_signed_evidence_required(self):
        self.denied('SIGNED_INSTALL_EVIDENCE_INVALID',install_evidence={})

    def test_52_signed_evidence_persisted_in_journal(self):
        self.publish()
        plan=m.parse((self.state/'install.json').read_bytes())
        self.assertEqual(plan['install_evidence']['permit_sha256'],'1'*64)
        receipt=m.parse((self.state/'receipt.json').read_bytes())
        self.assertEqual(receipt['install_evidence'],plan['install_evidence'])

    def test_53_recovery_rejects_permit_sha_change(self):
        self.denied('INJECTED_AFTER_B4',fail='after_b4')
        evidence={'permit_sha256':'f'*64,'agent_bundle_sha256':'2'*64,
               'release_sha256':'3'*64,'initial_revocation_sha256':'4'*64}
        self.denied('FILE_BYTES_CHANGED',install_evidence=evidence)

if __name__=='__main__':unittest.main()
