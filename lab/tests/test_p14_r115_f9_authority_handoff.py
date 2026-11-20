"""Strict, non-authorizing F9 external handoff tests."""
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from unittest import TestCase, mock
import tempfile

from ardrec.coordination import r115_f9_authority_handoff as m
from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r115_f3_f11_authority as f3
from ardrec.coordination import r115_f6_signed_scope_and_activation as f6
from ardrec.coordination import r115_f7_controlled_boot as f7

UTC = datetime(2026,11,20,15,0,tzinfo=timezone.utc)
HEAD = 'a017079c8ce60c82f3035d09b0eb5249377bde75'
CATALOG = f6.CATALOG.read_bytes()
BASE = {'status':'ABSENT','reason':'ROOT_TRUST_NOT_PROVISIONED','sha256':None}
SCOPE = {'status':'ND','reason':'CONTRACT_AND_SIGNED_SCOPE_NOT_SUPPLIED',
         'contract_sha256':None,'authorization_sha256':None}

class F9HandoffTests(TestCase):
    def test_01_requires_git_sha(self):
        with self.assertRaisesRegex(m.Stop,'BAD_SOURCE_HEAD'):
            m.make_report('x',CATALOG,BASE,BASE,SCOPE,now=UTC)

    def test_02_real_catalogue_contract_pin(self):
        out=m.make_report(HEAD,CATALOG,BASE,BASE,SCOPE,now=UTC)
        self.assertEqual(out['catalog_sha256'],f1.digest(CATALOG))
        self.assertEqual(out['catalog_status'],'P7_DRAFT_UNCALIBRATED_NOT_EXECUTABLE')

    def test_03_boot_sequenced(self):
        r=m.make_report(HEAD,CATALOG,BASE,BASE,SCOPE,now=UTC)
        self.assertEqual([(x['role'],x['predecessor']) for x in r['boot_roles']],
                         [('ssh',None),('runner','ssh'),('ftp','runner')])

    def test_04_does_not_authorize_p8_when_scope_looks_valid(self):
        scope=dict(SCOPE,status='VERDADERO')
        r=m.make_report(HEAD,CATALOG,BASE,BASE,scope,now=UTC)
        self.assertEqual((r['a5'],r['a6'],r['p8']),('NO-GO','ND','NO-GO'))
        self.assertFalse(r['traffic_authorized'])
        self.assertFalse(r['p7_executable'])
        self.assertTrue(all(x=='ND' for x in r['a3'].values()))

    def test_05_absent_root(self):
        r=m.trust_report(f6.TRUST,lambda _: (_ for _ in ()).throw(FileNotFoundError()),m._scope_trust,role='scope')
        self.assertEqual(r['status'],'ABSENT')

    def test_06_permission_denied(self):
        r=m.trust_report(f7.PERMIT_TRUST,lambda _: (_ for _ in ()).throw(PermissionError()),m._boot_trust,role='boot')
        self.assertEqual(r['status'],'ND')
        self.assertEqual(r['reason'],'ROOT_TRUST_NOT_READABLE')

    def test_07_other_os_failure(self):
        r=m.trust_report(f6.TRUST,lambda _: (_ for _ in ()).throw(OSError()),m._scope_trust,role='scope')
        self.assertEqual(r['reason'],'ROOT_TRUST_FILE_UNVERIFIABLE')

    def test_08_reject_unexpected_root(self):
        with self.assertRaisesRegex(m.Stop,'UNALLOWED_ROOT_PATH'):
            m.trust_report(Path('/tmp/fake-root.json'),lambda _:b'{}',m._scope_trust,role='scope')

    def test_09_reject_malformed_trust(self):
        r=m.trust_report(f6.TRUST,lambda _:b'{}',m._scope_trust,role='scope')
        self.assertEqual(r['status'],'REJECTED')

    def test_10_boot_schema_mismatch(self):
        r=m.trust_report(f7.PERMIT_TRUST,lambda _:f1.canonical({'schema':'bad','boot_signer':{},'revocation_signer':{}}),m._boot_trust,role='boot')
        self.assertEqual(r['status'],'REJECTED')

    def test_11_trust_matches_only_structure(self):
        with mock.patch.object(m,'_scope_trust',return_value=None):
            r=m.trust_report(f6.TRUST,lambda _:f1.canonical({'x':1}),m._scope_trust,role='scope')
        self.assertEqual(r['status'],'STRUCTURE_MATCH')
        self.assertIn('ONLY',r['reason'])

    def test_12_missing_scope(self):
        self.assertEqual(m.scope_review(None,None,now=UTC),SCOPE)

    def test_13_reject_partial_scope(self):
        with self.assertRaisesRegex(m.Stop,'PARTIAL_SCOPE_DOCUMENTS'):
            m.scope_review(b'{}',None,now=UTC)

    def test_14_reject_invalid_scope_inputs(self):
        with self.assertRaisesRegex(m.Stop,'SCOPE_INPUT_TYPE'):
            m.scope_review('bad',b'{}',now=UTC)

    def test_15_scope_delegates_to_f6(self):
        fake=lambda a,b,**k:('VERDADERO','SIGNED_SCOPE_ROOT_ANCHORED_AT_REVIEW_ONLY','1'*64)
        r=m.scope_review(b'contract',b'authorization',now=UTC,reviewer=fake,catalog_raw=CATALOG)
        self.assertEqual(r['status'],'VERDADERO')
        self.assertEqual(r['contract_sha256'],f1.digest(b'contract'))

    def test_16_malformed_scope_rejected(self):
        r=m.scope_review(b'bad',b'signed',now=UTC,
                         reviewer=lambda *a,**k: (_ for _ in ()).throw(f6.Stop('bad')),
                         catalog_raw=CATALOG)
        self.assertEqual(r['status'],'REJECTED')

    def test_17_unknown_scope_review_rejected(self):
        with self.assertRaisesRegex(m.Stop,'INVALID_SCOPE_REVIEW'):
            m.scope_review(b'a',b'b',now=UTC,
                           reviewer=lambda *a,**k:('GO','no','x'),catalog_raw=CATALOG)

    def test_18_wrong_catalog_state(self):
        cat=f1.load(CATALOG);cat['execution_enabled']=True
        with self.assertRaisesRegex(m.Stop,'CATALOG_STATE_CHANGED'):
            m.make_report(HEAD,f1.canonical(cat),BASE,BASE,SCOPE,now=UTC)

    def test_19_wrong_family_preconditions(self):
        cat=f1.load(CATALOG)
        next(x for x in cat['families'] if x.get('id')=='FTP-T01')['preconditions']=[]
        with self.assertRaisesRegex(m.Stop,'FTP_T01_PRECONDITION_CHANGED'):
            m.make_report(HEAD,f1.canonical(cat),BASE,BASE,SCOPE,now=UTC)

    def test_20_reject_naive_clock(self):
        with self.assertRaisesRegex(m.Stop,'CLOCK_NOT_UTC_AWARE'):
            m.make_report(HEAD,CATALOG,BASE,BASE,SCOPE,now=datetime(2026,11,20))

    def test_21_f7_max_permit(self):
        r=m.make_report(HEAD,CATALOG,BASE,BASE,SCOPE,now=UTC)
        self.assertTrue(all(x['permit_max_seconds']==120 for x in r['boot_roles']))

    def test_22_source_guard_compares_two_f8_and_f9_files(self):
        with mock.patch.object(f7,'git_guard',return_value=HEAD),mock.patch.object(f7,'_run',return_value={'rc':0}) as run:
            self.assertEqual(m.source_guard(),HEAD)
            self.assertEqual(run.call_count,8)

    def test_23_source_guard_rejects_uncommitted(self):
        with mock.patch.object(f7,'git_guard',return_value=HEAD),mock.patch.object(f7,'_run',return_value={'rc':1}):
            with self.assertRaisesRegex(m.Stop,'F9_SOURCE_NOT_COMMITTED'):
                m.source_guard()

    def test_24_evaluation_is_no_go_with_missing_roots(self):
        missing=lambda _: (_ for _ in ()).throw(FileNotFoundError())
        r=m.evaluate(clock=lambda:UTC,source_check=lambda:HEAD,
                     trust_scope_loader=missing,trust_boot_loader=missing)
        self.assertEqual((r['scope_trust']['status'],r['boot_trust']['status']),('ABSENT','ABSENT'))
        self.assertEqual(r['p8'],'NO-GO')

    def test_25_require_pair_files(self):
        with self.assertRaisesRegex(m.Stop,'PARTIAL_SCOPE_PATHS'):
            m.evaluate(contract_path=Path('/tmp/a'),source_check=lambda:HEAD)

    def test_26_no_persistence_of_untrusted_go(self):
        report=m.make_report(HEAD,CATALOG,BASE,BASE,SCOPE,now=UTC)
        report['p8']='GO'
        with mock.patch('os.geteuid',return_value=1000):
            with self.assertRaisesRegex(m.Stop,'UNSAFE_REPORT'):
                m.persist(report)

    def test_27_persistence_privacy_and_manifest(self):
        report=m.make_report(HEAD,CATALOG,BASE,BASE,SCOPE,now=UTC)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'receipts'
            root.mkdir(mode=0o700)
            with mock.patch('os.geteuid',return_value=1000),mock.patch.object(f7,'_create',return_value=root):
                folder=m.persist(report,root=root)
            raw=(folder/'report.json').read_bytes()
            man=f1.load((folder/'manifest.json').read_bytes())
            self.assertEqual(man['sha256'],f1.digest(raw))
            self.assertFalse(f1.load(raw)['traffic_authorized'])

    def test_28_main_rejects_missing_trust_without_fabricating(self):
        with mock.patch('os.geteuid',return_value=1000),mock.patch.object(m,'evaluate',return_value=m.make_report(HEAD,CATALOG,BASE,BASE,SCOPE,now=UTC)),mock.patch.object(m,'persist',return_value=Path('/tmp/receipt')):
            self.assertEqual(m.main(['--prepare']),0)
