"""R59-F adversarial tests: variant immutable at A5 creation, legacy projection ND."""
from __future__ import annotations

from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from ardrec.coordination import r59d_a5_result_intake as d
from ardrec.coordination import r59e_a5_a6_family_bridge as e
from ardrec.coordination import r59f_variant_origin as f

ZERO='0'*64

def family_sources():
    """Local mock of rule engine API; Prometheus uses actual R58H/I/J."""
    engines={}
    for service,n in e.FAMILY_COUNTS.items():
        prefix=service.split('_')[0]
        specs=[]
        for i in range(1,n+1):
            fid=f'{prefix}-T{i:02d}'
            specs.append({'id':fid, 'preconditions':['SCOPE_APPROVED','LAB_ISOLATION_CONFIRMED'],
                          'required_supports':['TARGET_ATTESTATION','INTEGRITY_PROVENANCE'],
                          'acceptance_supports':['TARGET_ATTESTATION'],
                          'cleanup':'NO_MUTATION'})
        def requirement(f,variant):
            extra=((f['id']+'_'+variant,) if variant else ())
            return ('SCOPE_APPROVED','LAB_ISOLATION_CONFIRMED'),('TARGET_ATTESTATION','INTEGRITY_PROVENANCE',*extra),('TARGET_ATTESTATION',),1,False
        fake=SimpleNamespace(_requirements=requirement)
        def build(units,service=service):
            u=units[0]
            assert u['family_id'].startswith(service.split('_')[0]+'-T')
            decision={k:u[k] for k in ('family_id','derived_case_id','assessment_index','session_id')}
            cls=('POSITIVO_VALIDO' if u['outcome']=='OBSERVADO_POSITIVO' and
                 all(v=='VERDADERO' for v in (*u['preconditions'].values(),
                       *u['supports'].values(),u['integrity'],u['provenance']))
                 else 'INCONCLUSO')
            decision.update({'a6_classification':'ND','technical_truth_accredited':False,
                             'confirmed_rf':None,'hypothetical_result_class':cls,
                             'hypothetical_reason':'TEST_ONLY'})
            doc={'source_catalog_sha256':ZERO,'catalog_source':'FULL_FILE_SHA256_PINNED',
                 'unit_count':1,'a6_classification':'ND','technical_truth_accredited':False,
                 'confirmed_final_risk':None,'published_generation':None,
                 'operational_dispatch':False,'p8_operational':'NO-GO',
                 'decisions':[decision]}
            doc['sha256']=d.digest(doc)
            return doc
        def verify(doc,build=build):
            return doc==build([doc['__input']]) if '__input' in doc else doc['a6_classification']=='ND'
        engines[service]=(fake,specs,build,verify)
    return ZERO,engines


class R59FTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.final,self.a5,self.a6=[root/n for n in ('v2','a5','a6')]
        for p in (self.final,self.a5,self.a6):
            p.mkdir(mode=0o700);p.chmod(0o700)
        self.rule_patch=patch.object(e,'_sources',side_effect=family_sources)
        self.rule_patch.start();self.addCleanup(self.rule_patch.stop)

    def intent(self, service='SSH_DEV', number=1, variant=None, attempt=None):
        fid=f'{service.split("_")[0]}-T{number:02d}'
        return f.build_intent(service_id=service,session_id='DEV_TUTOR_001',
            family_id=fid,derived_case_id=fid+'-S01-01',assessment_index=0,
            attempt_id=attempt or f'ATT_R59F_{service.split("_")[0]}_{number:02d}',
            configuration_sha256=ZERO,method_id=d.SERVICES[service][2],
            variant=variant)

    def save(self, intent=None, outcome='NO_START', support=b''):
        i = intent or self.intent()
        kwargs={}
        if outcome!='NO_START':
            kwargs.update(outcome=outcome,support=support,
                source_kind='EXTERNAL_UNVERIFIED',
                start_utc='2026-11-16T18:00:00Z',
                finish_utc='2026-11-16T18:01:00Z')
        r=f.make_receipt(i,**kwargs)
        return f.persist(self.final,self.a5,self.a6,i,r,support),i,r

    def test_v2_schema_and_legacy_hash(self):
        i=self.intent()
        self.assertTrue(f.verify_intent(i))
        self.assertNotEqual(i['sha256'],i['legacy_intent_sha256'])
        self.assertTrue(i['source_mode'].startswith('V2_VARIANT_DECLARED'))

    def test_v2_v1_projection_same_identity(self):
        i=self.intent()
        self.assertEqual({k:i[k] for k in f.IDENTITY},
                         {k:f._legacy(i)[k] for k in f.IDENTITY})

    def test_variant_origin_hashes_different(self):
        a=self.intent('FTP_DEV',2,'CONTROL')
        b=self.intent('FTP_DEV',2,'DATA')
        self.assertNotEqual(a['sha256'],b['sha256'])
        self.assertNotEqual(a['requirements_sha256'],b['requirements_sha256'])

    def test_25_families_v2_constructor(self):
        n=0
        for service,total in e.FAMILY_COUNTS.items():
            for num in range(1,total+1):
                fid=f'{service.split("_")[0]}-T{num:02d}'
                variant=e.VARIANT_OPTIONS.get(fid,(None,))[0]
                i=self.intent(service,num,variant)
                self.assertTrue(f.verify_intent(i))
                self.assertEqual(i['family_id'],fid)
                self.assertEqual(i['variant'],variant)
                n+=1
        self.assertEqual(n,25)

    def test_explicit_variants_required(self):
        for svc,n in (('FTP_DEV',2),('FTP_DEV',8),('SMB_DEV',3),('SMB_DEV',9)):
            with self.assertRaises(Exception): self.intent(svc,n)
            for variant in e.VARIANT_OPTIONS[f'{svc.split("_")[0]}-T{n:02d}']:
                self.assertTrue(f.verify_intent(self.intent(svc,n,variant)))

    def test_no_variant_where_not_needed(self):
        with self.assertRaises(Exception): self.intent('SSH_DEV',1,'WRITE')

    def test_unknown_family_denied(self):
        with self.assertRaises(Exception): self.intent('FTP_DEV',9)

    def test_variant_changed_rehashed_denied(self):
        i=self.intent('FTP_DEV',2,'CONTROL');i['variant']='DATA'
        i['sha256']=d.digest({k:v for k,v in i.items() if k!='sha256'})
        with self.assertRaises(Exception): f.verify_intent(i)

    def test_catalogue_pin_changed_rehashed_denied(self):
        i=self.intent();i['source_catalog_sha256']='f'*64
        i['sha256']=d.digest({k:v for k,v in i.items() if k!='sha256'})
        with self.assertRaises(Exception): f.verify_intent(i)

    def test_requirements_drift_rehashed_denied(self):
        i=self.intent();i['requirements_sha256']='f'*64
        i['sha256']=d.digest({k:v for k,v in i.items() if k!='sha256'})
        with self.assertRaises(Exception): f.verify_intent(i)

    def test_source_mode_promotion_rehashed_denied(self):
        i=self.intent();i['source_mode']='AUTHORIZED'
        i['sha256']=d.digest({k:v for k,v in i.items() if k!='sha256'})
        with self.assertRaises(Exception): f.verify_intent(i)

    def test_intent_wrong_service_denied(self):
        i=self.intent();i['service_id']='SMB_DEV'
        with self.assertRaises(Exception):f.verify_intent(i)

    def test_intent_schema_extra_denied(self):
        i=self.intent();i['untrusted_extra']=True
        with self.assertRaises(Exception):f.verify_intent(i)

    def test_receipt_variant_is_bound_to_origin(self):
        i=self.intent('SMB_DEV',3,'SIGNING')
        r=f.make_receipt(i)
        self.assertEqual(r['variant'],'SIGNING')
        self.assertEqual(r['v2_intent_sha256'],i['sha256'])

    def test_receipt_changed_variant_even_rehashed_denied(self):
        i=self.intent('SMB_DEV',3,'SIGNING')
        r=f.make_receipt(i);r['variant']='ENCRYPTION'
        r['sha256']=d.digest({k:v for k,v in r.items() if k!='sha256'})
        with self.assertRaises(Exception):f._project_receipt(i,r,b'')

    def test_receipt_wrong_case_denied(self):
        i=self.intent();r=f.make_receipt(i);r['derived_case_id']='SSH-T02-S01-01'
        with self.assertRaises(Exception):f._project_receipt(i,r,b'')

    def test_receipt_wrong_attempt_denied(self):
        i=self.intent();r=f.make_receipt(i);r['attempt_id']='ATT_MISMATCH'
        with self.assertRaises(Exception):f._project_receipt(i,r,b'')

    def test_receipt_unsupported_physical_authority_denied(self):
        i=self.intent();r=f.make_receipt(i);r['physical_authority_receipt_sha256']=ZERO
        with self.assertRaises(Exception):f._project_receipt(i,r,b'')

    def test_no_start_cannot_have_support(self):
        with self.assertRaises(Exception):f.make_receipt(self.intent(),support=b'not empty')

    def test_no_start_cannot_have_timestamp(self):
        with self.assertRaises(Exception):f.make_receipt(self.intent(),start_utc='2026-11-16T18:00:00Z')

    def test_positive_requires_support_and_dates(self):
        with self.assertRaises(Exception):f.make_receipt(self.intent(),outcome='OBSERVADO_POSITIVO')

    def test_positive_not_accredited(self):
        i=self.intent('FTP_DEV',2,'DATA')
        result,_,_=self.save(i,'OBSERVADO_POSITIVO',b'UNTRUSTED_FIXTURE_BYTES')
        self.assertEqual(result['a6_classification'],'ND')
        v=f.verify_stored(self.final,self.a5,self.a6,i['attempt_id'])
        self.assertTrue(v['variant_bound_at_origin'])
        self.assertFalse(v['a5_start_independently_attested'])
        self.assertIsNone(v['confirmed_rf'])
        self.assertEqual(v['receipt']['variant'],'DATA')

    def test_no_start_persists_and_reopens(self):
        result,i,_=self.save()
        self.assertEqual(result['status'],'CREATED')
        v=f.verify_stored(self.final,self.a5,self.a6,i['attempt_id'])
        self.assertEqual(v['a6_classification'],'ND')
        self.assertEqual(v['p8_operational'],'NO-GO')
        self.assertEqual(v['intent']['sha256'],i['sha256'])

    def test_replay_idempotent(self):
        a,i,r=self.save()
        b=f.persist(self.final,self.a5,self.a6,i,r,b'')
        self.assertEqual(b['status'],'REPLAY_IDENTICAL')
        self.assertEqual(a['v2_report_sha256'],b['v2_report_sha256'])

    def test_attempt_id_reuse_other_variant_denied_before_write(self):
        i=self.intent('FTP_DEV',2,'CONTROL',attempt='ATT_SHARED')
        self.save(i)
        j=self.intent('FTP_DEV',2,'DATA',attempt='ATT_SHARED')
        r=f.make_receipt(j)
        old_count=len(list(self.a5.iterdir()))
        with self.assertRaises(f.VariantOriginError):
            f.persist(self.final,self.a5,self.a6,j,r,b'')
        self.assertEqual(old_count,len(list(self.a5.iterdir())))

    def test_attempt_id_reuse_other_case_denied(self):
        i=self.intent(attempt='ATT_SHARED');self.save(i)
        j=self.intent('SSH_DEV',2,attempt='ATT_SHARED')
        with self.assertRaises(f.VariantOriginError):
            f.persist(self.final,self.a5,self.a6,j,f.make_receipt(j),b'')

    def test_attempt_id_reuse_other_result_denied(self):
        i=self.intent();self.save(i)
        r=f.make_receipt(i,outcome='INCONCLUSO',support=b'x',
             start_utc='2026-11-16T18:00:00Z',finish_utc='2026-11-16T18:00:00Z')
        with self.assertRaises(f.VariantOriginError):
            f.persist(self.final,self.a5,self.a6,i,r,b'x')

    def test_tampered_v2_file_refused(self):
        _,i,_=self.save()
        p=self.final/f._name(i['attempt_id']);p.write_bytes(p.read_bytes()+b' ')
        with self.assertRaises(Exception):f.verify_stored(self.final,self.a5,self.a6,i['attempt_id'])

    def test_tampered_legacy_file_refused(self):
        result,i,_=self.save()
        p=self.a5/('r59d-a5-'+result['legacy_candidate_sha256']+'.json')
        p.write_bytes(p.read_bytes()+b' ')
        with self.assertRaises(Exception):f.verify_stored(self.final,self.a5,self.a6,i['attempt_id'])

    def test_tampered_bridge_file_refused(self):
        result,i,_=self.save()
        p=self.a6/('r59e-a6-'+result['legacy_candidate_sha256']+'.json')
        p.write_bytes(p.read_bytes()+b' ')
        with self.assertRaises(Exception):f.verify_stored(self.final,self.a5,self.a6,i['attempt_id'])

    def test_tampered_support_refused(self):
        result,i,_=self.save(self.intent(),outcome='OBSERVADO_NEGATIVO',support=b'receipt-support')
        path=next(self.a5.glob('r59d-support-*.bin'))
        path.write_bytes(b'changed-support')
        with self.assertRaises(Exception):f.verify_stored(self.final,self.a5,self.a6,i['attempt_id'])

    def test_rehashed_false_p8_refused(self):
        _,i,_=self.save()
        path=self.final/f._name(i['attempt_id'])
        doc=json.loads(path.read_bytes());doc['p8_operational']='GO';doc['sha256']=d.digest({k:v for k,v in doc.items() if k!='sha256'})
        path.write_bytes(d.canonical(doc)+b'\n')
        with self.assertRaises(Exception):f.verify_stored(self.final,self.a5,self.a6,i['attempt_id'])

    def test_rehashed_false_a6_refused(self):
        _,i,_=self.save()
        path=self.final/f._name(i['attempt_id']);doc=json.loads(path.read_bytes())
        doc['a6_classification']='POSITIVO_VALIDO';doc['sha256']=d.digest({k:v for k,v in doc.items() if k!='sha256'})
        path.write_bytes(d.canonical(doc)+b'\n')
        with self.assertRaises(Exception):f.verify_stored(self.final,self.a5,self.a6,i['attempt_id'])

    def test_rehashed_false_a5_start_refused(self):
        _,i,_=self.save()
        path=self.final/f._name(i['attempt_id']);doc=json.loads(path.read_bytes())
        doc['a5_start_independently_attested']=True;doc['sha256']=d.digest({k:v for k,v in doc.items() if k!='sha256'})
        path.write_bytes(d.canonical(doc)+b'\n')
        with self.assertRaises(Exception):f.verify_stored(self.final,self.a5,self.a6,i['attempt_id'])

    def test_world_readable_v2_refused(self):
        _,i,_=self.save()
        (self.final/f._name(i['attempt_id'])).chmod(0o644)
        with self.assertRaises(Exception):f.verify_stored(self.final,self.a5,self.a6,i['attempt_id'])

    def test_symlink_v2_record_refused(self):
        _,i,_=self.save()
        name=f._name(i['attempt_id']);p=self.final/name
        other=self.final/'other';p.rename(other);p.symlink_to(other)
        with self.assertRaises(Exception):f.verify_stored(self.final,self.a5,self.a6,i['attempt_id'])

    def test_same_root_refused(self):
        i=self.intent();r=f.make_receipt(i)
        with self.assertRaises(Exception):f.persist(self.final,self.final,self.a6,i,r,b'')

    def test_world_readable_directory_refused(self):
        self.final.chmod(0o755)
        i=self.intent();r=f.make_receipt(i)
        with self.assertRaises(Exception):f.persist(self.final,self.a5,self.a6,i,r,b'')

    def test_umask000_no_leak(self):
        old=os.umask(0)
        try:result,i,_=self.save()
        finally:os.umask(old)
        self.assertEqual((self.final/f._name(i['attempt_id'])).stat().st_mode&0o777,0o600)

    def test_v2_timestamps_reverse_refused(self):
        i=self.intent()
        with self.assertRaises(Exception):f.make_receipt(i,outcome='INCONCLUSO',support=b'x',
            start_utc='2026-11-16T18:01:00Z',finish_utc='2026-11-16T18:00:00Z')

    def test_no_dispatch_api_present(self):
        import inspect
        src=inspect.getsource(f)
        for prohibited in ('subprocess.run','socket.socket','virsh start','systemctl start','nft -f'):
            self.assertNotIn(prohibited,src)

if __name__=='__main__':unittest.main()
