"""R59-E: source bound A5 -> existing A6 engines, never technical authority."""
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
from ardrec.coordination import r59e_a5_a6_family_bridge as m

ZERO='0'*64


def family_sources():
    """Local mock of rule engine API; Prometheus uses actual R58H/I/J."""
    engines={}
    for service,n in m.FAMILY_COUNTS.items():
        prefix=service.split('_')[0]
        specs=[]
        for i in range(1,n+1):
            fid=f'{prefix}-T{i:02d}'
            specs.append({'id':fid, 'preconditions':['SCOPE_APPROVED','LAB_ISOLATION_CONFIRMED'],
                          'required_supports':['TARGET_ATTESTATION','INTEGRITY_PROVENANCE'],
                          'acceptance_supports':['TARGET_ATTESTATION'],
                          'cleanup':'NO_MUTATION'})
        def requirement(f,variant):
            return ('SCOPE_APPROVED','LAB_ISOLATION_CONFIRMED'),('TARGET_ATTESTATION','INTEGRITY_PROVENANCE'),('TARGET_ATTESTATION',),1,False
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


class R59EBridgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base=Path(self.tmp.name)
        self.source=base/'source'
        self.output=base/'output'
        for path in (self.source,self.output):
            path.mkdir(mode=0o700)
            path.chmod(0o700)
        self.rule_patch=patch.object(m,'_sources',side_effect=family_sources)
        self.rule_patch.start()
        self.addCleanup(self.rule_patch.stop)

    def candidate(self,service='SSH_DEV',num=1,outcome='NO_START'):
        prefix=service.split('_')[0]
        fid=f'{prefix}-T{num:02d}'
        intent=d.build_intent(service_id=service,session_id='DEV_TUTOR_001',
                              family_id=fid,derived_case_id=fid+'-S01-01',
                              assessment_index=0,attempt_id=f'ATT_{prefix}_{num:02d}',
                              configuration_sha256=ZERO,
                              method_id=d.SERVICES[service][2])
        if outcome=='NO_START':
            receipt=d.make_receipt(intent)
            support=b''
        else:
            support=b'UNTRUSTED_DECLARED_SUPPORT_TEST'
            receipt=d.make_receipt(intent,outcome=outcome,
                        source_kind='EXTERNAL_UNVERIFIED',support=support,
                        start_utc='2026-11-16T18:00:00Z',
                        finish_utc='2026-11-16T18:01:00Z')
        item=d.persist_candidate(self.source,intent,receipt,support)
        return item['report_sha256']

    def build(self,sha,variant=None,review=None):
        return m.build_bridge(self.source,sha,variant=variant,review=review)

    def test_no_start_no_simulated_execution(self):
        h=self.candidate()
        doc=self.build(h)
        self.assertEqual(doc['hypothetical_family_class'],'NO_INTENTO_NO_CLASIFICACION')
        self.assertIsNone(doc['rule_report_sha256'])
        self.assertFalse(doc['a5_physical_start_accredited'])
        self.assertTrue(m.verify_bridge(doc,self.source))

    def test_declared_positive_never_admitted(self):
        h=self.candidate(outcome='OBSERVADO_POSITIVO')
        doc=self.build(h)
        self.assertEqual(doc['hypothetical_family_class'],'INCONCLUSO')
        self.assertEqual(doc['a6_classification'],'ND')
        self.assertFalse(doc['technical_truth_accredited'])
        self.assertIsNone(doc['confirmed_rf'])
        self.assertIsNone(doc['published_generation'])

    def test_declared_negative_never_admitted(self):
        h=self.candidate(outcome='OBSERVADO_NEGATIVO')
        doc=self.build(h)
        self.assertEqual(doc['a6_classification'],'ND')
        self.assertEqual(doc['p8_operational'],'NO-GO')

    def test_no_start_review_forbidden(self):
        h=self.candidate()
        good=self.build(h)
        rv=deepcopy(good['review_declaration']);rv['source_mode']='UNATTESTED_REVIEW_DECLARATION'
        with self.assertRaises(m.FamilyBridgeError):self.build(h,review=rv)

    def test_25_family_cases_including_variants(self):
        count=0
        for service,n in m.FAMILY_COUNTS.items():
            for i in range(1,n+1):
                fid=f'{service.split("_")[0]}-T{i:02d}'
                h=self.candidate(service,i,'OBSERVADO_POSITIVO')
                variant=m.VARIANT_OPTIONS.get(fid,(None,))[0]
                doc=self.build(h,variant=variant)
                self.assertEqual(doc['identity']['family_id'],fid)
                self.assertEqual(doc['family_count'],25)
                self.assertEqual(doc['a6_classification'],'ND')
                self.assertTrue(m.verify_bridge(doc,self.source))
                count+=1
        self.assertEqual(count,25)

    def test_every_variant_is_explicit(self):
        for service,i in [('FTP_DEV',2),('FTP_DEV',8),('SMB_DEV',3),('SMB_DEV',9)]:
            h=self.candidate(service,i,'OBSERVADO_POSITIVO')
            with self.assertRaises(m.FamilyBridgeError):self.build(h)
            family=f'{service.split("_")[0]}-T{i:02d}'
            for variant in m.VARIANT_OPTIONS[family]:
                doc=self.build(h,variant=variant)
                self.assertEqual(doc['variant'],variant)
                self.assertIs(doc['variant_in_original_a5_intent'],False)

    def test_variant_in_nonvariant_family_rejected(self):
        h=self.candidate()
        with self.assertRaises(m.FamilyBridgeError):self.build(h,variant='WRITE')

    def test_variant_invalid_rejected(self):
        h=self.candidate('FTP_DEV',2,'OBSERVADO_POSITIVO')
        with self.assertRaises(m.FamilyBridgeError):self.build(h,variant='BOTH')

    def test_stored_bridge_idempotent(self):
        h=self.candidate(outcome='OBSERVADO_POSITIVO')
        a=m.persist_bridge(self.output,self.source,h)
        b=m.persist_bridge(self.output,self.source,h)
        self.assertEqual(a['status'],'CREATED')
        self.assertEqual(b['status'],'REPLAY_IDENTICAL')
        self.assertEqual(a['bridge_sha256'],b['bridge_sha256'])
        self.assertEqual(m.verify_stored_bridge(self.output,self.source,h)['sha256'],a['bridge_sha256'])

    def test_stored_bridge_different_variant_conflict(self):
        h=self.candidate('FTP_DEV',2,'OBSERVADO_POSITIVO')
        m.persist_bridge(self.output,self.source,h,variant='CONTROL')
        with self.assertRaises(d.IntakeError):
            m.persist_bridge(self.output,self.source,h,variant='DATA')

    def test_stored_bridge_tampered_rejected(self):
        h=self.candidate()
        m.persist_bridge(self.output,self.source,h)
        p=self.output/m._filename(h)
        p.write_bytes(p.read_bytes().replace(b'NO-GO',b'GO-X!'))
        with self.assertRaises(Exception):m.verify_stored_bridge(self.output,self.source,h)

    def test_modified_candidate_blocks_reopen(self):
        h=self.candidate(outcome='OBSERVADO_POSITIVO')
        m.persist_bridge(self.output,self.source,h)
        p=self.source/('r59d-a5-'+h+'.json')
        p.write_bytes(p.read_bytes()+b' ')
        with self.assertRaises(Exception):m.verify_stored_bridge(self.output,self.source,h)

    def test_modified_support_blocks_reopen(self):
        h=self.candidate(outcome='OBSERVADO_POSITIVO')
        m.persist_bridge(self.output,self.source,h)
        candidate=d.verify_stored_candidate(self.source,h)
        p=self.source/('r59d-support-'+candidate['support_sha256']+'.bin')
        p.write_bytes(b'TAMPERED')
        with self.assertRaises(Exception):m.verify_stored_bridge(self.output,self.source,h)

    def test_physical_p8_risk_rehash_refused(self):
        h=self.candidate()
        report=self.build(h)
        for key,value in [('p8_operational','GO'),('a5_physical_start_accredited',True),
                          ('technical_truth_accredited',True),('a6_classification','POSITIVO_VALIDO'),
                          ('confirmed_rf','1/2'),('published_generation','FAKE'),
                          ('variant_in_original_a5_intent',True)]:
            fake=deepcopy(report);fake[key]=value
            fake['sha256']=d.digest({k:v for k,v in fake.items() if k!='sha256'})
            with self.subTest(field=key),self.assertRaises(Exception):
                m.verify_bridge(fake,self.source)

    def test_support_review_cannot_gain_real_authority(self):
        h=self.candidate(outcome='OBSERVADO_POSITIVO')
        doc=self.build(h)
        review=deepcopy(doc['review_declaration'])
        review['source_mode']='UNATTESTED_REVIEW_DECLARATION'
        review['preconditions']={k:'VERDADERO' for k in review['preconditions']}
        review['supports']={k:'VERDADERO' for k in review['supports']}
        review['integrity']=review['provenance']='VERDADERO'
        sim=self.build(h,review=review)
        self.assertEqual(sim['hypothetical_family_class'],'POSITIVO_VALIDO')
        self.assertEqual(sim['a6_classification'],'ND')
        self.assertFalse(sim['technical_truth_accredited'])
        self.assertEqual(sim['review_declaration']['source_mode'],'UNATTESTED_REVIEW_DECLARATION')

    def test_review_drift_rejected(self):
        h=self.candidate(outcome='OBSERVADO_POSITIVO')
        doc=self.build(h)
        rv=deepcopy(doc['review_declaration']);rv['source_mode']='UNATTESTED_REVIEW_DECLARATION'
        rv['candidate_sha256']=ZERO
        with self.assertRaises(m.FamilyBridgeError):self.build(h,review=rv)

    def test_review_missing_keys_rejected(self):
        h=self.candidate(outcome='OBSERVADO_POSITIVO')
        doc=self.build(h)
        rv=deepcopy(doc['review_declaration']);rv['source_mode']='UNATTESTED_REVIEW_DECLARATION'
        rv['supports'].pop(next(iter(rv['supports'])))
        with self.assertRaises(m.FamilyBridgeError):self.build(h,review=rv)

    def test_review_invalid_truth_rejected(self):
        h=self.candidate(outcome='OBSERVADO_POSITIVO')
        doc=self.build(h)
        rv=deepcopy(doc['review_declaration']);rv['source_mode']='UNATTESTED_REVIEW_DECLARATION'
        rv['supports'][next(iter(rv['supports']))]='PROBADO'
        with self.assertRaises(m.FamilyBridgeError):self.build(h,review=rv)

    def test_reviewer_replay_drift_rejected(self):
        h=self.candidate(outcome='OBSERVADO_POSITIVO')
        m.persist_bridge(self.output,self.source,h)
        doc=self.build(h)
        rv=deepcopy(doc['review_declaration']);rv['source_mode']='UNATTESTED_REVIEW_DECLARATION'
        with self.assertRaises(d.IntakeError):m.persist_bridge(self.output,self.source,h,review=rv)

    def test_symlink_output_rejected(self):
        h=self.candidate()
        real=self.output/'original';real.mkdir(mode=0o700)
        link=self.output/'link';link.symlink_to(real,target_is_directory=True)
        with self.assertRaises(d.IntakeError):m.persist_bridge(link,self.source,h)

    def test_same_source_output_root_refused(self):
        h=self.candidate()
        with self.assertRaises(m.FamilyBridgeError):m.persist_bridge(self.source,self.source,h)

    def test_insecure_output_mode_refused(self):
        h=self.candidate()
        self.output.chmod(0o755)
        with self.assertRaises(d.IntakeError):m.persist_bridge(self.output,self.source,h)

    def test_not_existing_source_refused(self):
        with self.assertRaises(Exception):self.build(ZERO)

    def test_real_pinned_p7_engines_when_available(self):
        """On Prometheus, run all 25 through genuine pinned R58H/I/J."""
        catalogue=Path(__file__).resolve().parents[1]/'operational-catalog-v1'/'catalog.json'
        if not catalogue.is_file():
            # Offline packaging environment lacks the user's full repository.
            self.assertEqual(sum(m.FAMILY_COUNTS.values()),25)
            return
        self.rule_patch.stop()
        try:
            pin, engines=m._sources()
            self.assertEqual(len(pin),64)
            self.assertEqual(sum(len(bundle[1]) for bundle in engines.values()),25)
            for service,n in m.FAMILY_COUNTS.items():
                for i in range(1,n+1):
                    fid=f'{service.split("_")[0]}-T{i:02d}'
                    variant=m.VARIANT_OPTIONS.get(fid,(None,))[0]
                    h=self.candidate(service,i,'OBSERVADO_POSITIVO')
                    result=self.build(h,variant=variant)
                    self.assertEqual(result['source_catalog_sha256'],pin)
                    self.assertEqual(result['rule_catalog_source'],'FULL_FILE_SHA256_PINNED')
                    self.assertEqual(result['a6_classification'],'ND')
                    self.assertTrue(m.verify_bridge(result,self.source))
        finally:
            self.rule_patch.start()

    def test_rule_engine_false_operational_go_rejected(self):
        h=self.candidate(outcome='OBSERVADO_POSITIVO')
        pin,engines=family_sources()
        engine,specs,run,verify=engines['SSH_DEV']
        def malicious(units):
            fake=run(units)
            fake['p8_operational']='GO'
            fake['sha256']=d.digest({k:v for k,v in fake.items() if k!='sha256'})
            return fake
        engines['SSH_DEV']=(engine,specs,malicious,lambda report:True)
        with patch.object(m,'_sources',return_value=(pin,engines)):
            with self.assertRaises(m.FamilyBridgeError):self.build(h)

    def test_rule_engine_mismatched_case_rejected(self):
        h=self.candidate(outcome='OBSERVADO_POSITIVO')
        pin,engines=family_sources()
        engine,specs,run,verify=engines['SSH_DEV']
        def malicious(units):
            fake=run(units)
            fake['decisions'][0]['derived_case_id']='SSH-T08-S01-99'
            fake['sha256']=d.digest({k:v for k,v in fake.items() if k!='sha256'})
            return fake
        engines['SSH_DEV']=(engine,specs,malicious,lambda report:True)
        with patch.object(m,'_sources',return_value=(pin,engines)):
            with self.assertRaises(m.FamilyBridgeError):self.build(h)

    def test_no_untrusted_dispatch_paths(self):
        p=Path(m.__file__).read_text()
        for forbidden in ('subprocess.', 'socket.', 'virsh start','systemctl start','nft -f'):
            self.assertNotIn(forbidden,p)


if __name__=='__main__':unittest.main()
