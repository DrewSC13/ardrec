"""Synthetic regression for a historical six-unit batch, no lab dispatch."""
import copy
import tempfile
import unittest
from pathlib import Path
from ardrec.coordination import pilot_controller as pc, pilot_readback as rb
from ardrec.coordination import pilot_analytical_archive as native, prospective_local_pilot as durable
from ardrec.persistence.analytical_archive import AnalyticalArchive, digest
from ardrec.persistence.codec import pack
import test_r276_native_pilot_archive as fixtures

class BatchTests(unittest.TestCase):
    def setUp(self):
        self.docs={}; records=[]
        review=fixtures.PilotArchiveTests().review(); review.pop('sha256')
        for row in review['units']:
            uid=row['unit_id']
            def doc(name, **fields):
                out=durable.seal(dict(schema=pc.SOURCE_SCHEMA+'-'+name,unit_id=uid,**fields))
                self.docs[f'method/{uid}/{name}.json']=out
                return out['sha256']
            i1=doc('I1',baseline_closed=False,service_specific_identity_pending=True,fresh_service_credentials_pending=True)
            i2=doc('I2',operational_baseline_closed=False,static_method_definitively_frozen=False,i1_sha256=i1)
            plan=doc('plan',i1_sha256=i1,i2_sha256=i2,guard='ND',execution_authorized=False)
            row.update(plan_sha256=plan,native_t1_rejection='authority_unverified')
            records.append(dict(unit_id=uid,instance_id=row['instance_id'],i1_sha256=i1,i2_sha256=i2,plan_sha256=plan))
        self.prereg=durable.seal(dict(schema=pc.SOURCE_SCHEMA,records=records,pilot_units_preregistered=6,researcher_ratings_preserved=36,static_candidates_registered=6,native_uncertainty_intervals=6,required_support_entries=24,operational_supports_accredited=0,physical_baselines_closed=0,operational_a5_attempts=0,formal_pilot_admitted=0,experimental_admitted=0,p7='DRAFT_NOT_FROZEN',p8='NO-GO'))
        review['source_sha256']=self.prereg['sha256'];review['native_review_state']=pack(pc.native_state(self.prereg['sha256'],sorted(pc.UNITS)))
        self.review=durable.seal(review)
        projs,manifest,objects=native.build_snapshot(self.review,None,0)
        temp=tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        with AnalyticalArchive(Path(temp.name)/'archive',create=True) as a:
            pin=a.store(projs,manifest,expected_manifest_sha256=digest(manifest),load_object=objects.__getitem__)
            self.snapshot=a.load(pin)
        self.report=durable.seal(dict(schema=rb.SCHEMA,scope='SOURCE_BOUND_DEVELOPMENT_READBACK',source_controller_sha256=self.review['sha256'],snapshot_sha256=[pin],units=[dict(unit_id=u,phase='PREPARADO',a8_decision='CIERRE_NO_EVALUABLE_OPERACIONALMENTE',blockers=list(pc.BLOCKERS)) for u in sorted(pc.UNITS)],p7='DRAFT_NOT_FROZEN',p8='NO-GO'))
    def run_batch(self):
        return rb.explain_batch(self.report,self.snapshot,self.prereg,self.review,self.docs.__getitem__)
    def test_coverage(self):
        result=self.run_batch(); self.assertEqual(result['units_replayed'],6); self.assertEqual(result['historical_guards_explained'],30); self.assertEqual(result['current_guards_accredited'],0)
        self.assertTrue(all(g['current_operational_status']=='ND' for u in result['units'] for g in u['guards']))
        self.assertIn('HISTORICAL_GUARDS_EXPLAINED=30',rb.render_batch_text(result))
    def test_idempotence(self): self.assertEqual(self.run_batch(),self.run_batch())
    def test_missing_document(self):
        del self.docs['method/PILOT-FTP-01/I1.json']
        with self.assertRaises(KeyError): self.run_batch()
    def test_cross_unit_document(self):
        self.docs['method/PILOT-FTP-01/I1.json']=self.docs['method/PILOT-FTP-02/I1.json']
        with self.assertRaises(ValueError): self.run_batch()
    def test_modified_document(self):
        self.docs['method/PILOT-FTP-01/I1.json']['baseline_closed']=True
        with self.assertRaises(ValueError): self.run_batch()
    def test_resealed_document(self):
        d=self.docs['method/PILOT-FTP-01/I1.json'];d.pop('sha256');d['fresh_service_credentials_pending']=False;self.docs['method/PILOT-FTP-01/I1.json']=durable.seal(d)
        with self.assertRaises(ValueError): self.run_batch()
    def test_changed_report(self):
        self.report['p8']='GO'
        with self.assertRaises(ValueError): self.run_batch()
    def test_single_unit_pin_unchanged(self):
        u=self.run_batch()['units'][0];rec=next(r for r in self.prereg['records'] if r['unit_id']==u['unit_id']); ctrl=next(r for r in self.review['units'] if r['unit_id']==u['unit_id'])
        self.assertEqual(u['replay'],rb.explain_unit(self.report,self.snapshot,rec,ctrl,self.prereg['sha256']))
if __name__=='__main__': unittest.main(verbosity=2)
