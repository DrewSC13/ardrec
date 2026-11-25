"""R286 synthetic mutations of R276 historical review scope; no dispatch."""
from dataclasses import replace
from fractions import Fraction
import copy
import unittest
from ardrec.contracts import ND
from ardrec.coordination import pilot_readback as rb
import test_r278_pilot_readback as fixtures

class HistoricalSemanticsTests(unittest.TestCase):
    def setUp(self):
        f=fixtures.PilotReadbackTests(); f.setUp(); self.addCleanup(f.doCleanups)
        self.p=f.snapshot.projections[0]; self.payloads=f.payloads; self.uid=self.p.service_scenario_id
    def mutate(self, role, field, value):
        data=copy.deepcopy(self.payloads); data[(self.uid,role)][field]=value
        with self.assertRaises(ValueError): rb.evaluate_archived_unit(self.p,data)
    def test_valid(self):
        self.assertEqual(rb.evaluate_archived_unit(self.p,self.payloads)['criteria'], {'ES':'ND','SA':'FALSO','CV':'FALSO','LE':'ND'})
    def test_all_missing_magnitudes(self):
        for field in ('substituted_baseline','upper_bound','lower_adjustment_bound'):
            with self.subTest(field=field):
                p=replace(self.p,analysis=replace(self.p.analysis,**{field:Fraction(0)}))
                with self.assertRaises(ValueError): rb.evaluate_archived_unit(p,self.payloads)
    def test_wrong_nd_reason(self):
        p=replace(self.p,analysis=replace(self.p.analysis,accumulated_evidence=ND('OTHER_REASON')))
        with self.assertRaises(ValueError): rb.evaluate_archived_unit(p,self.payloads)
    def test_history(self):
        for field,value in [('review_generation',1),('native_phase','ACTIVO'),('operational_publications',False)]:
            with self.subTest(field=field): self.mutate('history',field,value)
    def test_supports(self):
        supports=copy.deepcopy(self.payloads[(self.uid,'evidence_repository')]['i7']); supports[0]['operationally_accredited']=True
        self.mutate('evidence_repository','i7',supports)
        supports=copy.deepcopy(self.payloads[(self.uid,'evidence_repository')]['i7']); supports[1]=supports[0]
        self.mutate('evidence_repository','i7',supports)
    def test_counters(self):
        for field,value in [('development_observations',1),('automatic_retry',True),('operational_attempts',False),('i6',{})]:
            with self.subTest(field=field): self.mutate('execution_counters',field,value)
    def test_objectives(self):
        self.mutate('objective_status','selected_for_dispatch',True); self.mutate('objective_status','status','CONFIRMED')
    def test_controls(self):
        for field,value in [('a3_authority','VERDADERO'),('a4_operational_selection','CASE'),('blockers',['OTHER'])]:
            with self.subTest(field=field): self.mutate('pending_controls',field,value)
    def test_characterization(self):
        self.mutate('characterization','profile','OTHER'); self.mutate('characterization','family_id','OTHER')
    def test_review_observation_not_operational(self):
        p=replace(self.p,generation_index=1); data=copy.deepcopy(self.payloads)
        h=data[(self.uid,'history')]; h['review_generation']=1
        c=data[(self.uid,'execution_counters')]; c.update(development_observations=1,i6={'operational_attempt_admitted':False,'automatic_retry':False})
        char=data[(self.uid,'characterization')]; repo=data[(self.uid,'evidence_repository')]
        repo['i3']={'unit_id':self.uid,'instance_id':char['instance_id'],'plan_sha256':char['plan_sha256'],'experimental_admission':False}
        rb.evaluate_archived_unit(p,data)
        repo['i3']['experimental_admission']=True
        with self.assertRaises(ValueError): rb.evaluate_archived_unit(p,data)
if __name__=='__main__': unittest.main(verbosity=2)
