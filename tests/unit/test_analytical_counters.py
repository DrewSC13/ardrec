"""Contadores desde recibos y recuperación / receipt counters and recovery."""
from copy import deepcopy
from dataclasses import replace
from fractions import Fraction
import hashlib
import multiprocessing
from pathlib import Path
import os
import signal
import tempfile
import unittest
from unittest.mock import patch
from ardrec.analytical import ObjectReference
from ardrec.analytical_counters import FORMAT, counter_payload
from ardrec.analytical_references import ROLES, canonical, ReferenceError
from ardrec.persistence import DurableStore, _publish
from ardrec.persistence.analytical_archive import AnalyticalArchive, digest
from ardrec.persistence.codec import StorageError, parse
from ardrec.state import Truth, ServicePhase, Transition
from test_analytical_references import fixture
from test_persistence import INITIAL, context, reserve, outcome, FIXTURES, OBJECT_POINTS, HEAD_POINTS


def snapshot(archive, state, edit=None, origin=None):
    template, manifest, _ = fixture()
    ctx = dict(record_id=state.confirmed.record_id, execution_id=state.execution_id,
               configuration_sha256=state.confirmed.configuration_sha256,
               generation_index=state.confirmed.generation)
    bindings, projections, objects = [], [], {}
    for service in sorted(state.confirmed.services, key=lambda s:s.service_scenario_id):
        sid=service.service_scenario_id; refs={}
        for role in ROLES:
            payload=counter_payload(state,sid) if role=='execution_counters' else {'synthetic':True,'semantics_not_validated':True}
            if edit is not None and role=='execution_counters':payload=edit(sid,deepcopy(payload))
            raw=canonical(dict(format='ardrec-analytical-object-1',context={**ctx,'generation_index':0 if role!='execution_counters' else (ctx['generation_index'] if origin is None else origin)},service_scenario_id=sid,role=role,reference=sid+'-'+role,payload=payload))
            sha=digest(raw);objects[sha]=raw;refs[role]=ObjectReference(sid+'-'+role,sha)
            bindings.append(dict(service_scenario_id=sid,role=role,reference=sid+'-'+role,sha256=sha))
        projections.append(replace(template,**ctx,service_scenario_id=sid,operational_state=service.phase,
            frozen=replace(template.frozen,characterization=refs['characterization']),
            analysis=replace(template.analysis,priority=None if service.phase is ServicePhase.PREPARADO else Fraction(7,12)),
            references=tuple(refs[r] for r in ROLES[1:])))
    manifest.update(context=ctx,bindings=sorted(bindings,key=lambda b:(b['service_scenario_id'],b['role'])))
    raw=canonical(manifest)
    return archive.store(tuple(projections),raw,expected_manifest_sha256=digest(raw),load_object=objects.__getitem__)


def reopen(root,archive,**kw):
    return DurableStore.open(root/'store',record_id='REG-1',configuration_sha256='a'*64,analytical_archive=archive,**kw)


def crash(root,point,sha):
    def kill(actual):
        if actual==point:os.kill(os.getpid(),signal.SIGKILL)
    with AnalyticalArchive(Path(root)/'archive') as archive,reopen(Path(root),archive,fault=kill) as store:
        store.publish_analytical_counters(expected_generation=1,reference='GEN-2',event='PUB-2',snapshot_sha256=sha)
    raise RuntimeError('Fault not reached')


class AnalyticalCounterTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup);self.root=Path(tmp.name)
        self.archive=AnalyticalArchive(self.root/'archive',create=True);self.addCleanup(self.archive.close)
    def create(self,strict=True):
        sha=snapshot(self.archive,replace(INITIAL,authority=Truth.VERDADERO))
        self.store=DurableStore.create(self.root/'store',INITIAL,analytical_archive=self.archive,snapshot_sha256=sha,validate_counters=strict)
        self.addCleanup(self.store.close);return sha
    def publish(self,sha,gen=0):
        return self.store.publish_analytical_counters(expected_generation=gen,reference='GEN-'+str(gen+1),event='PUB-'+str(gen+1),snapshot_sha256=sha)
    def candidate(self):
        g=self.store.state.confirmed.generation
        return _publish(self.store.state,g,'GEN-'+str(g+1),'PUB-'+str(g+1))
    def prepare(self):
        self.create();self.store.transition('S01',Transition.PREPARAR,context(self.store,Transition.PREPARAR))
        self.publish(snapshot(self.archive,self.candidate()))
    def ready_result(self,no_start=False):
        self.prepare();reserve(self.store);outcome(self.store,no_start=no_start)
        return self.candidate()
    def tree(self):return {str(p.relative_to(self.root/'store')):p.read_bytes() for p in (self.root/'store').rglob('*') if p.is_file()}
    def test_initial_empty_payload_and_mode(self):
        self.create();self.assertEqual(counter_payload(self.store.state,'S01'),{'format':FORMAT,'cases':[]})
        self.assertEqual(self.store.analytical_validation,'execution_counters_v1')
    def test_initial_invalid_payload_creates_no_store(self):
        sha=snapshot(self.archive,replace(INITIAL,authority=Truth.VERDADERO),lambda s,p:{**p,'extra':True})
        with self.assertRaises(ReferenceError):DurableStore.create(self.root/'store',INITIAL,analytical_archive=self.archive,snapshot_sha256=sha,validate_counters=True)
        self.assertFalse((self.root/'store').exists())
    def test_strict_initialization_requires_anchor(self):
        with self.assertRaises(StorageError):DurableStore.create(self.root/'store',INITIAL,validate_counters=True)
        self.assertFalse((self.root/'store').exists())
    def test_boolean_mode_type(self):
        with self.assertRaises(StorageError):DurableStore.create(self.root/'store',INITIAL,validate_counters=1)
    def test_unverified_or_simulated_state_rejected(self):
        for state in (INITIAL,replace(INITIAL,authority=Truth.FALSO),replace(INITIAL,authority=Truth.VERDADERO,simulation=True)):
            with self.assertRaises(ReferenceError):counter_payload(state,'S01')
    def test_unknown_service_rejected(self):
        with self.assertRaises(ReferenceError):counter_payload(replace(INITIAL,authority=Truth.VERDADERO),'OTHER')
    def test_pending_reservation_not_counted(self):
        self.prepare();reserve(self.store)
        self.assertEqual(counter_payload(self.store.state,'S01')['cases'],[])
        self.assertEqual(self.store.state.pending_attempts,('ATT-1',));self.store.close()
        with reopen(self.root,self.archive) as s:
            self.assertEqual(counter_payload(s.state,'S01')['cases'],[]);self.assertEqual(s.state.pending_attempts,('ATT-1',))
    def test_uncertain_not_counted(self):
        self.prepare();reserve(self.store);self.store.uncertain('ATT-1','UNCERTAIN-1')
        self.assertEqual(counter_payload(self.store.state,'S01')['cases'],[])
        self.assertEqual(self.store.state.pending_attempts,('ATT-1',))
    def test_received_result_not_counted_before_publication(self):
        self.ready_result();self.assertEqual(counter_payload(self.store.state,'S01')['cases'],[])
    def test_confirmed_execution_has_exact_receipt(self):
        candidate=self.ready_result();self.publish(snapshot(self.archive,candidate),1)
        a=self.store.state.attempts[0]
        expected={'derived_case_id':'CASE-1','confirmed_executions':1,'receipts':[{'attempt_id':'ATT-1','event_reference':'PUB-2','generation_index':2,'start_status':'VERIFICADO','request_sha256':hashlib.sha256(a.request).hexdigest(),'report_sha256':hashlib.sha256(a.reports[-1].message).hexdigest()}]}
        self.assertEqual(counter_payload(self.store.state,'S01')['cases'],[expected])
        self.assertEqual(counter_payload(self.store.state,'S02')['cases'],[])
    def test_no_start_has_receipt_and_zero_count(self):
        candidate=self.ready_result(True);self.publish(snapshot(self.archive,candidate),1)
        case=counter_payload(self.store.state,'S01')['cases'][0]
        self.assertEqual(case['confirmed_executions'],0);self.assertEqual(case['receipts'][0]['start_status'],'NO_INICIADO')
    def test_wrong_count_rejected_before_writing(self):
        candidate=self.ready_result()
        def edit(s,p):
            if p['cases']:p['cases'][0]['confirmed_executions']=0
            return p
        sha=snapshot(self.archive,candidate,edit);before=self.tree()
        with self.assertRaisesRegex(ReferenceError,'counter_payload_mismatch'):self.publish(sha,1)
        self.assertEqual(before,self.tree());self.assertEqual(self.store.state.confirmed.generation,1)
    def test_receipt_cannot_follow_its_object_origin(self):
        candidate=self.ready_result();sha=snapshot(self.archive,candidate,origin=0)
        with self.assertRaisesRegex(ReferenceError,'counter_receipt_after_object_origin'):self.publish(sha,1)

    def test_boolean_count_does_not_equal_one(self):
        candidate=self.ready_result()
        def edit(s,p):
            if p['cases']:p['cases'][0]['confirmed_executions']=True
            return p
        with self.assertRaises(ReferenceError):self.publish(snapshot(self.archive,candidate,edit),1)
    def test_receipt_fields_are_verified(self):
        candidate=self.ready_result()
        for field,value in [('attempt_id','OTHER'),('event_reference','OTHER'),('generation_index',1),('start_status','NO_INICIADO'),('request_sha256','0'*64),('report_sha256','0'*64)]:
            def edit(s,p):
                if p['cases']:p['cases'][0]['receipts'][0][field]=value
                return p
            sha=snapshot(self.archive,candidate,edit);before=self.tree()
            with self.subTest(field=field),self.assertRaises(ReferenceError):self.publish(sha,1)
            self.assertEqual(before,self.tree())
    def test_duplicate_and_missing_receipts_rejected(self):
        candidate=self.ready_result()
        for duplicate in (True,False):
            def edit(s,p):
                if p['cases']:
                    receipts=p['cases'][0]['receipts'];p['cases'][0]['receipts']=receipts*2 if duplicate else []
                return p
            with self.assertRaises(ReferenceError):self.publish(snapshot(self.archive,candidate,edit),1)
    def test_wrong_case_and_cross_service_rejected(self):
        candidate=self.ready_result()
        for field in ('case','service'):
            def edit(s,p):
                if field=='case' and p['cases']:p['cases'][0]['derived_case_id']='OTHER'
                elif field=='service':p['cases']=counter_payload(candidate,'S01' if s=='S02' else 'S02')['cases']
                return p
            with self.assertRaises(ReferenceError):self.publish(snapshot(self.archive,candidate,edit),1)
    def test_payload_version_unknown_and_extra_fields(self):
        self.create();self.store.transition('S01',Transition.PREPARAR,context(self.store,Transition.PREPARAR));candidate=self.candidate()
        for bad in ({'format':'unknown','cases':[]},{'synthetic':True},{'format':FORMAT,'cases':[],'authorized':True}):
            with self.assertRaises(ReferenceError):self.publish(snapshot(self.archive,candidate,lambda s,p:bad))
    def test_generation_contains_validation_marker(self):
        self.create();g=parse((self.root/'store/generations'/(self.store._head['generation_digest']+'.json')).read_bytes())
        self.assertEqual(g['analytical_validation'],'execution_counters_v1')
    def test_reopen_preserves_count_and_strict_mode(self):
        candidate=self.ready_result();sha=snapshot(self.archive,candidate);self.publish(sha,1);self.store.close()
        with reopen(self.root,self.archive) as s:
            self.assertEqual(s.analytical_validation,'execution_counters_v1');self.assertEqual(counter_payload(s.state,'S01')['cases'][0]['confirmed_executions'],1);self.assertEqual(s.analytical_snapshot_sha256,sha)
    def test_downgrade_rejected_before_writes(self):
        self.create();self.store.transition('S01',Transition.PREPARAR,context(self.store,Transition.PREPARAR));sha=snapshot(self.archive,self.candidate());before=self.tree()
        with self.assertRaisesRegex(StorageError,'counter_validation_required'):self.store.publish_analytical(expected_generation=0,reference='GEN-1',event='PUB-1',snapshot_sha256=sha)
        with self.assertRaises(StorageError):self.store.publish(expected_generation=0,reference='GEN-1',event='PUB-1')
        self.assertEqual(before,self.tree())
    def test_legacy_adoption_preserves_old_records(self):
        self.create(False);old=self.tree();self.assertEqual(self.store.analytical_validation,'structural_only')
        self.store.transition('S01',Transition.PREPARAR,context(self.store,Transition.PREPARAR));self.publish(snapshot(self.archive,self.candidate()))
        for name,raw in old.items():
            if name!='HEAD':self.assertEqual((self.root/'store'/name).read_bytes(),raw)
        self.store.close()
        with reopen(self.root,self.archive) as s:self.assertEqual(s.analytical_validation,'execution_counters_v1')
    def test_no_empty_publication_to_enable_mode(self):
        sha=self.create(False)
        with self.assertRaisesRegex(StorageError,'empty_publication'):self.publish(sha)
    def test_duplicate_result_preserves_count(self):
        candidate=self.ready_result();self.publish(snapshot(self.archive,candidate),1);before=self.tree()
        self.store.report('ATT-1',deepcopy(FIXTURES['result_completed']))
        self.assertEqual(before,self.tree());self.assertEqual(counter_payload(self.store.state,'S01')['cases'][0]['confirmed_executions'],1)
    def test_corrupt_counter_object_blocks_access(self):
        sha=self.create();entry=next(raw for raw in self.store.analytical_snapshot.references.object_bytes if b'"role":"execution_counters"' in raw)
        p=self.root/'archive'/sha/(digest(entry)+'.json');p.chmod(0o600);p.write_bytes(b'{}')
        with self.assertRaises(StorageError):_=self.store.state
        with self.assertRaises(StorageError):_=self.store.analytical_validation
    def test_semantic_failure_during_replay_blocks_open(self):
        self.create();self.store.close()
        with patch('ardrec.analytical_counters.check_execution_counters',side_effect=ReferenceError('semantic_failure')):
            with self.assertRaisesRegex(ReferenceError,'semantic_failure'):reopen(self.root,self.archive)
    def test_acceptance_alone_never_counts(self):
        self.prepare();reserve(self.store);self.store.report('ATT-1',deepcopy(FIXTURES['acceptance']))
        self.assertEqual(counter_payload(self.store.state,'S01')['cases'],[])
    def test_new_invocation_does_not_reset_confirmed_count(self):
        state=self.ready_result()
        other=replace(state,execution_id='EXE-2')
        self.assertEqual(counter_payload(other,'S01'),counter_payload(state,'S01'))
    def test_discovery_receipt_is_not_a_derived_case_execution(self):
        self.create();request=deepcopy(FIXTURES['discovery_request']);result=deepcopy(FIXTURES['discovery_result'])
        request['decision_index']=result['decision_index']=0
        self.store.reserve(request,decision_reference='DEC-1');self.store.report('ATT-1',result)
        self.store.transition('S01',Transition.PREPARAR,context(self.store,Transition.PREPARAR))
        state=self.candidate();self.publish(snapshot(self.archive,state))
        self.assertIsNotNone(self.store.state.attempts[0].incorporation)
        self.assertEqual(counter_payload(self.store.state,'S01')['cases'],[])
    def test_multiple_receipts_grouped_and_sorted_without_double_count(self):
        state=self.ready_result();a=state.attempts[0]
        def changed(raw,case):
            for old,new in ((b'"ATT-1"',b'"ATT-2"'),(b'"REQ-1"',b'"REQ-2"'),(b'"RESULT-completed"',b'"RESULT-2"')):
                raw=raw.replace(old,new)
            return raw.replace(b'"CASE-1"',b'"CASE-0"') if case else raw
        for other_case in (True,False):
            other=replace(a,request=changed(a.request,other_case),reports=tuple(replace(r,message=changed(r.message,other_case)) for r in a.reports),incorporation=replace(a.incorporation,event_reference='PUB-OTHER'))
            joined=replace(state,confirmed=replace(state.confirmed,incorporated_events=(*state.confirmed.incorporated_events,'PUB-OTHER')),attempts=(other,a))
            cases=counter_payload(joined,'S01')['cases']
            self.assertEqual(sum(c['confirmed_executions'] for c in cases),2)
            self.assertEqual([c['derived_case_id'] for c in cases],['CASE-0','CASE-1'] if other_case else ['CASE-1'])
            if not other_case:self.assertEqual([r['attempt_id'] for r in cases[0]['receipts']],['ATT-1','ATT-2'])

    def test_process_death_preserves_receipt_count_and_mode(self):
        self.archive.close()
        for index,point in enumerate(tuple(f'{folder}:{p}' for folder in ('generations','journal') for p in OBJECT_POINTS)+HEAD_POINTS):
            with self.subTest(point=point):
                root=self.root/str(index);root.mkdir()
                with AnalyticalArchive(root/'archive',create=True) as archive:
                    sha=snapshot(archive,replace(INITIAL,authority=Truth.VERDADERO))
                    with DurableStore.create(root/'store',INITIAL,analytical_archive=archive,snapshot_sha256=sha,validate_counters=True) as s:
                        s.transition('S01',Transition.PREPARAR,context(s,Transition.PREPARAR));c=_publish(s.state,0,'GEN-1','PUB-1');sha=snapshot(archive,c)
                        s.publish_analytical_counters(expected_generation=0,reference='GEN-1',event='PUB-1',snapshot_sha256=sha)
                        reserve(s);outcome(s);c=_publish(s.state,1,'GEN-2','PUB-2');new=snapshot(archive,c)
                child=multiprocessing.get_context('fork').Process(target=crash,args=(root,point,new));child.start();child.join(15)
                if child.is_alive():child.kill();child.join(5)
                self.assertEqual(child.exitcode,-signal.SIGKILL);child.close();committed=point in ('head:replaced','head:durable','commit:acknowledge')
                with AnalyticalArchive(root/'archive') as archive,reopen(root,archive) as s:
                    self.assertEqual(s.state.confirmed.generation,2 if committed else 1)
                    self.assertEqual(sum(c['confirmed_executions'] for c in counter_payload(s.state,'S01')['cases']),int(committed))
                    self.assertEqual(s.analytical_validation,'execution_counters_v1');self.assertEqual(s.analytical_snapshot_sha256,new if committed else sha)

if __name__=='__main__':unittest.main(verbosity=2)
