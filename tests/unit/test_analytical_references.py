"""Resolución por generación, rechazos independientes y límites de autoridad."""
from dataclasses import replace, FrozenInstanceError
import hashlib
import json
from pathlib import Path
import unittest
from unittest.mock import patch
from ardrec.analytical import decode_projection, ObjectReference
from ardrec.analytical_references import (
    ROLES, OBJECT_FORMAT, MANIFEST_FORMAT, ReferenceError, canonical,
    resolve_references, check_operational_alignment,
)
from ardrec.state import ConfirmedState, GlobalState, ServiceState, Truth

def digest(raw):return hashlib.sha256(raw).hexdigest()

def fixture(change=None):
    p=decode_projection((Path(__file__).resolve().parents[1]/'fixtures/analytical-projection-v1.json').read_bytes())
    ctx={k:getattr(p,k) for k in ('record_id','execution_id','configuration_sha256','generation_index')}
    objects={};refs={};bindings=[]
    for role in ROLES:
        value={'format':OBJECT_FORMAT,'context':{**ctx,'generation_index':0},'service_scenario_id':'S01',
               'role':role,'reference':'REF-'+role,'payload':{'authorized':True,'synthetic':True}}
        if change and role=='characterization':change(value)
        raw=canonical(value);sha=digest(raw);objects[sha]=raw
        refs[role]=ObjectReference('REF-'+role,sha)
        bindings.append({'service_scenario_id':'S01','role':role,'reference':'REF-'+role,'sha256':sha})
    p=replace(p,frozen=replace(p.frozen,characterization=refs['characterization']),references=tuple(refs[r] for r in ROLES[1:]))
    manifest={'format':MANIFEST_FORMAT,'context':ctx,'bindings':sorted(bindings,key=lambda b:(b['service_scenario_id'],b['role']))}
    return p,manifest,objects

def resolve(p,m,o,anchor=None):
    def load(sha):
        if sha not in o:raise FileNotFoundError(sha)
        return o[sha]
    raw=canonical(m)
    return resolve_references((p,),raw,expected_manifest_sha256=anchor or digest(raw),load_object=load)

class AnalyticalReferenceTests(unittest.TestCase):
    def test_complete_resolution_and_original_bytes(self):
        p,m,o=fixture();r=resolve(p,m,o)
        self.assertEqual(r.object_bytes,tuple(o[b['sha256']] for b in m['bindings']))
        self.assertEqual(r.manifest_bytes,canonical(m))
    def test_older_objects_reused_explicitly(self):
        p,m,o=fixture();first=resolve(p,m,o)
        m['context']['generation_index']=19
        self.assertEqual(resolve(replace(p,generation_index=19),m,o).object_bytes,first.object_bytes)
    def test_result_immutable_after_provider_changes(self):
        p,m,o=fixture();r=resolve(p,m,o);before=r.object_bytes;o.clear()
        self.assertEqual(before,r.object_bytes)
        with self.assertRaises(FrozenInstanceError):r.object_bytes=()
    def test_integrity_does_not_promote_authority(self):
        p,m,o=fixture();r=resolve(p,m,o)
        services=(ServiceState('S01',p.operational_state),)
        state=GlobalState(ConfirmedState(p.record_id,18,'GEN-18',p.configuration_sha256,'VERS-1',services),p.execution_id,services)
        check_operational_alignment((p,),state)
        self.assertIs(state.authority,Truth.ND)
        self.assertFalse(hasattr(r,'facts'));self.assertFalse(hasattr(r,'authority'))
        with self.assertRaises(ReferenceError):check_operational_alignment((replace(p,generation_index=19),),state)
    def test_size_and_depth_bounds(self):
        with self.assertRaises(ReferenceError):canonical({'x':'a'*262144})
        value=0
        for _ in range(34):value=[value]
        with self.assertRaises(ReferenceError):canonical(value)
    def test_duplicate_and_noncanonical_json(self):
        p,m,o=fixture();raw=canonical(m)
        for altered in (raw+b'\n',raw[:-1]+b',"format":"duplicate"}'):
            with self.assertRaises(ReferenceError):resolve_references((p,),altered,expected_manifest_sha256=digest(altered),load_object=o.get)
    def test_float_and_integer_bounds(self):
        for value in [0.1,float('nan'),2**63]:
            with self.assertRaises(ReferenceError):canonical({'x':value})
        self.assertEqual(json.loads(canonical({'n':str(2**255)}))['n'],str(2**255))
    def test_aggregate_size_bound(self):
        p,m,o=fixture()
        with patch('ardrec.analytical_references.MAX_TOTAL_BYTES',len(canonical(m))),self.assertRaises(ReferenceError):resolve(p,m,o)
    def test_projection_duplicates_and_missing(self):
        p,m,o=fixture();raw=canonical(m)
        for items in [(),(p,p),[p]]:
            with self.assertRaises(ReferenceError):resolve_references(items,raw,expected_manifest_sha256=digest(raw),load_object=o.get)

# Independently named fault cases keep CI evidence identifiable.
OBJECT_FAULTS={
 'wrong_object_version':lambda o:o.update(format='future'),
 'wrong_record':lambda o:o['context'].update(record_id='OTHER'),
 'wrong_execution':lambda o:o['context'].update(execution_id='OTHER'),
 'wrong_configuration':lambda o:o['context'].update(configuration_sha256='b'*64),
 'future_object':lambda o:o['context'].update(generation_index=19),
 'boolean_generation':lambda o:o['context'].update(generation_index=True),
 'wrong_service':lambda o:o.update(service_scenario_id='OTHER'),
 'wrong_role':lambda o:o.update(role='history'),
 'wrong_reference':lambda o:o.update(reference='OTHER'),
 'unknown_object_field':lambda o:o.update(extra=0),
 'nonobject_payload':lambda o:o.update(payload=[]),
}
for name,change in OBJECT_FAULTS.items():
    def test(self,change=change):
        p,m,o=fixture(change)
        with self.assertRaises(ReferenceError):resolve(p,m,o)
    setattr(AnalyticalReferenceTests,'test_'+name,test)

MANIFEST_FAULTS={
 'wrong_manifest_version':lambda m:m.update(format='future'),
 'missing_role':lambda m:m['bindings'].pop(),
 'duplicate_binding':lambda m:m['bindings'].append(m['bindings'][0]),
 'reversed_bindings':lambda m:m['bindings'].reverse(),
 'wrong_manifest_context':lambda m:m['context'].update(execution_id='OTHER'),
}
for name,change in MANIFEST_FAULTS.items():
    def test(self,change=change):
        p,m,o=fixture();change(m)
        with self.assertRaises(ReferenceError):resolve(p,m,o)
    setattr(AnalyticalReferenceTests,'test_'+name,test)

def test_bad_anchor(self):
    p,m,o=fixture()
    with self.assertRaisesRegex(ReferenceError,'manifest_hash'):resolve(p,m,o,'0'*64)
AnalyticalReferenceTests.test_bad_anchor=test_bad_anchor

def test_missing_and_corrupt_object(self):
    p,m,o=fixture();key=m['bindings'][0]['sha256'];original=o.pop(key)
    with self.assertRaisesRegex(ReferenceError,'missing'):resolve(p,m,o)
    o[key]=original+b' '
    with self.assertRaisesRegex(ReferenceError,'object_hash'):resolve(p,m,o)
AnalyticalReferenceTests.test_missing_and_corrupt_object=test_missing_and_corrupt_object

if __name__=='__main__':unittest.main(verbosity=2)
