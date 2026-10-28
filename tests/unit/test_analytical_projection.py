"""Oráculo de tesis y límites del contrato de proyección, sin autoridad global."""
from dataclasses import FrozenInstanceError, replace
from fractions import Fraction as F
import json
from pathlib import Path
import unittest
from ardrec.analytical import (
    AnalyticalError, AnalyticalProjection, AnalysisValues, FrozenValues,
    ObjectReference, REFERENCE_ROLES, MAX_BYTES, check_frozen_compatibility,
    decode_projection, encode_projection,
)
from ardrec.contracts import ND
from ardrec.state import ServicePhase
FIXTURE = Path(__file__).resolve().parents[1] / 'fixtures/analytical-projection-v1.json'


def projection():
    return AnalyticalProjection('REG-1','EXE-1','a'*64,'S01',18,ServicePhase.PENDIENTE,
        FrozenValues(F(1,2),F(1,2),ObjectReference('CAR-EJEMPLO-S01','b'*64)),
        AnalysisValues(F(3,4),F(1,3),F(7,12),F(4,9),F(19,36),F(7,12)),
        tuple(ObjectReference(name.upper(),'c'*64) for name in REFERENCE_ROLES))


class AnalyticalProjectionTests(unittest.TestCase):
    def wire(self, change):
        value=json.loads(encode_projection(projection()));change(value)
        return json.dumps(value).encode()

    def test_thesis_oracle(self):
        p=decode_projection(FIXTURE.read_bytes())
        self.assertEqual((p.frozen.initial_risk,p.frozen.normalized_criticality),(F(1,2),F(1,2)))
        self.assertEqual(tuple(getattr(p.analysis,n) for n in ('accumulated_evidence','substituted_baseline','upper_bound','lower_adjustment_bound','recalibrated_risk','priority')),
                         (F(3,4),F(1,3),F(7,12),F(4,9),F(19,36),F(7,12)))
        self.assertEqual(p.generation_index,18)

    def test_roundtrip_and_order(self):
        p=projection();raw=encode_projection(p)
        self.assertEqual(decode_projection(raw),p)
        reordered=json.dumps(dict(reversed(list(json.loads(raw).items())))).encode()
        self.assertEqual(encode_projection(decode_projection(reordered)),raw)

    def test_all_states(self):
        for state in ServicePhase:
            p=projection()
            if state is ServicePhase.PREPARADO:p=replace(p,analysis=replace(p.analysis,priority=None))
            p=replace(p,operational_state=state)
            self.assertEqual(decode_projection(encode_projection(p)),p)

    def test_prepared_priority(self):
        with self.assertRaisesRegex(AnalyticalError,'prepared_priority_not_empty'):
            replace(projection(),operational_state=ServicePhase.PREPARADO)

    def test_empty_nd_zero(self):
        p=projection();values=(None,ND('UNKNOWN'),F(0))
        raw=[encode_projection(replace(p,analysis=replace(p.analysis,priority=v))) for v in values]
        self.assertEqual(len(set(raw)),3)
        self.assertEqual(tuple(decode_projection(r).analysis.priority for r in raw),values)

    def test_nd_preserved(self):
        p=projection();p=replace(p,analysis=replace(p.analysis,recalibrated_risk=ND('CONFLICT')))
        self.assertEqual(decode_projection(encode_projection(p)).analysis.recalibrated_risk,ND('CONFLICT'))

    def test_known_bounds_with_unrelated_nd(self):
        p=projection()
        with self.assertRaisesRegex(AnalyticalError,'bounds_inconsistent'):
            replace(p,analysis=replace(p.analysis,accumulated_evidence=ND('UNKNOWN'),lower_adjustment_bound=F(3,4)))

    def test_known_bounds_across_nd(self):
        p=projection()
        with self.assertRaisesRegex(AnalyticalError,'bounds_inconsistent'):
            replace(p,analysis=replace(p.analysis,lower_adjustment_bound=ND('UNKNOWN'),recalibrated_risk=F(1,4)))

    def test_all_magnitude_domains(self):
        p=projection()
        for name in ('accumulated_evidence','substituted_baseline','upper_bound','lower_adjustment_bound','recalibrated_risk','priority'):
            for v in (F(-1,10),F(11,10),True,0.5,0):
                with self.subTest(name=name,value=v),self.assertRaises(AnalyticalError):replace(p.analysis,**{name:v})
        for name in ('initial_risk','normalized_criticality'):
            with self.assertRaises(AnalyticalError):replace(p.frozen,**{name:F(2)})

    def test_risk_identity(self):
        p=projection()
        with self.assertRaisesRegex(AnalyticalError,'risk_identity_inconsistent'):
            replace(p,analysis=replace(p.analysis,recalibrated_risk=F(1,2)))

    def test_large_exact_rational(self):
        p=projection();q=F(2**200+1,2**201+1)
        p=replace(p,analysis=replace(p.analysis,accumulated_evidence=q,priority=q))
        self.assertEqual(decode_projection(encode_projection(p)).analysis.priority,q)

    def test_generation_limits(self):
        for v in (True,-1,2**63,1.0,'18'):
            with self.assertRaisesRegex(AnalyticalError,'generation_invalid'):replace(projection(),generation_index=v)

    def test_frozen_changes(self):
        p=projection()
        for f in (replace(p.frozen,normalized_criticality=F(1,4)),replace(p.frozen,characterization=ObjectReference('OTHER','d'*64))):
            with self.assertRaisesRegex(AnalyticalError,'frozen_values_changed'):check_frozen_compatibility(p,replace(p,frozen=f))

    def test_context_changes(self):
        p=projection()
        for name,v in [('record_id','REG-2'),('execution_id','EXE-2'),('configuration_sha256','f'*64),('service_scenario_id','S02')]:
            with self.assertRaisesRegex(AnalyticalError,'context_changed'):check_frozen_compatibility(p,replace(p,**{name:v}))

    def test_frozen_check_is_not_transition_validation(self):
        p=projection()
        self.assertIsNone(check_frozen_compatibility(p,replace(p,generation_index=99)))

    def test_immutable_nested_values(self):
        p=projection()
        with self.assertRaises(FrozenInstanceError):p.analysis.priority=F(0)
        with self.assertRaises(FrozenInstanceError):p.references[0].reference='changed'
        with self.assertRaises(AnalyticalError):replace(p,references=list(p.references))
        with self.assertRaises(AnalyticalError):replace(p,references=p.references[:-1])

    def test_identifiers_hashes_states(self):
        for v in ('','../escape','a'*129):
            with self.assertRaises(AnalyticalError):replace(projection(),service_scenario_id=v)
        with self.assertRaises(AnalyticalError):ObjectReference('REF','A'*64)
        with self.assertRaises(AnalyticalError):replace(projection(),operational_state='PENDIENTE')

    def test_unknown_missing_duplicate_fields(self):
        cases=[self.wire(lambda x:x.update(extra=1)),self.wire(lambda x:x.pop('frozen')),
               self.wire(lambda x:x['references'].update(extra={'reference':'R','sha256':'a'*64}))]
        cases.append(encode_projection(projection()).replace(b'"generation_index":18',b'"generation_index":18,"generation_index":19'))
        for raw in cases:
            with self.assertRaises(AnalyticalError):decode_projection(raw)

    def test_bad_numbers_rationals_versions(self):
        for text in ('0.5','NaN','Infinity','true'):
            raw=encode_projection(projection()).replace(b'"generation_index":18',b'"generation_index":'+text.encode())
            with self.assertRaises(AnalyticalError):decode_projection(raw)
        raw=self.wire(lambda x:x['frozen']['initial_risk'].update(value={'numerator':2,'denominator':4}))
        with self.assertRaises(AnalyticalError):decode_projection(raw)
        with self.assertRaisesRegex(AnalyticalError,'version_incompatible'):decode_projection(self.wire(lambda x:x.update(format='future')))

    def test_size_encoding_depth(self):
        for raw in (b'x'*(MAX_BYTES+1),b'\xff',b'['*2000+b']'*2000,'not bytes'):
            with self.assertRaises(AnalyticalError):decode_projection(raw)

    def test_references_not_resolved(self):
        p=projection();p=replace(p,references=(ObjectReference('DOES-NOT-EXIST','0'*64),)+p.references[1:])
        self.assertEqual(decode_projection(encode_projection(p)),p)
