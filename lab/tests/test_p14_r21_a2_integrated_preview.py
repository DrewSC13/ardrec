"""R21: síntesis A2 en modo solo lectura de fuentes R17--R20."""
from __future__ import annotations

from dataclasses import replace
import copy
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'src'))
from test_p14_r20_a2_control_preview import input_set
from ardrec.initialization.control_preview import prepare_control_preview
from ardrec.initialization.rule_preflight import FrozenRulePreview
from ardrec.initialization.initial_preview import InitialPreview
from ardrec.initialization.dependency_preview import DependencyPreview
from ardrec.initialization.control_preview import ControlPreview
from ardrec.initialization.integrated_preview import (
    FORMAT, IntegratedPreviewError, assemble_integrated_preview)


def make(n=3, with_controls=True):
    rules,initial,deps,candidate=input_set(n)
    if not with_controls:
        for service in candidate['services']:
            service['controls']=[]
    control=prepare_control_preview(rules,initial,deps,candidate)
    return rules,initial,deps,control


class IntegratedR21Tests(unittest.TestCase):
    def setUp(self):
        self.sources=make()
        self.preview=assemble_integrated_preview(*self.sources)

    def reject(self,code,source=None):
        with self.assertRaises(IntegratedPreviewError) as error:
            (self.preview if source is None else source).verify(*self.sources)
        self.assertEqual(error.exception.code,code)

    def test_valid_source_chain(self):
        self.assertTrue(self.preview.verify(*self.sources))
        self.assertEqual(hashlib.sha256(self.preview.source).hexdigest(),self.preview.sha256)

    def test_54_units_all_three_protocols(self):
        sources=make(54)
        preview=assemble_integrated_preview(*sources)
        self.assertTrue(preview.verify(*sources))
        self.assertEqual(len(preview.units),54)
        self.assertEqual({p:sum(u.protocol==p for u in preview.units)
                          for p in ('SSH','FTP','SMB')}, {'SSH':18,'FTP':18,'SMB':18})
        self.assertEqual(sum(len(u.cases) for u in preview.units),108)
        self.assertEqual(sum(len(u.controls) for u in preview.units),108)
        self.assertTrue(all(u.initial_risk=='1/4' and
                            u.normalized_criticality=='3/4' for u in preview.units))

    def test_closed_reference_identity(self):
        doc=json.loads(self.preview.source)
        expected=dict(zip(('rules_sha256','initial_sha256','dependencies_sha256','controls_sha256'),
                          (self.preview.rule_source_sha256,
                           self.preview.initial_snapshot_sha256,
                           self.preview.dependency_snapshot_sha256,
                           self.preview.control_snapshot_sha256)))
        self.assertEqual(doc['sources'],expected)

    def test_exact_format(self):
        self.assertEqual(json.loads(self.preview.source)['format'],FORMAT)

    def test_service_record_is_readonly_declarative(self):
        doc=json.loads(self.preview.source)
        for unit in doc['services']:
            self.assertEqual(unit['initial_phase'],'PREPARADO')
            self.assertEqual(unit['accumulated_evidence'],'0')
            self.assertEqual(unit['recalibrated_risk'],unit['initial_risk'])
            self.assertNotIn('authorized',unit)
            self.assertNotIn('argv',unit)

    def test_control_targets_resolve_locally(self):
        for u in self.preview.units:
            by_case={c[0]:c[3] for c in u.cases}
            self.assertEqual(by_case,{'C1':('CONTROL_A',),'C2':('CONTROL_B',)})
            self.assertEqual(u.case_order,('C1','C2'))
            self.assertEqual(u.control_order,('CONTROL_A','CONTROL_B'))

    def test_budgets_are_declared_not_consumed(self):
        for u in self.preview.units:
            self.assertEqual({c[0]:c[1] for c in u.cases},{'C1':1,'C2':2})

    def test_no_controls_allowed_but_diagnostic_refs_empty(self):
        src=make(with_controls=False)
        p=assemble_integrated_preview(*src)
        self.assertTrue(p.verify(*src))
        self.assertTrue(all(u.control_order==() and
                            all(c[3]==() for c in u.cases) for u in p.units))

    def test_no_operational_dispatch(self):
        self.assertFalse(self.preview.operational_dispatch_allowed)
        self.assertIsNone(self.preview.published_generation)
        self.assertFalse(self.sources[3].operational_dispatch_allowed)

    def test_source_is_bytes(self):
        self.assertIs(type(self.preview.source),bytes)

    def test_unit_is_immutable(self):
        with self.assertRaises((AttributeError,TypeError)):
            self.preview.units[0].service_id='OTHER'

    def test_source_unchanged_after_assembly(self):
        before=[x.source for x in self.sources]
        assemble_integrated_preview(*self.sources)
        self.assertEqual(before,[x.source for x in self.sources])

    def test_repeat_assembly_exact_sha(self):
        a=assemble_integrated_preview(*self.sources)
        self.assertEqual(a,self.preview)
        self.assertEqual(a.source,self.preview.source)

    def test_input_config_permutation_is_canonical(self):
        rules,initial,deps,doc=input_set()
        doc['services'].reverse()
        for service in doc['services']:
            service['controls'].reverse()
            for control in service['controls']:
                control['requires'].reverse()
        permuted=prepare_control_preview(rules,initial,deps,doc)
        result=assemble_integrated_preview(rules,initial,deps,permuted)
        self.assertEqual(result.source,self.preview.source)
        self.assertEqual(result.sha256,self.preview.sha256)

    def test_other_configuration_cannot_verify(self):
        other=make(4)
        with self.assertRaises(Exception):
            self.preview.verify(*other)

    def test_wrong_type_rules(self):
        with self.assertRaises(IntegratedPreviewError) as error:
            assemble_integrated_preview(None,*self.sources[1:])
        self.assertEqual(error.exception.code,'fuentes_invalidas')

    def test_wrong_type_initial(self):
        with self.assertRaises(IntegratedPreviewError) as error:
            assemble_integrated_preview(self.sources[0],{},*self.sources[2:])
        self.assertEqual(error.exception.code,'fuentes_invalidas')

    def test_wrong_type_dependencies(self):
        with self.assertRaises(IntegratedPreviewError) as error:
            assemble_integrated_preview(*self.sources[:2],None,self.sources[3])
        self.assertEqual(error.exception.code,'fuentes_invalidas')

    def test_wrong_type_controls(self):
        with self.assertRaises(IntegratedPreviewError) as error:
            assemble_integrated_preview(*self.sources[:3],None)
        self.assertEqual(error.exception.code,'fuentes_invalidas')

    def test_bytes_mutation_detected(self):
        p=replace(self.preview,source=self.preview.source+b' ')
        self.reject('instantanea_alterada',p)

    def test_digest_mutation_detected(self):
        p=replace(self.preview,sha256='0'*64)
        self.reject('instantanea_alterada',p)

    def test_digest_wrong_type(self):
        p=replace(self.preview,sha256=None)
        self.reject('instantanea_alterada',p)

    def test_source_wrong_type(self):
        p=replace(self.preview,source=bytearray(self.preview.source))
        self.reject('instantanea_alterada',p)

    def test_rule_sha_changed(self):
        self.reject('origen_no_coincide',replace(self.preview,rule_source_sha256='0'*64))

    def test_initial_sha_changed(self):
        self.reject('origen_no_coincide',replace(self.preview,initial_snapshot_sha256='0'*64))

    def test_dependency_sha_changed(self):
        self.reject('origen_no_coincide',replace(self.preview,dependency_snapshot_sha256='0'*64))

    def test_control_sha_changed(self):
        self.reject('origen_no_coincide',replace(self.preview,control_snapshot_sha256='0'*64))

    def test_in_memory_contract_forged(self):
        unit=replace(self.preview.units[0],protocol='SSH' if self.preview.units[0].protocol!='SSH' else 'FTP')
        self.reject('contrato_no_coincide',replace(self.preview,units=(unit,*self.preview.units[1:])))

    def _repack(self,source):
        return replace(self.preview,source=source,sha256=hashlib.sha256(source).hexdigest())

    def test_recomputed_sha_cannot_change_risk(self):
        doc=json.loads(self.preview.source)
        doc['services'][0]['initial_risk']='0'
        raw=json.dumps(doc,sort_keys=True,ensure_ascii=True,separators=(',',':')).encode()
        self.reject('contrato_no_coincide',self._repack(raw))

    def test_recomputed_sha_cannot_add_authorization(self):
        doc=json.loads(self.preview.source)
        doc['operational_authorized']=True
        raw=json.dumps(doc,sort_keys=True,ensure_ascii=True,separators=(',',':')).encode()
        self.reject('contrato_no_coincide',self._repack(raw))

    def test_recomputed_sha_cannot_change_case_budget(self):
        doc=json.loads(self.preview.source)
        doc['services'][0]['cases'][0]['attempt_ceiling']=100
        raw=json.dumps(doc,sort_keys=True,ensure_ascii=True,separators=(',',':')).encode()
        self.reject('contrato_no_coincide',self._repack(raw))

    def test_noncanonical_spacing_denied(self):
        obj=json.loads(self.preview.source)
        raw=json.dumps(obj,sort_keys=True,indent=2).encode()
        self.reject('instantanea_no_canonica',self._repack(raw))

    def test_noncanonical_order_denied(self):
        obj=json.loads(self.preview.source)
        raw=json.dumps(dict(reversed(list(obj.items()))),sort_keys=False,separators=(',',':')).encode()
        self.reject('instantanea_no_canonica',self._repack(raw))

    def test_version_mismatch(self):
        obj=json.loads(self.preview.source)
        obj['format']='UNKNOWN'
        raw=json.dumps(obj,sort_keys=True,separators=(',',':')).encode()
        self.reject('version_incompatible',self._repack(raw))

    def test_invalid_json(self):
        self.reject('instantanea_invalida',self._repack(b'{'))

    def test_json_repeated_key_denied(self):
        raw=b'{"format":"x","format":"y"}'
        self.reject('clave_duplicada',self._repack(raw))

    def test_nonjson_extra_bytes_denied(self):
        raw=self.preview.source+b'{}'
        self.reject('instantanea_invalida',self._repack(raw))

    def test_empty_service_metadata_not_tolerated(self):
        obj=json.loads(self.preview.source)
        obj['services']=[]
        raw=json.dumps(obj,sort_keys=True,separators=(',',':')).encode()
        self.reject('contrato_no_coincide',self._repack(raw))

    def test_hash_is_not_authority(self):
        self.assertIsNone(self.preview.published_generation)
        self.assertNotIn('authorization',json.loads(self.preview.source))

    def test_original_previews_stay_protected(self):
        for src in self.sources:
            self.assertIs(type(src.source),bytes)
            self.assertEqual(hashlib.sha256(src.source).hexdigest(),src.sha256)

    def test_control_tampering_rejected_before_composition(self):
        tampered=replace(self.sources[3],sha256='bad')
        with self.assertRaises(Exception):
            assemble_integrated_preview(*self.sources[:3],tampered)

    def test_initial_tampering_rejected_before_composition(self):
        tampered=replace(self.sources[1],sha256='bad')
        with self.assertRaises(Exception):
            assemble_integrated_preview(self.sources[0],tampered,*self.sources[2:])

    def test_dependency_tampering_rejected_before_composition(self):
        tampered=replace(self.sources[2],sha256='bad')
        with self.assertRaises(Exception):
            assemble_integrated_preview(*self.sources[:2],tampered,self.sources[3])

    def test_rule_tampering_rejected_before_composition(self):
        tampered=replace(self.sources[0],sha256='bad')
        with self.assertRaises(Exception):
            assemble_integrated_preview(tampered,*self.sources[1:])


if __name__=='__main__':
    unittest.main()
