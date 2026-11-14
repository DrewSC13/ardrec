"""R25: integridad documental, procedencia limitada y negativa operativa."""
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
sys.path.insert(0,str(ROOT/'scripts'))
from ardrec.scheduling.observation_preview import (
    ObservationError, reconcile_documentary_observations, FORMAT,
    DOCUMENT_FORMAT)
from demo_p14_r25_a3_documentary_observations import sample


def raw(o):
    return json.dumps(o,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')


class DocumentaryR25Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources,cls.candidates,cls.scenario,cls.readiness,cls.batch,cls.blobs=sample(6)

    def view(self,batch=None,blobs=None,sources=None,candidates=None,scenario=None,readiness=None):
        return reconcile_documentary_observations(
            *(sources or self.sources),candidates or self.candidates,
            self.scenario if scenario is None else scenario,
            readiness or self.readiness,
            self.batch if batch is None else batch,
            self.blobs if blobs is None else blobs)

    def reject(self,code,change):
        batch=copy.deepcopy(self.batch);blobs=copy.deepcopy(self.blobs)
        change(batch,blobs)
        with self.assertRaises(ObservationError) as cm:
            self.view(batch,blobs)
        self.assertEqual(cm.exception.code,code)

    def test_full_chain_reconciled(self):
        v=self.view()
        self.assertTrue(v.verify(*self.sources,self.candidates,self.scenario,
                                 self.readiness,self.batch,self.blobs))
        self.assertEqual(hashlib.sha256(v.source).hexdigest(),v.sha256)
        self.assertEqual(hashlib.sha256(v.batch_source).hexdigest(),v.batch_sha256)

    def test_54_units_and_counts(self):
        sources,candidates,scenario,readiness,batch,blobs=sample(54)
        v=self.view(batch,blobs,sources,candidates,scenario,readiness)
        self.assertEqual(len(v.units),54)
        self.assertEqual(sum(len(u.items) for u in v.units),216)
        self.assertEqual(len(blobs),36)
        self.assertEqual({c:sum(x.comparison==c for u in v.units for x in u.items)
                          for c in ('SIN_DECLARACION','COINCIDE_SUPUESTO','DIFIERE_SUPUESTO')},
                         {'SIN_DECLARACION':180,'COINCIDE_SUPUESTO':18,'DIFIERE_SUPUESTO':18})

    def test_no_operational_capability(self):
        v=self.view()
        self.assertFalse(v.operational_dispatch_allowed)
        self.assertIsNone(v.published_generation)
        self.assertIsNone(v.executable_agenda)
        self.assertTrue(all(not c.executable and not c.accredited
                            for u in v.units for c in u.items))
        doc=json.loads(v.source)
        self.assertFalse(doc['technical_truth_accredited'])
        self.assertFalse(doc['external_custody_verified'])
        self.assertTrue(doc['integrity_verified'])
        self.assertFalse(doc['controls_applied'])
        self.assertEqual(doc['p8_operational'],'NO-GO')

    def test_document_proves_bytes_not_truth(self):
        v=self.view()
        self.assertEqual({x.comparison for u in v.units for x in u.items},
                         {'SIN_DECLARACION','COINCIDE_SUPUESTO','DIFIERE_SUPUESTO'})
        self.assertEqual({x.declared.name for u in v.units for x in u.items},
                         {'ND','FALSO','VERDADERO'})
        self.assertFalse(any(x.accredited for u in v.units for x in u.items))

    def test_order_invariant(self):
        x=copy.deepcopy(self.batch)
        x['services'].reverse()
        for row in x['services']:
            row['cases'].reverse();row['controls'].reverse()
        v=self.view();p=self.view(x)
        self.assertEqual((v.sha256,v.batch_sha256),(p.sha256,p.batch_sha256))

    def test_blobs_dict_order_invariant(self):
        backward=dict(reversed(tuple(self.blobs.items())))
        self.assertEqual(self.view().sha256,self.view(blobs=backward).sha256)

    def test_input_immutability(self):
        batch=copy.deepcopy(self.batch);blobs=copy.deepcopy(self.blobs)
        self.view()
        self.assertEqual(self.batch,batch);self.assertEqual(self.blobs,blobs)

    def test_changes_to_declaration_change_digest(self):
        b=copy.deepcopy(self.batch);supports=copy.deepcopy(self.blobs)
        row=b['services'][0]['cases'][0]
        self.assertEqual(row['declared'],'VERDADERO')
        row['declared']='FALSO'
        ref=row['support_reference'];doc=json.loads(supports[ref]);doc['declaration']='FALSO'
        supports[ref]=raw(doc);row['support_sha256']=hashlib.sha256(supports[ref]).hexdigest()
        self.assertNotEqual(self.view().sha256,self.view(b,supports).sha256)

    def test_document_source_corrupt(self):
        v=self.view()
        with self.assertRaises(ObservationError) as cm:
            replace(v,source=v.source+b'!').verify(*self.sources,self.candidates,
                                self.scenario,self.readiness,self.batch,self.blobs)
        self.assertEqual(cm.exception.code,'informe_alterado')

    def test_document_sha_corrupt(self):
        v=self.view()
        with self.assertRaises(ObservationError) as cm:
            replace(v,sha256='a'*64).verify(*self.sources,self.candidates,
                                 self.scenario,self.readiness,self.batch,self.blobs)
        self.assertEqual(cm.exception.code,'informe_alterado')

    def test_batch_source_corrupt(self):
        v=self.view()
        with self.assertRaises(ObservationError) as cm:
            replace(v,batch_source=v.batch_source+b'!').verify(*self.sources,
                         self.candidates,self.scenario,self.readiness,self.batch,self.blobs)
        self.assertEqual(cm.exception.code,'lote_alterado')

    def test_batch_sha_corrupt(self):
        v=self.view()
        with self.assertRaises(ObservationError) as cm:
            replace(v,batch_sha256='b'*64).verify(*self.sources,
                         self.candidates,self.scenario,self.readiness,self.batch,self.blobs)
        self.assertEqual(cm.exception.code,'lote_alterado')

    def test_units_tamper(self):
        v=self.view()
        with self.assertRaises(ObservationError) as cm:
            replace(v,units=()).verify(*self.sources,self.candidates,
                         self.scenario,self.readiness,self.batch,self.blobs)
        self.assertEqual(cm.exception.code,'conciliacion_inconsistente')

    def test_candidate_hash_tamper(self):
        v=self.view()
        with self.assertRaises(ObservationError) as cm:
            replace(v,candidate_sha256='0'*64).verify(*self.sources,
                         self.candidates,self.scenario,self.readiness,self.batch,self.blobs)
        self.assertEqual(cm.exception.code,'origen_alterado')

    def test_readiness_hash_tamper(self):
        v=self.view()
        with self.assertRaises(ObservationError) as cm:
            replace(v,readiness_sha256='0'*64).verify(*self.sources,
                         self.candidates,self.scenario,self.readiness,self.batch,self.blobs)
        self.assertEqual(cm.exception.code,'origen_alterado')

    def test_forged_dispatch_cannot_verify(self):
        v=self.view();doc=json.loads(v.source)
        doc['operational_dispatch']=True
        patched=raw(doc)
        with self.assertRaises(ObservationError) as cm:
            replace(v,source=patched,sha256=hashlib.sha256(patched).hexdigest()).verify(
                *self.sources,self.candidates,self.scenario,self.readiness,self.batch,self.blobs)
        self.assertEqual(cm.exception.code,'conciliacion_inconsistente')

    def test_forged_accreditation_cannot_verify(self):
        v=self.view();doc=json.loads(v.source)
        doc['technical_truth_accredited']=True
        patched=raw(doc)
        with self.assertRaises(ObservationError) as cm:
            replace(v,source=patched,sha256=hashlib.sha256(patched).hexdigest()).verify(
                *self.sources,self.candidates,self.scenario,self.readiness,self.batch,self.blobs)
        self.assertEqual(cm.exception.code,'conciliacion_inconsistente')

    def test_invalid_format(self):
        self.reject('formato_incompatible',lambda b,p:b.update(format='wrong'))

    def test_candidate_reference_mismatch(self):
        self.reject('origen_no_coincide',lambda b,p:b.update(candidate_sha256='x'*64))

    def test_readiness_reference_mismatch(self):
        self.reject('origen_no_coincide',lambda b,p:b.update(readiness_sha256='x'*64))

    def test_unknown_field(self):
        self.reject('lote_invalido',lambda b,p:b.update(operational_dispatch=True))

    def test_unknown_service(self):
        self.reject('servicio_ajeno_o_duplicado',lambda b,p:b['services'][0].update(id='ALIEN'))

    def test_duplicate_service(self):
        self.reject('servicio_ajeno_o_duplicado',lambda b,p:b['services'][1].update(id=b['services'][0]['id']))

    def test_service_count_missing(self):
        self.reject('servicios_invalidos',lambda b,p:b['services'].pop())

    def test_unknown_item(self):
        self.reject('elemento_ajeno_o_duplicado',lambda b,p:b['services'][0]['cases'][0].update(id='UNKNOWN'))

    def test_duplicate_item(self):
        self.reject('elemento_ajeno_o_duplicado',lambda b,p:b['services'][0]['cases'][1].update(id='CHECK_A'))

    def test_invalid_declaration(self):
        self.reject('valor_declarado_invalido',lambda b,p:b['services'][0]['cases'][0].update(declared='TRUE'))

    def test_bool_declaration_rejected(self):
        self.reject('valor_declarado_invalido',lambda b,p:b['services'][0]['cases'][0].update(declared=True))

    def test_nd_cannot_have_support(self):
        self.reject('nd_con_soporte',lambda b,p:b['services'][0]['controls'][1].update(support_reference='ABC'))

    def test_non_nd_missing_support(self):
        self.reject('referencia_invalida_o_reutilizada',lambda b,p:b['services'][0]['cases'][0].update(support_reference=None))

    def test_duplicate_ref(self):
        self.reject('referencia_invalida_o_reutilizada',lambda b,p:b['services'][0]['controls'][0].update(support_reference=b['services'][0]['cases'][0]['support_reference']))

    def test_invalid_digest(self):
        self.reject('huella_soporte_invalida',lambda b,p:b['services'][0]['cases'][0].update(support_sha256='abcd'))

    def test_missing_blob(self):
        self.reject('soporte_ausente',lambda b,p:p.pop(b['services'][0]['cases'][0]['support_reference']))

    def test_extra_blob(self):
        self.reject('soportes_extras_o_ausentes',lambda b,p:p.update(EXTRA=b'x'))

    def test_falsified_hash(self):
        self.reject('soporte_alterado',lambda b,p:p.update({b['services'][0]['cases'][0]['support_reference']:b'forged'}))

    def test_falsified_body_even_with_updated_hash(self):
        def change(b,p):
            row=b['services'][0]['cases'][0];ref=row['support_reference']
            doc=json.loads(p[ref]);doc['item_id']='CHECK_B';p[ref]=raw(doc)
            row['support_sha256']=hashlib.sha256(p[ref]).hexdigest()
        self.reject('soporte_no_corresponde',change)

    def test_noncanonical_support_even_if_hash_matches(self):
        def change(b,p):
            row=b['services'][0]['cases'][0];ref=row['support_reference']
            p[ref]=p[ref]+b' ';row['support_sha256']=hashlib.sha256(p[ref]).hexdigest()
        self.reject('json_no_canonico',change)

    def test_duplicate_json_keys_even_if_hash_matches(self):
        def change(b,p):
            row=b['services'][0]['cases'][0];ref=row['support_reference']
            body=p[ref];p[ref]=body[:-1]+b',"source":"SYNTHETIC_DECLARATION_ONLY"}'
            row['support_sha256']=hashlib.sha256(p[ref]).hexdigest()
        self.reject('clave_duplicada',change)

    def test_oversized_support(self):
        def change(b,p):
            row=b['services'][0]['cases'][0];ref=row['support_reference']
            p[ref]=b'a'*2049;row['support_sha256']=hashlib.sha256(p[ref]).hexdigest()
        self.reject('soporte_alterado',change)

    def test_wrong_category_bound(self):
        def change(b,p):
            row=b['services'][0]['cases'][0];ref=row['support_reference']
            doc=json.loads(p[ref]);doc['category']='control';p[ref]=raw(doc)
            row['support_sha256']=hashlib.sha256(p[ref]).hexdigest()
        self.reject('soporte_no_corresponde',change)

    def test_wrong_service_bound(self):
        def change(b,p):
            row=b['services'][0]['cases'][0];ref=row['support_reference']
            doc=json.loads(p[ref]);doc['service_id']='SMB_01';p[ref]=raw(doc)
            row['support_sha256']=hashlib.sha256(p[ref]).hexdigest()
        self.reject('soporte_no_corresponde',change)

    def test_wrong_source_declared(self):
        def change(b,p):
            row=b['services'][0]['cases'][0];ref=row['support_reference']
            doc=json.loads(p[ref]);doc['source']='VERIFIED_PRODUCTION';p[ref]=raw(doc)
            row['support_sha256']=hashlib.sha256(p[ref]).hexdigest()
        self.reject('soporte_no_corresponde',change)

    def test_wrong_document_format(self):
        def change(b,p):
            row=b['services'][0]['cases'][0];ref=row['support_reference']
            doc=json.loads(p[ref]);doc['format']=FORMAT;p[ref]=raw(doc)
            row['support_sha256']=hashlib.sha256(p[ref]).hexdigest()
        self.reject('soporte_no_corresponde',change)

    def test_bad_ref_format(self):
        self.reject('referencia_invalida_o_reutilizada',lambda b,p:b['services'][0]['cases'][0].update(support_reference='../x'))

    def test_extra_support_schema_field(self):
        def change(b,p):
            row=b['services'][0]['cases'][0];ref=row['support_reference']
            doc=json.loads(p[ref]);doc['authority']=True;p[ref]=raw(doc)
            row['support_sha256']=hashlib.sha256(p[ref]).hexdigest()
        self.reject('soporte_esquema_invalido',change)

    def test_body_type_nonbytes(self):
        self.reject('soporte_ausente',lambda b,p:p.update({b['services'][0]['cases'][0]['support_reference']:'text'}))

    def test_service_broken_structure(self):
        self.reject('servicio_invalido',lambda b,p:b['services'][0].update(extra='x'))

    def test_row_broken_structure(self):
        self.reject('declaracion_invalida',lambda b,p:b['services'][0]['cases'][0].update(extra='x'))

    def test_undocumented_false_cannot_apply_control(self):
        v=self.view()
        self.assertTrue(any(c.declared.name=='FALSO' and c.comparison=='DIFIERE_SUPUESTO'
                            for u in v.units for c in u.items))
        self.assertTrue(all(not c.executable and not c.accredited
                            for u in v.units for c in u.items))


if __name__=='__main__':unittest.main()
