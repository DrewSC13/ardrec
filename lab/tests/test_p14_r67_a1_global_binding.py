"""R67: oráculo independiente de vínculo GlobalState/ConfirmedState y A1, sin P8."""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from ardrec.initialization.rule_preflight import preflight_rule_configuration
from ardrec.persistence.codec import canonical, pack
from ardrec.rules.global_binding import (
    GlobalA1Decision, evaluate_global_a1, evaluate_global_a1_files,
    restore_global_state,
)
from ardrec.rules.kernel import A1Error
from ardrec.state import GlobalState, Truth, ServiceState, ServicePhase
from test_p14_r65_a1_confirmed_context import config, confirmed

KW = {'case_id': 'CASE_POLICY', 'condition_id': 'COND_FACT',
      'context_id': 'CTX_R67_001'}


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class A1GlobalConfirmedIndependentOracle(unittest.TestCase):
    def setUp(self):
        self.frozen = preflight_rule_configuration(config())
        self.confirmed = confirmed()
        self.global_state = GlobalState(
            confirmed=self.confirmed, execution_id='EXECUTION_001',
            services=self.confirmed.services, authority=Truth.ND)
        self.global_raw = canonical(pack(self.global_state))
        self.confirmed_raw = canonical(pack(self.confirmed))
        self.global_pin = sha(self.global_raw)
        self.confirmed_pin = sha(self.confirmed_raw)
        self.env = {'FACT': Truth.VERDADERO}

    def evaluate(self, **options):
        inputs = {
            'global_raw': self.global_raw, 'global_pin': self.global_pin,
            'confirmed_raw': self.confirmed_raw, 'confirmed_pin': self.confirmed_pin,
            'service_id': 'SSH_DEV', 'environment': self.env,
        }
        inputs.update(KW)
        inputs.update(options)
        return evaluate_global_a1(self.frozen, **inputs)

    def test_01_global_state_restores_native_type(self):
        restored = restore_global_state(self.global_raw, self.global_pin)
        self.assertEqual(restored, self.global_state)
        self.assertEqual(canonical(pack(restored)), self.global_raw)

    def test_02_two_source_cross_binding(self):
        j = json.loads(self.evaluate().source)
        self.assertEqual(j['global_storage_sha256'], self.global_pin)
        self.assertEqual(j['confirmed_storage_sha256'], self.confirmed_pin)
        self.assertEqual(j['rules_source_sha256'], self.frozen.sha256)
        self.assertTrue(j['global_confirmed_model_identical'])
        self.assertTrue(j['no_unconfirmed_candidate_state'])
        self.assertTrue(j['no_pending_attempt'])

    def test_03_confirmed_a1_result_is_real_r66(self):
        j = json.loads(self.evaluate().source)
        nested = j['a1_recovered_receipt']
        self.assertEqual(nested['confirmed_model_receipt']['a1_contextual']['estado_tabla'],
                         'VERDADERO')
        self.assertEqual(nested['confirmed_model_receipt']['a1_contextual']['salida_declarativa'],
                         'CASE_POLICY')
        self.assertEqual(j['a1_recovered_receipt_sha256'],
                         sha(json.dumps(nested, sort_keys=True, separators=(',', ':'),
                                        ensure_ascii=True).encode('ascii')))

    def test_04_false_and_optional_nd_are_preserved(self):
        for env, expected in (({'FACT': Truth.FALSO}, 'FALSO'), ({}, 'ND')):
            with self.subTest(env=env):
                j = json.loads(self.evaluate(environment=env).source)
                a1 = j['a1_recovered_receipt']['confirmed_model_receipt']['a1_contextual']
                self.assertEqual(a1['estado_tabla'], 'ND')
                self.assertEqual(a1['evaluaciones'][0]['valor'], expected)

    def test_05_never_authorizes_or_publishes(self):
        r = self.evaluate()
        self.assertFalse(r.operationally_authorized)
        self.assertIsNone(r.published_generation)
        j = json.loads(r.source)
        for field in ('external_pin_authority_attested',
                      'a9_published_generation_attested',
                      'global_configuration_rules_binding_attested',
                      'physical_origin_attested', 'operational_dispatch'):
            self.assertIs(j[field], False)
        self.assertIsNone(j['published_generation'])
        self.assertEqual(j['p8_operational'], 'NO-GO')

    def test_06_rerun_and_verify_recomputes(self):
        a = self.evaluate()
        self.assertEqual(a, self.evaluate())
        self.assertEqual(sha(a.source), a.sha256)
        self.assertTrue(a.verify(self.frozen, self.global_raw, self.global_pin,
                                 self.confirmed_raw, self.confirmed_pin,
                                 'SSH_DEV', self.env, **KW))

    def test_07_wrong_global_pin_fails_closed(self):
        with self.assertRaisesRegex(A1Error, 'estado_global_hash_invalido'):
            self.evaluate(global_pin='0'*64)

    def test_08_invalid_global_pin_fails_closed(self):
        for bad in (None, True, 'F'*64, 'wrong', '', 2):
            with self.subTest(bad=bad), self.assertRaisesRegex(A1Error, 'pin_global_invalido'):
                restore_global_state(self.global_raw, bad)

    def test_09_wrong_confirmed_pin_fails_closed(self):
        with self.assertRaisesRegex(A1Error, 'estado_serializado_hash_invalido'):
            self.evaluate(confirmed_pin='0'*64)

    def test_10_different_confirmed_generation_must_not_bind(self):
        other = confirmed(generation=1, generation_ref='GENERATION_1')
        raw = canonical(pack(other))
        with self.assertRaisesRegex(A1Error, 'global_confirmado_no_coincide'):
            self.evaluate(confirmed_raw=raw, confirmed_pin=sha(raw))

    def test_11_different_global_generation_must_not_bind(self):
        newer = confirmed(generation=1, generation_ref='GENERATION_1')
        g = GlobalState(newer, 'EXECUTION_001', newer.services)
        raw = canonical(pack(g))
        with self.assertRaisesRegex(A1Error, 'global_confirmado_no_coincide'):
            self.evaluate(global_raw=raw, global_pin=sha(raw))

    def test_12_noncanonical_global_json_rejected(self):
        bad = self.global_raw.replace(b'"@":', b'"@" :', 1)
        self.assertNotEqual(bad, self.global_raw)
        with self.assertRaisesRegex(A1Error, 'estado_global_invalido'):
            restore_global_state(bad, sha(bad))

    def test_13_duplicate_object_key_rejected(self):
        raw = b'{"@":"GlobalState","@":"GlobalState","fields":{}}'
        with self.assertRaisesRegex(A1Error, 'estado_global_invalido'):
            restore_global_state(raw, sha(raw))

    def test_14_non_global_payload_rejected(self):
        raw = canonical(pack(self.confirmed))
        with self.assertRaisesRegex(A1Error, 'objeto_no_es_estado_global'):
            restore_global_state(raw, sha(raw))

    def test_15_size_and_empty_rejected(self):
        for bad in (b'', b'x'*(1024*1024+1)):
            with self.subTest(n=len(bad)), self.assertRaisesRegex(
                    A1Error, 'estado_global_tamano_invalido'):
                restore_global_state(bad, sha(bad))

    def test_16_external_global_authority_is_not_auto_accredited(self):
        claim = GlobalState(self.confirmed, 'EXECUTION_001', self.confirmed.services,
                            authority=Truth.VERDADERO)
        raw = canonical(pack(claim))
        j = json.loads(self.evaluate(global_raw=raw, global_pin=sha(raw)).source)
        self.assertEqual(j['global_authority_declared'], 'VERDADERO')
        self.assertFalse(j['external_pin_authority_attested'])
        self.assertFalse(j['operational_dispatch'])
        self.assertEqual(j['p8_operational'], 'NO-GO')

    def test_17_global_execution_identity_changes_receipt(self):
        other = GlobalState(self.confirmed, 'EXECUTION_OTHER', self.confirmed.services)
        raw = canonical(pack(other))
        self.assertNotEqual(self.evaluate().sha256,
                            self.evaluate(global_raw=raw, global_pin=sha(raw)).sha256)

    def test_18_global_simulation_flag_is_not_authority(self):
        other = GlobalState(self.confirmed, 'EXECUTION_001', self.confirmed.services,
                            simulation=True)
        raw = canonical(pack(other))
        j = json.loads(self.evaluate(global_raw=raw, global_pin=sha(raw)).source)
        self.assertTrue(j['global_simulation_declared'])
        self.assertFalse(j['operational_dispatch'])

    def test_19_wrong_service_rejected(self):
        with self.assertRaisesRegex(A1Error, 'servicio_no_confirmado'):
            self.evaluate(service_id='FTP_DEV')

    def test_20_wrong_environment_type_rejected(self):
        with self.assertRaisesRegex(A1Error, 'ambiente_tipo_invalido'):
            self.evaluate(environment={'FACT': True})

    def test_21_replay_rejects_changed_global_pin_and_context(self):
        r = self.evaluate()
        other = GlobalState(self.confirmed, 'EXECUTION_OTHER', self.confirmed.services)
        raw = canonical(pack(other))
        with self.assertRaisesRegex(A1Error, 'recibo_global_no_coincide'):
            r.verify(self.frozen, raw, sha(raw), self.confirmed_raw,
                     self.confirmed_pin, 'SSH_DEV', self.env, **KW)
        with self.assertRaisesRegex(A1Error, 'recibo_global_no_coincide'):
            r.verify(self.frozen, self.global_raw, self.global_pin,
                     self.confirmed_raw, self.confirmed_pin, 'SSH_DEV', self.env,
                     **(KW | {'context_id': 'CTX_DIFFERENT'}))

    def test_22_rehashing_a_forgery_does_not_authorize(self):
        r = self.evaluate()
        j = json.loads(r.source)
        j['external_pin_authority_attested'] = True
        raw = json.dumps(j, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True).encode('ascii')
        fake = GlobalA1Decision(raw, sha(raw), r.global_sha256,
                                r.confirmed_sha256, r.rules_sha256, r.source_mode)
        self.assertEqual(fake.json_bytes(), raw)
        with self.assertRaisesRegex(A1Error, 'recibo_global_no_coincide'):
            fake.verify(self.frozen, self.global_raw, self.global_pin,
                        self.confirmed_raw, self.confirmed_pin,
                        'SSH_DEV', self.env, **KW)

    def test_23_corrupt_receipt_hash_refused(self):
        r = self.evaluate()
        fake = GlobalA1Decision(r.source, '0'*64, r.global_sha256,
                                r.confirmed_sha256, r.rules_sha256, r.source_mode)
        with self.assertRaisesRegex(A1Error, 'recibo_global_alterado'):
            fake.json_bytes()

    def test_24_frozen_receipt(self):
        r = self.evaluate()
        with self.assertRaises(FrozenInstanceError):
            r.sha256 = '0'*64

    def test_25_private_two_file_readonly_roundtrip(self):
        with tempfile.TemporaryDirectory() as dirname:
            root = Path(dirname)
            gp = root/'global.json'; cp = root/'confirmed.json'
            for path, content in ((gp, self.global_raw), (cp, self.confirmed_raw)):
                path.write_bytes(content); path.chmod(0o600)
            before = ((gp.stat().st_mtime_ns, gp.read_bytes()),
                      (cp.stat().st_mtime_ns, cp.read_bytes()))
            r = evaluate_global_a1_files(self.frozen, gp, self.global_pin,
                                         cp, self.confirmed_pin, 'SSH_DEV',
                                         self.env, **KW)
            j = json.loads(r.source)
            self.assertEqual(j['source_mode'], 'READONLY_FILE')
            self.assertTrue(r.verify_files(self.frozen, gp, self.global_pin,
                                           cp, self.confirmed_pin, 'SSH_DEV',
                                           self.env, **KW))
            self.assertEqual(before, ((gp.stat().st_mtime_ns, gp.read_bytes()),
                                      (cp.stat().st_mtime_ns, cp.read_bytes())))
            with self.assertRaisesRegex(A1Error, 'modo_global_incorrecto'):
                r.verify(self.frozen, self.global_raw, self.global_pin,
                         self.confirmed_raw, self.confirmed_pin,
                         'SSH_DEV', self.env, **KW)

    def test_26_same_path_for_two_sources_rejected(self):
        with tempfile.TemporaryDirectory() as dirname:
            p = Path(dirname)/'single.json'
            p.write_bytes(self.global_raw); p.chmod(0o600)
            with self.assertRaisesRegex(A1Error, 'rutas_globales_no_independientes'):
                evaluate_global_a1_files(self.frozen, p, self.global_pin,
                                         p, self.confirmed_pin, 'SSH_DEV',
                                         self.env, **KW)

    def test_27_symlink_read_rejected(self):
        with tempfile.TemporaryDirectory() as dirname:
            root = Path(dirname)
            gp = root/'global.json'; cp = root/'confirmed.json'
            gp.write_bytes(self.global_raw); gp.chmod(0o600)
            cp.write_bytes(self.confirmed_raw); cp.chmod(0o600)
            link = root/'global_link.json'; link.symlink_to(gp)
            with self.assertRaisesRegex(A1Error, 'ruta_estado_insegura'):
                evaluate_global_a1_files(self.frozen, link, self.global_pin,
                                         cp, self.confirmed_pin, 'SSH_DEV',
                                         self.env, **KW)

    def test_28_group_readable_rejected(self):
        with tempfile.TemporaryDirectory() as dirname:
            root = Path(dirname)
            gp = root/'global.json'; cp = root/'confirmed.json'
            gp.write_bytes(self.global_raw); gp.chmod(0o640)
            cp.write_bytes(self.confirmed_raw); cp.chmod(0o600)
            with self.assertRaisesRegex(A1Error, 'archivo_estado_permisos_invalidos'):
                evaluate_global_a1_files(self.frozen, gp, self.global_pin,
                                         cp, self.confirmed_pin, 'SSH_DEV',
                                         self.env, **KW)

    def test_29_global_file_replay_detects_content_change(self):
        with tempfile.TemporaryDirectory() as dirname:
            root = Path(dirname)
            gp = root/'global.json'; cp = root/'confirmed.json'
            gp.write_bytes(self.global_raw); gp.chmod(0o600)
            cp.write_bytes(self.confirmed_raw); cp.chmod(0o600)
            r = evaluate_global_a1_files(self.frozen, gp, self.global_pin,
                                         cp, self.confirmed_pin, 'SSH_DEV',
                                         self.env, **KW)
            cp.write_bytes(b'{}')
            with self.assertRaisesRegex(A1Error, 'estado_serializado_hash_invalido'):
                r.verify_files(self.frozen, gp, self.global_pin, cp, self.confirmed_pin,
                               'SSH_DEV', self.env, **KW)

    def test_30_candidate_difference_guard_rejects_before_a1(self):
        # Inyecta un estado candidato divergente para probar directamente la
        # guarda, sin construir una transición operativa ni permitir P8.
        candidate = SimpleNamespace(
            confirmed=self.confirmed,
            services=(ServiceState('SSH_DEV', ServicePhase.PENDIENTE),),
            pending_attempts=(),
        )
        with patch('ardrec.rules.global_binding.restore_global_state',
                   return_value=candidate):
            with self.assertRaisesRegex(A1Error, 'candidato_global_no_confirmado'):
                self.evaluate()

    def test_31_pending_attempt_guard_rejects_before_a1(self):
        active = SimpleNamespace(
            confirmed=self.confirmed, services=self.confirmed.services,
            pending_attempts=('ATTEMPT_PENDING',),
        )
        with patch('ardrec.rules.global_binding.restore_global_state',
                   return_value=active):
            with self.assertRaisesRegex(A1Error, 'intento_global_pendiente'):
                self.evaluate()

    def test_32_legacy_r66_remains_independent(self):
        r = self.evaluate()
        self.assertEqual(r.source_mode, 'CANONICAL_BYTES')
        self.assertEqual(self.confirmed.generation_reference, 'GENERATION_0')
        self.assertFalse(json.loads(r.source)['a9_published_generation_attested'])


if __name__ == '__main__':
    unittest.main()
