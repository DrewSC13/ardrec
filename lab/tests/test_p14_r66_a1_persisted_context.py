"""Oráculos R66: recuperación A1 desde bytes canónicos y archivo privado pinneado.

Sin red, ejecutor, cambios de estado ni autorización P8.
"""
from __future__ import annotations

from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from ardrec.initialization.rule_preflight import preflight_rule_configuration
from ardrec.persistence.codec import canonical, pack
from ardrec.rules.kernel import A1Error
from ardrec.rules.persisted_context import (
    RecoveredA1Decision, evaluate_recovered_a1, evaluate_recovered_a1_file,
    read_pinned_state_file, restore_confirmed_state,
)
from ardrec.state import Truth
from test_p14_r65_a1_confirmed_context import config, confirmed

KW = dict(case_id='CASE_POLICY', condition_id='COND_FACT', context_id='CTX_R66_001')


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class A1PersistedSourceOracle(unittest.TestCase):
    def setUp(self):
        self.frozen = preflight_rule_configuration(config())
        self.state = confirmed()
        self.raw = canonical(pack(self.state))
        self.pin = sha(self.raw)
        self.env = {'FACT': Truth.VERDADERO}

    def evaluate(self, raw=None, pin=None, env=None, **kwargs):
        return evaluate_recovered_a1(
            self.frozen, self.raw if raw is None else raw,
            self.pin if pin is None else pin, 'SSH_DEV',
            self.env if env is None else env, **(KW | kwargs))

    def test_01_exact_codec_restores_real_confirmed_state(self):
        restored = restore_confirmed_state(self.raw, self.pin)
        self.assertEqual(restored, self.state)
        self.assertEqual(canonical(pack(restored)), self.raw)

    def test_02_emits_pinned_state_and_actual_a1_decision(self):
        r = self.evaluate()
        document = json.loads(r.source)
        self.assertEqual(document['state_storage_sha256'], self.pin)
        self.assertEqual(document['rules_source_sha256'], self.frozen.sha256)
        self.assertEqual(document['confirmed_model_receipt']['a1_contextual']['estado_tabla'],
                         'VERDADERO')
        self.assertEqual(document['confirmed_model_receipt']['a1_contextual']['salida_declarativa'],
                         'CASE_POLICY')
        self.assertTrue(document['canonical_codec_verified'])
        self.assertTrue(r.verify(self.frozen, self.raw, self.pin,
                                 'SSH_DEV', self.env, **KW))

    def test_03_individual_false_and_no_matching_table_nd(self):
        result = self.evaluate(env={'FACT': Truth.FALSO})
        inner = json.loads(result.source)['confirmed_model_receipt']['a1_contextual']
        self.assertEqual(inner['estado_tabla'], 'ND')
        self.assertEqual(inner['evaluaciones'],
                         [{'id': 'ALLOW', 'valor': 'FALSO'},
                          {'id': 'NEVER', 'valor': 'FALSO'}])

    def test_04_optional_missing_yields_nd(self):
        result = self.evaluate(env={})
        inner = json.loads(result.source)['confirmed_model_receipt']['a1_contextual']
        self.assertEqual(inner['estado_tabla'], 'ND')
        self.assertEqual(inner['evaluaciones'][0]['valor'], 'ND')

    def test_05_a1_does_not_grant_operational_authority(self):
        r = self.evaluate()
        self.assertFalse(r.operationally_authorized)
        self.assertIsNone(r.published_generation)
        j = json.loads(r.source)
        for key in ('trusted_pin_origin_attested', 'a9_durable_generation_attested',
                    'global_configuration_rules_binding_attested',
                    'physical_origin_attested', 'operational_dispatch'):
            self.assertIs(j[key], False)
        self.assertIsNone(j['published_generation'])
        self.assertEqual(j['p8_operational'], 'NO-GO')

    def test_06_deterministic_byte_identity(self):
        self.assertEqual(self.evaluate(), self.evaluate())
        self.assertEqual(self.evaluate().sha256, sha(self.evaluate().source))

    def test_07_wrong_storage_pin_rejected(self):
        with self.assertRaisesRegex(A1Error, 'estado_serializado_hash_invalido'):
            self.evaluate(pin='0' * 64)

    def test_08_malformed_pin_rejected(self):
        for bad in (None, 'bad', 'A' * 64, '', 4, True):
            with self.subTest(pin=bad), self.assertRaisesRegex(A1Error, 'pin_estado_invalido'):
                restore_confirmed_state(self.raw, bad)

    def test_09_noncanonical_json_rejected_with_matching_pin(self):
        bad = self.raw.replace(b'"@":', b'"@" :', 1)
        self.assertNotEqual(bad, self.raw)
        with self.assertRaisesRegex(A1Error, 'estado_serializado_invalido'):
            restore_confirmed_state(bad, sha(bad))

    def test_10_wrong_object_type_rejected(self):
        raw = canonical(pack('NOT_CONFIRMED'))
        with self.assertRaisesRegex(A1Error, 'objeto_no_es_estado_confirmado'):
            restore_confirmed_state(raw, sha(raw))

    def test_11_empty_and_oversized_payload_rejected(self):
        for raw in (b'', b'x' * (1024 * 1024 + 1)):
            with self.subTest(n=len(raw)), self.assertRaisesRegex(
                    A1Error, 'estado_serializado_tamano_invalido'):
                restore_confirmed_state(raw, sha(raw))

    def test_12_duplicate_json_keys_fail_closed(self):
        bad = b'{"@":"ConfirmedState","@":"ConfirmedState","fields":{}}'
        with self.assertRaisesRegex(A1Error, 'estado_serializado_invalido'):
            restore_confirmed_state(bad, sha(bad))

    def test_13_tampered_state_with_new_pin_changes_decision_receipt(self):
        modified = confirmed(generation=1, generation_ref='GENERATION_1')
        raw = canonical(pack(modified))
        new = self.evaluate(raw=raw, pin=sha(raw))
        old = self.evaluate()
        self.assertNotEqual(new.source, old.source)
        with self.assertRaisesRegex(A1Error, 'recibo_recuperado_no_coincide'):
            old.verify(self.frozen, raw, sha(raw), 'SSH_DEV', self.env, **KW)

    def test_14_changed_environment_invalidates_replay(self):
        old = self.evaluate()
        with self.assertRaisesRegex(A1Error, 'recibo_recuperado_no_coincide'):
            old.verify(self.frozen, self.raw, self.pin,
                       'SSH_DEV', {'FACT': Truth.FALSO}, **KW)

    def test_15_changed_context_invalidates_replay(self):
        old = self.evaluate()
        with self.assertRaisesRegex(A1Error, 'recibo_recuperado_no_coincide'):
            old.verify(self.frozen, self.raw, self.pin, 'SSH_DEV', self.env,
                       **(KW | {'context_id': 'CTX_OTHER'}))

    def test_16_forged_rehashed_receipt_rejected(self):
        old = self.evaluate()
        doc = json.loads(old.source)
        doc['confirmed_model_receipt']['a1_contextual']['estado'] = 'DETENIDO'
        forged_bytes = json.dumps(doc, sort_keys=True, separators=(',', ':'),
                                  ensure_ascii=True).encode('ascii')
        fake = RecoveredA1Decision(forged_bytes, sha(forged_bytes), old.storage_sha256,
                                   old.rules_sha256, old.source_mode)
        self.assertEqual(fake.json_bytes(), forged_bytes)
        with self.assertRaisesRegex(A1Error, 'recibo_recuperado_no_coincide'):
            fake.verify(self.frozen, self.raw, self.pin, 'SSH_DEV', self.env, **KW)

    def test_17_invalid_self_hash_detected(self):
        old = self.evaluate()
        fake = RecoveredA1Decision(old.source, '0'*64, old.storage_sha256,
                                   old.rules_sha256, old.source_mode)
        with self.assertRaisesRegex(A1Error, 'recibo_recuperado_alterado'):
            fake.json_bytes()

    def test_18_receipt_is_frozen(self):
        r = self.evaluate()
        with self.assertRaises(FrozenInstanceError):
            r.source = b''

    def test_19_source_mode_cannot_be_forged_via_public_bytes_api(self):
        with self.assertRaises(TypeError):
            self.evaluate(source_mode='READONLY_FILE')

    def test_20_normal_file_read_preserves_contents_and_permissions(self):
        with tempfile.TemporaryDirectory() as name:
            p = Path(name) / 'confirmed-state.json'
            p.write_bytes(self.raw)
            p.chmod(0o600)
            before = p.stat()
            self.assertEqual(read_pinned_state_file(p, self.pin), self.raw)
            r = evaluate_recovered_a1_file(self.frozen, p, self.pin,
                                           'SSH_DEV', self.env, **KW)
            j = json.loads(r.source)
            self.assertEqual(j['source_mode'], 'READONLY_FILE')
            self.assertEqual(j['state_storage_sha256'], self.pin)
            self.assertEqual(p.read_bytes(), self.raw)
            self.assertEqual(p.stat().st_mode, before.st_mode)
            self.assertFalse(j['a9_durable_generation_attested'])
            self.assertTrue(r.verify_file(self.frozen, p, self.pin,
                                          'SSH_DEV', self.env, **KW))
            with self.assertRaisesRegex(A1Error, 'verificacion_archivo_requerida'):
                r.verify(self.frozen, self.raw, self.pin, 'SSH_DEV', self.env, **KW)

    def test_21_symlink_file_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            p = Path(name) / 'source.json'
            p.write_bytes(self.raw)
            p.chmod(0o600)
            link = Path(name) / 'link.json'
            link.symlink_to(p)
            with self.assertRaisesRegex(A1Error, 'ruta_estado_insegura'):
                read_pinned_state_file(link, self.pin)

    def test_22_symlink_parent_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            base = Path(name)
            real = base / 'real'
            real.mkdir()
            p = real / 'source.json'
            p.write_bytes(self.raw)
            p.chmod(0o600)
            fake = base / 'alias'
            fake.symlink_to(real, target_is_directory=True)
            with self.assertRaisesRegex(A1Error, 'ruta_estado_insegura'):
                read_pinned_state_file(fake / 'source.json', self.pin)

    def test_23_group_read_permission_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            p = Path(name) / 'source.json'
            p.write_bytes(self.raw)
            p.chmod(0o640)
            with self.assertRaisesRegex(A1Error, 'archivo_estado_permisos_invalidos'):
                read_pinned_state_file(p, self.pin)

    def test_24_hardlink_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            p = Path(name) / 'source.json'
            p.write_bytes(self.raw)
            p.chmod(0o600)
            os.link(p, Path(name) / 'another.json')
            with self.assertRaisesRegex(A1Error, 'archivo_estado_permisos_invalidos'):
                read_pinned_state_file(p, self.pin)

    def test_25_wrong_file_digest_rejected(self):
        with tempfile.TemporaryDirectory() as name:
            p = Path(name) / 'source.json'
            p.write_bytes(self.raw)
            p.chmod(0o600)
            with self.assertRaisesRegex(A1Error, 'estado_serializado_hash_invalido'):
                read_pinned_state_file(p, '0' * 64)

    def test_26_relative_and_missing_path_rejected(self):
        with self.assertRaisesRegex(A1Error, 'ruta_estado_invalida'):
            read_pinned_state_file(Path('foo.json'), self.pin)
        with tempfile.TemporaryDirectory() as name:
            with self.assertRaisesRegex(A1Error, 'ruta_estado_insegura'):
                read_pinned_state_file(Path(name) / 'missing.json', self.pin)

    def test_27_absent_service_rejected(self):
        with self.assertRaisesRegex(A1Error, 'servicio_no_confirmado'):
            evaluate_recovered_a1(self.frozen, self.raw, self.pin,
                                  'FTP_DEV', self.env, **KW)

    def test_28_bad_environment_type_rejected(self):
        with self.assertRaisesRegex(A1Error, 'ambiente_tipo_invalido'):
            self.evaluate(env={'FACT': True})

    def test_29_source_mode_parameter_disallowed_for_public_bytes_api(self):
        with self.assertRaises(TypeError):
            self.evaluate(source_mode=None)

    def test_30_noncanonical_storage_bytes_cannot_be_self_attested(self):
        # El pin calculado sobre bytes manipulados no convierte el modelo en válido.
        doc = json.loads(self.raw)
        doc['fields']['services']['value'].append({'@':'ServiceState', 'fields': {}})
        forged = canonical(doc)
        with self.assertRaisesRegex(A1Error, 'estado_serializado_invalido'):
            restore_confirmed_state(forged, sha(forged))


if __name__ == '__main__':
    unittest.main()
