#!/usr/bin/env python3
"""Demostración R17: congelamiento sintético de tablas y consultas puras."""
from __future__ import annotations

from fractions import Fraction
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from ardrec.initialization.rule_preflight import FORMAT, preflight_rule_configuration
from ardrec.state import Truth


def constant(name):
    return {'op': 'CAMPO', 'nombre': name}


def main() -> int:
    config = {'format': FORMAT, 'fields': {'confirmacion': 'LOGICO', 'puntaje': 'RACIONAL'},
              'services': [
                  {'id': 'SSH_LAB', 'initial_state': 'PREPARADO', 'rules': [
                      {'id': 'permiso', 'condicion': constant('confirmacion')}]},
                  {'id': 'SMB_LAB', 'initial_state': 'PREPARADO', 'rules': [
                      {'id': 'suficiente', 'condicion': {'op': 'COMPARAR',
                         'relacion': 'MAYOR_IGUAL', 'izq': constant('puntaje'),
                         'der': {'op': 'CONSTANTE', 'tipo': 'RACIONAL', 'valor': '1/2'}}}]}
              ]}
    frozen = preflight_rule_configuration(config)
    # La mutación posterior no altera la instantánea congelada.
    config['services'][0]['rules'][0]['id'] = 'otro'
    choices = [
        frozen.evaluate_service('SSH_LAB', {}),
        frozen.evaluate_service('SSH_LAB', {'confirmacion': Truth.FALSO}),
        frozen.evaluate_service('SSH_LAB', {'confirmacion': Truth.VERDADERO}),
        frozen.evaluate_service('SMB_LAB', {'puntaje': Fraction(3, 4)}),
    ]
    results = [{'service': c.service_id, 'status': c.status.value,
                'selected_rule': c.selected_rule,
                'logical_guard_satisfied': c.logical_guard_satisfied,
                'operationally_authorized': c.operationally_authorized} for c in choices]
    output = {'schema': 'ardrec-p14-r17-a1-a2-preflight-demo-v1',
              'configuration_sha256': frozen.sha256, 'services': list(frozen.service_ids),
              'cases': results, 'a1_complete': False, 'a2_complete': False,
              'operational_dispatch': False, 'p8_operational': 'NO-GO'}
    assert [r['status'] for r in results] == ['ND', 'FALSO', 'VERDADERO', 'VERDADERO']
    assert all(r['operationally_authorized'] is False for r in results)
    print(json.dumps(output, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
