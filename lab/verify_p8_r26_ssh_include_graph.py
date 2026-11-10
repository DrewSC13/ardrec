#!/usr/bin/env python3
"""P8-R26 CI verifier: frozen *synthetic* sources only, never QCOW2 or ssh."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

import p8_r26_ssh_include_graph as model

HERE = Path(__file__).resolve().parent
SPEC = HERE/'p8-r26-ssh-include-graph-v1/spec.json'
FIXTURE = HERE/'p8-r26-ssh-include-graph-v1/cases.json'
SPEC_SHA = '601d19bd52fc8632e017b44aa5c52264548503bc184c669c2311829d23f9acc9'
FIXTURE_SHA = 'fe4793dd16b0837a22824e28379375e96ccdc12f47163fbbd211cc0584d0fd2c'


def verify() -> dict:
    model.need(hashlib.sha256(SPEC.read_bytes()).hexdigest() == SPEC_SHA,
               'spec_sha256_changed')
    model.need(hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == FIXTURE_SHA,
               'fixture_sha256_changed')
    spec = json.loads(SPEC.read_bytes())
    fixture = json.loads(FIXTURE.read_bytes())
    model.need(type(spec) is dict and spec['roadmap_step'] == 8 and
               spec['increment'] == 'P8-R26' and spec['base_main_commit'] == model.BASE_MAIN and
               spec['r25_private_receipt_sha256_operator_report_only'] == model.R25_SHA256 and
               spec['synthetic_fixture_sha256'] == FIXTURE_SHA and
               spec['scope'] == 'SYNTHETIC_BOUNDED_SSH_INCLUDE_CANDIDATE_GRAPH_SOURCE_ONLY',
               'spec_identity')
    for k in ('ci_reads_private_receipt','ci_reads_qcow2','ci_executes_ssh',
              'real_include_graph_resolved','effective_config_verified','dispatch_allowed',
              'p9_started','algorithms_a1_to_a10_started'):
        model.need(spec[k] is False, 'spec_scope_promotion:'+k)
    model.need(spec['authorized_profiles'] == spec['authorized_cases'] == 0 and
               spec['profile_count_total_unchanged'] == 29 and
               spec['binding_fields_pending_unchanged'] == 348 and
               spec['proof_gates_pending_unchanged'] == 261, 'spec_denial')
    model.need(spec['limits'] == {'source_count': model.MAX_SOURCES,
               'file_bytes': model.MAX_FILE_BYTES,'total_bytes': model.MAX_TOTAL_BYTES,
               'include_depth': model.MAX_DEPTH,'include_edges': model.MAX_EDGES,
               'include_visits': model.MAX_VISITS,'lines_per_file': model.MAX_LINES,
               'include_tokens_per_directive': model.MAX_INCLUDE_TOKENS}, 'spec_limits')
    model.need(fixture['schema_version'] == '1.0' and
               fixture['scope'] == 'SYNTHETIC_ONLY_NO_REAL_SSH_FILES' and
               len(fixture['cases']) == spec['synthetic_cases'] == 17, 'frozen_cases')
    pass_count = deny_count = 0
    for row in fixture['cases']:
        sources = {model.ROOT: row['root_text'].encode('utf-8')}
        sources.update({k: v.encode('utf-8') for k, v in row['files'].items()})
        aliases = ({model.ALIAS: model.ALIAS_TARGET}
                   if row['synthetic_alias_exact'] else {})
        try:
            result = model.analyze_synthetic_sources(sources, aliases=aliases)
        except model.GraphError:
            model.need(row['expect'] == 'FAIL_CLOSED', 'unexpected_case_denial:'+row['name'])
            deny_count += 1
            continue
        model.need(row['expect'] == result['status'] ==
                   'SYNTHETIC_GRAPH_CANDIDATES_ONLY_DENY_ALL', 'case_promotion:'+row['name'])
        model.need(result['candidate_edge_count'] == row['candidate_edges'] and
                   result['conditional_edges_not_evaluated'] == row['conditional_edges'] and
                   result['dispatch_allowed'] is False and
                   result['real_qcow2_access'] is False and
                   result['real_include_graph_resolved'] is False and
                   result['effective_ssh_configuration_verified'] is False,
                   'case_bad_contract:'+row['name'])
        pass_count += 1
    model.need(pass_count + deny_count == 17 and pass_count >= 6 and deny_count >= 5,
               'frozen_case_coverage')
    status = model.public_contract()
    model.need(status['dispatch_allowed'] is False and
               status['physical_include_graph_resolved'] is False and
               status['approved_profiles'] == 0, 'public_contract')
    return {'status': 'PASS_P8_R26_SYNTHETIC_INCLUDE_GRAPH_DENY_ALL',
            'synthetic_cases':17, 'synthetic_supported_cases':pass_count,
            'synthetic_rejected_cases':deny_count,
            'spec_sha256':SPEC_SHA,'fixture_sha256':FIXTURE_SHA,
            'physical_capture_new':False,'effective_ssh_config_verified':False,
            'authorized_profiles':0,'authorized_cases':0,'dispatch_allowed':False}


def main() -> int:
    try:
        print(json.dumps(verify(),sort_keys=True))
        return 0
    except (model.GraphError, OSError, ValueError, KeyError, TypeError) as error:
        print('P8_R26_VERIFY=FAIL_CLOSED:'+str(error),file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
