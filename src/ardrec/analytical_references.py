"""Resolución estructural de referencias; no concede autoridad ni evalúa guardas."""
from dataclasses import dataclass
import hashlib
import json
import re
from ardrec.analytical import AnalyticalProjection, ObjectReference, REFERENCE_ROLES
from ardrec.state import GlobalState

ROLES = ('characterization', *REFERENCE_ROLES)
OBJECT_FORMAT = 'ardrec-analytical-object-1'
MANIFEST_FORMAT = 'ardrec-analytical-references-1'
MAX_BYTES = 262144
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_OBJECTS = 896
MAX_INDEX = 2**63 - 1

class ReferenceError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)

def need(value, code):
    if not value:
        raise ReferenceError(code)

def identifier(value):
    need(type(value) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:-]{0,127}', value) is not None, 'identifier_invalid')

def fingerprint(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}', value) is not None, 'hash_invalid')

def fields(value, names):
    need(type(value) is dict and set(value) == set(names), 'fields_invalid')

def json_value(value, depth=0):
    need(depth <= 32, 'payload_too_deep')
    if value is None or type(value) in (str, bool):
        return
    if type(value) is int:
        need(-MAX_INDEX <= value <= MAX_INDEX, 'integer_out_of_range')
        return
    if type(value) is list:
        for child in value:
            json_value(child, depth + 1)
        return
    need(type(value) is dict and all(type(k) is str for k in value), 'payload_type_invalid')
    for child in value.values():
        json_value(child, depth + 1)

def canonical(value):
    try:
        json_value(value)
        raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('ascii')
        need(len(raw) <= MAX_BYTES, 'object_too_large')
        return raw
    except (ValueError, TypeError, RecursionError, UnicodeError) as error:
        if isinstance(error, ReferenceError):
            raise
        raise ReferenceError('json_invalid') from error

def decode(raw):
    need(type(raw) is bytes and len(raw) <= MAX_BYTES, 'object_bytes_invalid')
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate_key')
            result[key] = value
        return result
    def reject(_):
        raise ReferenceError('noninteger_number')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_float=reject, parse_constant=reject)
        need(canonical(value) == raw, 'noncanonical_object')
        return value
    except (ValueError, TypeError, RecursionError, UnicodeError) as error:
        if isinstance(error, ReferenceError):
            raise
        raise ReferenceError('json_invalid') from error

CONTEXT_FIELDS = ('record_id', 'execution_id', 'configuration_sha256', 'generation_index')

def context(value):
    fields(value, CONTEXT_FIELDS)
    identifier(value['record_id'])
    identifier(value['execution_id'])
    fingerprint(value['configuration_sha256'])
    generation = value['generation_index']
    need(type(generation) is int and 0 <= generation <= MAX_INDEX, 'generation_invalid')
    return tuple(value[k] for k in CONTEXT_FIELDS)

@dataclass(frozen=True, slots=True)
class ResolvedReferences:
    """Bytes verificados e inmutables, sin certificado de autenticidad o autoridad."""
    manifest_bytes: bytes
    object_bytes: tuple[bytes, ...]


def resolve_references(projections, manifest_bytes, *, expected_manifest_sha256, load_object):
    """La huella esperada debe provenir del llamador o de la generación durable anclada.

    load_object(sha256) devuelve bytes o FileNotFoundError. Las cargas son opacas:
    su integridad no demuestra autorización, evidencia válida ni verdad de guardas.
    """
    fingerprint(expected_manifest_sha256)
    need(type(manifest_bytes) is bytes and len(manifest_bytes) <= MAX_BYTES, 'manifest_bytes_invalid')
    need(hashlib.sha256(manifest_bytes).hexdigest() == expected_manifest_sha256, 'manifest_hash_mismatch')
    manifest = decode(manifest_bytes)
    fields(manifest, ('format', 'context', 'bindings'))
    need(manifest['format'] == MANIFEST_FORMAT, 'manifest_version_incompatible')
    target_context = context(manifest['context'])
    bindings = manifest['bindings']
    need(type(bindings) is list and 0 < len(bindings) <= MAX_OBJECTS, 'bindings_invalid')
    indexed = {}
    identifiers = set()
    keys = []
    for binding in bindings:
        fields(binding, ('service_scenario_id', 'role', 'reference', 'sha256'))
        for field in ('service_scenario_id', 'reference'):
            identifier(binding[field])
        fingerprint(binding['sha256'])
        need(type(binding['role']) is str and binding['role'] in ROLES, 'role_invalid')
        key = (binding['service_scenario_id'], binding['role'])
        need(key not in indexed and binding['reference'] not in identifiers, 'ambiguous_binding')
        indexed[key] = ObjectReference(binding['reference'], binding['sha256'])
        identifiers.add(binding['reference'])
        keys.append(key)
    need(keys == sorted(keys), 'binding_order_invalid')
    need(type(projections) is tuple and 0 < len(projections) <= MAX_OBJECTS // len(ROLES)
         and all(type(p) is AnalyticalProjection for p in projections), 'projections_invalid')
    services = [p.service_scenario_id for p in projections]
    need(services == sorted(set(services)), 'projection_order_or_duplicate')
    need(set(indexed) == {(s, r) for s in services for r in ROLES}, 'reference_scope_mismatch')
    for p in projections:
        need(tuple(getattr(p, k) for k in CONTEXT_FIELDS) == target_context, 'projection_context_mismatch')
        for role, ref in zip(ROLES, (p.frozen.characterization, *p.references)):
            need(indexed[(p.service_scenario_id, role)] == ref, 'projection_reference_mismatch')
    resolved = []
    total = len(manifest_bytes)
    for binding in bindings:
        try:
            raw = load_object(binding['sha256'])
        except FileNotFoundError as error:
            raise ReferenceError('referenced_object_missing') from error
        need(type(raw) is bytes and len(raw) <= MAX_BYTES, 'object_bytes_invalid')
        total += len(raw)
        need(total <= MAX_TOTAL_BYTES, 'reference_set_too_large')
        need(hashlib.sha256(raw).hexdigest() == binding['sha256'], 'object_hash_mismatch')
        obj = decode(raw)
        fields(obj, ('format', 'context', 'service_scenario_id', 'role', 'reference', 'payload'))
        need(obj['format'] == OBJECT_FORMAT, 'object_version_incompatible')
        origin = context(obj['context'])
        need(origin[:3] == target_context[:3], 'object_context_mismatch')
        need(origin[3] <= target_context[3], 'future_object')
        need(all(obj[k] == binding[k] for k in ('service_scenario_id', 'role', 'reference')), 'object_identity_mismatch')
        need(type(obj['payload']) is dict, 'payload_object_required')
        resolved.append(raw)
    return ResolvedReferences(manifest_bytes, tuple(resolved))


def check_operational_alignment(projections, operational):
    """Comparar con la parte confirmada; no comprobar ni promover su autoridad."""
    need(type(operational) is GlobalState and not operational.simulation, 'operational_state_invalid')
    need(type(projections) is tuple and all(type(p) is AnalyticalProjection for p in projections), 'projections_invalid')
    actual = {p.service_scenario_id: p.operational_state for p in projections}
    expected = {s.service_scenario_id: s.phase for s in operational.confirmed.services}
    need(len(actual) == len(projections) and actual == expected, 'operational_scope_or_phase_mismatch')
    confirmed = operational.confirmed
    for p in projections:
        need(tuple(getattr(p, k) for k in CONTEXT_FIELDS) ==
             (confirmed.record_id, operational.execution_id, confirmed.configuration_sha256, confirmed.generation),
             'operational_context_mismatch')
