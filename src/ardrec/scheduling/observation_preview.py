"""P14-R25 / A3: conciliación de declaraciones sintéticas con su soporte binario.

SHA-256 comprueba identidad e integridad de bytes, NO la veracidad del contenido.
Ninguna declaración equivale a evidencia acreditada, resultado ejecutado,
autorización P8 ni estado confirmado. No lee archivos o red ni ejecuta acciones.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any

from ardrec.initialization.rule_preflight import FrozenRulePreview
from ardrec.initialization.initial_preview import InitialPreview
from ardrec.initialization.dependency_preview import DependencyPreview
from ardrec.initialization.control_preview import ControlPreview
from ardrec.initialization.integrated_preview import IntegratedPreview
from ardrec.scheduling.guard_preview import GuardDiagnosticPreview
from ardrec.scheduling.agenda_preview import CandidateAgendaPreview
from ardrec.scheduling.readiness_preview import ReadinessPreview
from ardrec.state import Truth

FORMAT = 'ardrec-p14-r25-a3-documentary-reconciliation-v1'
DOCUMENT_FORMAT = 'ardrec-p14-r25-synthetic-declaration-v1'
MAX_BATCH_BYTES = 262144
MAX_REPORT_BYTES = 393216
MAX_SUPPORT_BYTES = 2048
MAX_TOTAL_SUPPORT_BYTES = 262144
REF = re.compile(r'[A-Z][A-Z0-9_]{0,63}\Z', re.ASCII)
HASH = re.compile(r'[0-9a-f]{64}\Z', re.ASCII)


class ObservationError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _need(ok: bool, code: str) -> None:
    if not ok:
        raise ObservationError(code)


def _keys(doc: Any, keys: set[str], code: str) -> None:
    _need(type(doc) is dict and set(doc) == keys, code)


def _canonical(doc: Any, max_bytes: int) -> bytes:
    try:
        raw = json.dumps(doc, sort_keys=True, separators=(',', ':'),
                         ensure_ascii=True, allow_nan=False).encode('ascii')
    except (ValueError, TypeError, OverflowError, UnicodeError, RecursionError) as exc:
        raise ObservationError('serializacion_invalida') from exc
    _need(len(raw) <= max_bytes, 'documento_excesivo')
    return raw


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        _need(k not in out, 'clave_duplicada')
        out[k] = v
    return out


def _parse(raw: bytes, max_bytes: int) -> dict[str, Any]:
    _need(type(raw) is bytes and len(raw) <= max_bytes, 'bytes_invalidos')
    try:
        doc = json.loads(raw, object_pairs_hook=_unique_pairs)
    except ObservationError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise ObservationError('json_invalido') from exc
    _need(type(doc) is dict and _canonical(doc, max_bytes) == raw, 'json_no_canonico')
    return doc


@dataclass(frozen=True, slots=True)
class DocumentaryItem:
    category: str
    item_id: str
    declared: Truth
    assumed: Truth
    comparison: str  # SIN_DECLARACION, COINCIDE_SUPUESTO, DIFIERE_SUPUESTO
    support_reference: str | None
    support_sha256: str | None

    @property
    def accredited(self) -> bool:
        return False

    @property
    def executable(self) -> bool:
        return False


@dataclass(frozen=True, slots=True)
class DocumentaryUnit:
    service_id: str
    protocol: str
    items: tuple[DocumentaryItem, ...]


@dataclass(frozen=True, slots=True)
class DocumentaryPreview:
    source: bytes
    sha256: str
    batch_source: bytes
    batch_sha256: str
    candidate_sha256: str
    readiness_sha256: str
    units: tuple[DocumentaryUnit, ...]

    def verify(self, rules: FrozenRulePreview, initial: InitialPreview,
               dependencies: DependencyPreview, controls: ControlPreview,
               integrated: IntegratedPreview, diagnostic: GuardDiagnosticPreview,
               environments: dict[str, dict[str, Any]],
               candidates: CandidateAgendaPreview, scenario: dict[str, Any],
               readiness: ReadinessPreview, batch: dict[str, Any],
               support_blobs: dict[str, bytes]) -> bool:
        _need(type(self.sha256) is str and type(self.source) is bytes
              and hashlib.sha256(self.source).hexdigest() == self.sha256,
              'informe_alterado')
        _need(type(self.batch_sha256) is str and type(self.batch_source) is bytes
              and hashlib.sha256(self.batch_source).hexdigest() == self.batch_sha256,
              'lote_alterado')
        _need(self.candidate_sha256 == candidates.sha256
              and self.readiness_sha256 == readiness.sha256, 'origen_alterado')
        source, original, units = _compose(
            rules, initial, dependencies, controls, integrated, diagnostic,
            environments, candidates, scenario, readiness, batch, support_blobs)
        _parse(self.source, MAX_REPORT_BYTES)
        _parse(self.batch_source, MAX_BATCH_BYTES)
        _need((source, original, units) == (self.source, self.batch_source, self.units),
              'conciliacion_inconsistente')
        return True

    @property
    def operational_dispatch_allowed(self) -> bool:
        return False

    @property
    def executable_agenda(self) -> None:
        return None

    @property
    def published_generation(self) -> None:
        return None


def _compose(rules: FrozenRulePreview, initial: InitialPreview,
             dependencies: DependencyPreview, controls: ControlPreview,
             integrated: IntegratedPreview, diagnostic: GuardDiagnosticPreview,
             environments: dict[str, dict[str, Any]],
             candidates: CandidateAgendaPreview, scenario: dict[str, Any],
             readiness: ReadinessPreview, batch: dict[str, Any],
             support_blobs: dict[str, bytes]
             ) -> tuple[bytes, bytes, tuple[DocumentaryUnit, ...]]:
    _need(type(readiness) is ReadinessPreview and type(candidates) is CandidateAgendaPreview
          and type(integrated) is IntegratedPreview, 'fuentes_invalidas')
    readiness.verify(rules, initial, dependencies, controls, integrated,
                     diagnostic, environments, candidates, scenario)
    _keys(batch, {'format', 'candidate_sha256', 'readiness_sha256', 'services'},
          'lote_invalido')
    _need(batch['format'] == FORMAT, 'formato_incompatible')
    _need(batch['candidate_sha256'] == candidates.sha256
          and batch['readiness_sha256'] == readiness.sha256, 'origen_no_coincide')
    _need(type(support_blobs) is dict, 'soportes_invalidos')
    _need(type(batch['services']) is list and len(batch['services']) == len(integrated.units),
          'servicios_invalidos')
    contract = {u.service_id: u for u in integrated.units}
    scenario_by_service = {u['id']:u for u in scenario['services']}
    _need(len(contract) == len(integrated.units)
          and len(scenario_by_service) == len(integrated.units)
          and set(contract) == set(scenario_by_service), 'fuentes_inconsistentes')
    norm_services = []
    results = []
    used_refs: set[str] = set()
    support_digests: dict[str, str] = {}
    for entry in batch['services']:
        _keys(entry, {'id', 'cases', 'controls'}, 'servicio_invalido')
        sid = entry['id']
        _need(type(sid) is str and sid in contract
              and sid not in {u.service_id for u in results}, 'servicio_ajeno_o_duplicado')
        unit = contract[sid]
        original = scenario_by_service[sid]
        out_items = []
        grouped = {}
        for key, member, source_key in (
            ('cases', 'case', 'cases'), ('controls', 'control', 'controls')
        ):
            expected = {c[0] for c in getattr(unit, source_key)}
            assumed = {i['id']:Truth[i['assumed']] for i in original[key]}
            _need(type(entry[key]) is list and len(entry[key]) == len(expected),
                  'elementos_incompletos')
            found: dict[str, dict[str, Any]] = {}
            for row in entry[key]:
                _keys(row, {'id', 'declared', 'support_reference', 'support_sha256'},
                      'declaracion_invalida')
                item = row['id']
                _need(type(item) is str and item in expected and item not in found,
                      'elemento_ajeno_o_duplicado')
                state = row['declared']
                _need(type(state) is str and state in Truth.__members__,
                      'valor_declarado_invalido')
                ref, digest = row['support_reference'], row['support_sha256']
                if state == 'ND':
                    _need(ref is None and digest is None, 'nd_con_soporte')
                else:
                    _need(type(ref) is str and REF.fullmatch(ref) is not None
                          and ref not in used_refs, 'referencia_invalida_o_reutilizada')
                    _need(type(digest) is str and HASH.fullmatch(digest) is not None,
                          'huella_soporte_invalida')
                    used_refs.add(ref)
                    _need(ref in support_blobs and type(support_blobs[ref]) is bytes,
                          'soporte_ausente')
                    raw = support_blobs[ref]
                    _need(len(raw) <= MAX_SUPPORT_BYTES
                          and hashlib.sha256(raw).hexdigest() == digest,
                          'soporte_alterado')
                    doc = _parse(raw, MAX_SUPPORT_BYTES)
                    _keys(doc, {'format', 'source', 'service_id', 'category',
                                'item_id', 'declaration'}, 'soporte_esquema_invalido')
                    _need(doc == {
                        'format':DOCUMENT_FORMAT, 'source':'SYNTHETIC_DECLARATION_ONLY',
                        'service_id':sid, 'category':member, 'item_id':item,
                        'declaration':state}, 'soporte_no_corresponde')
                    support_digests[ref] = digest
                found[item] = {'id':item, 'declared':state,
                               'support_reference':ref, 'support_sha256':digest}
            _need(set(found) == expected, 'elementos_incompletos')
            grouped[key] = [found[i] for i in sorted(found)]
            for item in sorted(found):
                row = found[item]
                declared = Truth[row['declared']]
                previous = assumed[item]
                comparison = ('SIN_DECLARACION' if declared is Truth.ND else
                              'COINCIDE_SUPUESTO' if declared is previous else
                              'DIFIERE_SUPUESTO')
                out_items.append(DocumentaryItem(member, item, declared, previous,
                                                 comparison, row['support_reference'],
                                                 row['support_sha256']))
        norm_services.append({'id':sid, **grouped})
        results.append(DocumentaryUnit(sid, unit.protocol, tuple(out_items)))
    _need(type(support_blobs) is dict and set(support_blobs) == used_refs,
          'soportes_extras_o_ausentes')
    _need(sum(len(support_blobs[ref]) for ref in used_refs) <= MAX_TOTAL_SUPPORT_BYTES,
          'soportes_excesivos')
    norm_services.sort(key=lambda d:d['id'])
    results.sort(key=lambda d:d.service_id)
    normalized = _canonical({'format':FORMAT, 'candidate_sha256':candidates.sha256,
                             'readiness_sha256':readiness.sha256,
                             'services':norm_services}, MAX_BATCH_BYTES)
    counts = {k:sum(item.comparison == k for u in results for item in u.items)
              for k in ('SIN_DECLARACION','COINCIDE_SUPUESTO','DIFIERE_SUPUESTO')}
    report = {
        'format':FORMAT, 'scope':'SYNTHETIC_DOCUMENT_INTEGRITY_ONLY_NO_FACT_AUTHORITY',
        'candidate_sha256':candidates.sha256, 'readiness_sha256':readiness.sha256,
        'batch_sha256':hashlib.sha256(normalized).hexdigest(),
        'support_digests':{ref:support_digests[ref] for ref in sorted(support_digests)},
        'comparison_counts':counts,
        'services':[{'id':u.service_id,'protocol':u.protocol,
                     'items':[{'category':r.category,'id':r.item_id,
                               'declared':r.declared.name,'assumed':r.assumed.name,
                               'comparison':r.comparison,
                               'support_reference':r.support_reference,
                               'support_sha256':r.support_sha256,
                               'accredited':False,'executable':False}
                              for r in u.items]}
                    for u in results],
        'integrity_verified':True,
        'technical_truth_accredited':False,
        'external_custody_verified':False,
        'operational_dispatch':False, 'executable_agenda':None,
        'generation_published':None, 'controls_applied':False, 'p8_operational':'NO-GO',
    }
    return _canonical(report, MAX_REPORT_BYTES), normalized, tuple(results)


def reconcile_documentary_observations(
        rules: FrozenRulePreview, initial: InitialPreview,
        dependencies: DependencyPreview, controls: ControlPreview,
        integrated: IntegratedPreview, diagnostic: GuardDiagnosticPreview,
        environments: dict[str, dict[str, Any]],
        candidates: CandidateAgendaPreview, scenario: dict[str, Any],
        readiness: ReadinessPreview, batch: dict[str, Any],
        support_blobs: dict[str, bytes]) -> DocumentaryPreview:
    """Reconcilia bytes declarados, sin inferir verdad material ni habilitar despacho."""
    source, normalized, units = _compose(
        rules, initial, dependencies, controls, integrated, diagnostic,
        environments, candidates, scenario, readiness, batch, support_blobs)
    result = DocumentaryPreview(source, hashlib.sha256(source).hexdigest(),
                                normalized, hashlib.sha256(normalized).hexdigest(),
                                candidates.sha256, readiness.sha256, units)
    result.verify(rules, initial, dependencies, controls, integrated,
                  diagnostic, environments, candidates, scenario, readiness,
                  batch, support_blobs)
    return result
