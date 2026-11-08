"""P8-R8: thesis T1-T10 structural review, synthetic P8 denial and no mutation."""
from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from ardrec.state import (  # noqa: E402
    ClosureCriteria, ConfirmedState, GlobalState, GuardFact, InvocationPhase,
    ServicePhase as S, ServiceState, Transition as T, Truth,
)
from ardrec.p8_state_bridge import (  # noqa: E402
    BridgeError, DENIAL, GRAPH, SyntheticProposal, review_boundary,
)
from ardrec.p8_diagnostic import KNOWN_PROFILES  # noqa: E402

CORPUS = json.loads((ROOT / "tests/fixtures/p8-diagnostic-v1.json").read_text())
PAYLOAD = next(c["payload"] for c in CORPUS["cases"]
               if c["name"] == "profile_SSH-T01-BASE").encode("utf-8")
P8 = json.loads(PAYLOAD)
TRUE = Truth.VERDADERO

# Independent table, transcribed from thesis 3.5.3 T1-T10 / ADR 0004.
EDGES = {
    T.PREPARAR: ({S.PREPARADO}, S.PENDIENTE, {"preparation_authorized", "preconditions_valid"}),
    T.ACREDITAR_INICIO: ({S.PENDIENTE}, S.ACTIVO, {"start_verified"}),
    T.VALIDAR_RESULTADO: ({S.ACTIVO}, S.VALIDACION,
                          {"termination_verified", "cleanup_verified", "outcome_structured"}),
    T.APLICAR_RESULTADO: ({S.VALIDACION}, S.ACTUALIZADO,
                          {"outcome_processable", "effects_calculated"}),
    T.APLICAR_CONTROL: ({S.PENDIENTE}, S.ACTUALIZADO,
                        {"control_authorized", "effects_calculated"}),
    T.APLICAR_NO_INICIO: ({S.PENDIENTE}, S.ACTUALIZADO,
                          {"absence_verified", "effects_calculated"}),
    T.CONTINUAR: ({S.ACTUALIZADO}, S.PENDIENTE, {"work_available", "precedence_resolved"}),
    T.CERRAR: ({S.PENDIENTE, S.ACTUALIZADO}, S.CERRADO, {"precedence_resolved"}),
    T.PAUSAR: ({S.PENDIENTE, S.ACTUALIZADO}, S.PAUSADO,
               {"external_wait_registered", "pause_authorized", "precedence_resolved"}),
    T.REANUDAR: ({S.PAUSADO}, S.PENDIENTE,
                 {"new_authorization", "wait_resolved", "preconditions_valid"}),
    T.DETENER: (set(S) - {S.CERRADO, S.DETENIDO}, S.DETENIDO,
                {"cause_verified", "effect_processable"}),
}


def svc(phase: S) -> ServiceState:
    kwargs = {}
    if phase in {S.PAUSADO, S.CERRADO, S.DETENIDO}:
        kwargs["reason_reference"] = "REASON-1"
    if phase is S.PAUSADO:
        kwargs["wait_reference"] = "WAIT-1"
        kwargs["pause_authorization_reference"] = "PAUSE-AUTH-1"
    if phase is S.CERRADO:
        kwargs["closure"] = ClosureCriteria(*(GuardFact(
            name, TRUE if name == "ES" else Truth.FALSO, "REF-" + name
        ) for name in ("ES", "SA", "CV", "LE")))
    if phase is S.DETENIDO:
        kwargs["stop_cause"] = "SEGURIDAD"
    return ServiceState("S01", phase, **kwargs)


def state(phase: S = S.PENDIENTE, *, authority: Truth = Truth.ND) -> GlobalState:
    services = (svc(phase), ServiceState("S02", S.PENDIENTE))
    confirmed = ConfirmedState("REG-1", 1, "GEN-1", "a" * 64, "VERS-1", services)
    return GlobalState(confirmed, "EXE-1", services, authority=authority)


def proposal(route: T = T.APLICAR_CONTROL, *, values: Truth = TRUE) -> SyntheticProposal:
    return SyntheticProposal(
        stage="dev", service_id="S01", case_id=P8["case_id"],
        profile_id=P8["profile_id"], transition=route,
        generation=1, configuration_sha256="a" * 64,
        snapshot_sha256=P8["snapshot_sha256"],
        guards=tuple((name, values) for name in sorted(EDGES[route][2])),
    )


class P8StateBridgeTests(unittest.TestCase):
    def assert_deny(self, result):
        self.assertEqual(result.decision, DENIAL)
        self.assertFalse(result.authorized)
        self.assertFalse(result.dispatch_allowed)
        self.assertFalse(result.transition_applied)
        self.assertFalse(result.publication_allowed)
        self.assertEqual(result.real_cases_authorized, 0)

    def test_graph_exact_t1_to_t10_with_t5_variants(self):
        self.assertEqual(set(GRAPH), set(T))
        self.assertEqual(len(GRAPH), 11)
        for route, (origins, dest, names) in EDGES.items():
            self.assertEqual(GRAPH[route], (frozenset(origins), dest, frozenset(names)))

    def test_all_eight_origins_and_eleven_transitions(self):
        for route, (origins, dest, _) in EDGES.items():
            for phase in S:
                with self.subTest(route=route.value, phase=phase.value):
                    if phase in {S.ACTIVO, S.VALIDACION, S.ACTUALIZADO}:
                        # Actual state model forbids these as confirmed phases:
                        # the existing state test helper creates valid local candidates.
                        from test_state import phase_state
                        s = phase_state(phase)
                    else:
                        s = state(phase)
                    review = review_boundary(s, proposal(route), PAYLOAD)
                    self.assert_deny(review)
                    self.assertEqual(review.origin_compatible, phase in origins)
                    self.assertEqual(review.hypothetical_target, dest.value if phase in origins else None)
                    self.assertIs(s.services[0].phase, phase)
                    self.assertEqual(s.confirmed.generation, 1)

    def test_true_guards_are_structural_not_authority(self):
        s = state(S.PENDIENTE, authority=TRUE)
        r = review_boundary(s, proposal(), PAYLOAD)
        self.assertEqual(r.boundary_reason, "P8_R8_SYNTHETIC_ONLY_DENY_ALL")
        self.assertEqual(r.p8_reason, "P8_R7_UNVERIFIED_AUTHORITY")
        self.assertTrue(r.synthetic_guards_all_true)
        self.assertEqual(r.hypothetical_target, S.ACTUALIZADO.value)
        self.assert_deny(r)

    def test_unknown_and_false_guards_block(self):
        for value in (Truth.ND, Truth.FALSO):
            with self.subTest(value=value.value):
                r = review_boundary(state(), proposal(values=value), PAYLOAD)
                self.assertEqual(r.boundary_reason, "P8_R8_GUARDS_NOT_VERIFIED")
                self.assertFalse(r.synthetic_guards_all_true)
                self.assertIsNone(r.hypothetical_target)
                self.assert_deny(r)

    def test_unexpected_or_duplicate_guard_rejected(self):
        base = proposal()
        for guards in ((), (("wrong", TRUE),), (base.guards[0], base.guards[0])):
            with self.subTest(guards=guards):
                with self.assertRaises(BridgeError):
                    replace(base, guards=guards)

    def test_identity_mismatch_cannot_authorize(self):
        for changed in (
            {"stage": "pilot"}, {"case_id": "SSH-T01-S02-01"},
            {"profile_id": "SSH-T02-BASE"}, {"snapshot_sha256": "b" * 64},
        ):
            with self.subTest(changed=changed):
                r = review_boundary(state(), replace(proposal(), **changed), PAYLOAD)
                self.assertEqual(r.boundary_reason, "P8_R8_IDENTITY_MISMATCH")
                self.assert_deny(r)

    def test_generation_and_configuration_stale(self):
        for changed in ({"generation": 2}, {"configuration_sha256": "b" * 64}):
            r = review_boundary(state(), replace(proposal(), **changed), PAYLOAD)
            self.assertEqual(r.boundary_reason, "P8_R8_STALE_CONFIGURATION")
            self.assert_deny(r)

    def test_no_service_scope_and_terminal_states(self):
        r = review_boundary(state(), replace(proposal(), service_id="S99"), PAYLOAD)
        self.assertEqual(r.boundary_reason, "P8_R8_SERVICE_OUT_OF_SCOPE")
        for terminal in (S.CERRADO, S.DETENIDO):
            r = review_boundary(state(terminal), proposal(), PAYLOAD)
            self.assertEqual(r.boundary_reason, "P8_R8_ORIGIN_FORBIDDEN")
            self.assertFalse(r.origin_compatible)
            self.assert_deny(r)

    def test_malformed_and_duplicate_json_rejected(self):
        raw = PAYLOAD[:-1] + b',"profile_id":"SSH-T02-BASE"}'
        for specimen in (b'', b'{', raw, b'\xff', b' ' * 4097, b'{"x":NaN}'):
            with self.subTest(specimen=specimen[:30]):
                r = review_boundary(state(), proposal(), specimen)
                self.assertEqual(r.boundary_reason, "P8_R8_DIAGNOSTIC_INVALID")
                self.assert_deny(r)

    def test_all_shared_p8_vectors_still_denied(self):
        self.assertEqual(len(CORPUS["cases"]), 106)
        for case in CORPUS["cases"]:
            with self.subTest(case=case["name"]):
                r = review_boundary(state(), proposal(), case["payload"].encode("utf-8"))
                self.assertEqual(r.p8_reason, case["reason_code"])
                self.assert_deny(r)

    def test_all_29_profiles_still_blocked(self):
        self.assertEqual(len(KNOWN_PROFILES), 29)
        for profile in KNOWN_PROFILES:
            entry = next(c for c in CORPUS["cases"] if c["name"] == "profile_" + profile)
            raw = entry["payload"].encode("utf-8")
            claim = json.loads(raw)
            p = replace(proposal(), profile_id=profile, case_id=claim["case_id"])
            self.assert_deny(review_boundary(state(), p, raw))

    def test_invalid_types_are_fail_closed(self):
        p = proposal()
        for change in ({"generation": True}, {"transition": "T5_CONTROL"},
                       {"guards": (("control_authorized", True), ("effects_calculated", TRUE))},
                       {"configuration_sha256": "X" * 64},
                       {"case_id": "../../passwd"}):
            with self.subTest(change=change):
                with self.assertRaises(BridgeError):
                    replace(p, **change)
        for bad in (None, {}, 1):
            with self.assertRaises(BridgeError):
                review_boundary(bad, p, PAYLOAD)
            with self.assertRaises(BridgeError):
                review_boundary(state(), p, bad)

    def test_result_immutable_and_input_state_not_changed(self):
        s = state()
        p = proposal()
        original = (s.confirmed, s.services, s.attempts, s.confirmed.generation)
        result = review_boundary(s, p, PAYLOAD)
        self.assertEqual(original, (s.confirmed, s.services, s.attempts, s.confirmed.generation))
        self.assertIs(s.services, original[1])
        with self.assertRaises(FrozenInstanceError):
            result.dispatch_allowed = True

    def test_cannot_publish_or_reserve_attempt(self):
        source = (ROOT / "src/ardrec/p8_state_bridge.py").read_text()
        tree = ast.parse(source)
        calls = {n.func.id for n in ast.walk(tree)
                 if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
        forbidden = {"transition_service", "reserve_attempt", "record_report", "finish_invocation",
                     "open", "exec", "eval", "system", "Popen", "run", "connect", "socket"}
        self.assertFalse(calls & forbidden, calls & forbidden)
        imports = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        self.assertFalse(imports & {"subprocess", "socket", "os"})
        self.assertIn("ardrec.state", imports)

    def test_contract_and_historical_baseline_unchanged(self):
        c = json.loads((ROOT / "lab/p8-state-bridge-v1/contract.json").read_text())
        t = json.loads((ROOT / "docs/traceability/p8-state-bridge-r8.json").read_text())
        self.assertEqual(c["base_commit"], "517aa57183ca6a406c890fc92ccd00211eb79c3c")
        self.assertEqual(c["sources"], ["3.5.2", "3.5.3", "3.5.4", "3.7.5", "3.9.2"])
        self.assertEqual(c["profile_slots"], 29)
        self.assertEqual(c["real_cases"], 0)
        self.assertFalse(c["dispatch_allowed"])
        self.assertFalse(c["transition_applied"])
        self.assertFalse(c["publication_allowed"])
        self.assertEqual(c["open_findings"], ["AL-06", "AL-07"])
        self.assertEqual(c["open_development_obligations"], 7)
        self.assertEqual(t["status"], "SOURCE_ONLY_UNMERGED")
        self.assertFalse(t["system_acceptance"])
        self.assertFalse(t["experimental_validation"])


if __name__ == "__main__":
    unittest.main()
