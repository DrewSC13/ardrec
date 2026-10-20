"""Casos de referencia de estados derivados de las guardas de TESIS ARDREC."""

from copy import deepcopy
from dataclasses import FrozenInstanceError, replace
import json
from pathlib import Path
import unittest

from ardrec.messages import encode_message
from ardrec.state import (
    AttemptPhase, AttemptState, ClosureCriteria, ConfirmedState, GlobalState,
    GuardFact, Incorporation, InvocationPhase, Report, ServicePhase, ServiceState,
    StateError, Transition, TransitionContext, TransitionRecord, Truth, finish_invocation,
    mark_uncertain, record_report, reserve_attempt, transition_service,
)

FIXTURES = json.loads((Path(__file__).resolve().parents[1] / "fixtures/messages-v2.json").read_text())
S = ServicePhase
T = Transition
TRUE = Truth.VERDADERO

# La tabla esperada es independiente de la tabla interna del módulo.
EDGES = {
    T.PREPARAR: ({S.PREPARADO}, S.PENDIENTE, ("preparation_authorized", "preconditions_valid")),
    T.ACREDITAR_INICIO: ({S.PENDIENTE}, S.ACTIVO, ("start_verified",)),
    T.VALIDAR_RESULTADO: ({S.ACTIVO}, S.VALIDACION,
                        ("termination_verified", "cleanup_verified", "outcome_structured")),
    T.APLICAR_RESULTADO: ({S.VALIDACION}, S.ACTUALIZADO, ("outcome_processable", "effects_calculated")),
    T.APLICAR_CONTROL: ({S.PENDIENTE}, S.ACTUALIZADO, ("control_authorized", "effects_calculated")),
    T.APLICAR_NO_INICIO: ({S.PENDIENTE}, S.ACTUALIZADO, ("absence_verified", "effects_calculated")),
    T.CONTINUAR: ({S.ACTUALIZADO}, S.PENDIENTE, ("work_available", "precedence_resolved")),
    T.CERRAR: ({S.PENDIENTE, S.ACTUALIZADO}, S.CERRADO, ("precedence_resolved",)),
    T.PAUSAR: ({S.PENDIENTE, S.ACTUALIZADO}, S.PAUSADO,
               ("external_wait_registered", "pause_authorized", "precedence_resolved")),
    T.REANUDAR: ({S.PAUSADO}, S.PENDIENTE, ("new_authorization", "wait_resolved", "preconditions_valid")),
    T.DETENER: ({S.PREPARADO, S.PENDIENTE, S.ACTIVO, S.VALIDACION, S.ACTUALIZADO, S.PAUSADO},
                S.DETENIDO, ("cause_verified", "effect_processable")),
}


def criteria(**values):
    return ClosureCriteria(*(GuardFact(name, values.get(name, Truth.FALSO), "REF-" + name)
                             for name in ("ES", "SA", "CV", "LE")))


def service(phase):
    kwargs = {}
    if phase in {S.PAUSADO, S.CERRADO, S.DETENIDO}:
        kwargs["reason_reference"] = "REASON-1"
    if phase is S.PAUSADO:
        kwargs["wait_reference"] = "WAIT-1"
        kwargs["pause_authorization_reference"] = "PAUSE-AUTH-1"
    if phase is S.CERRADO:
        kwargs["closure"] = criteria(ES=TRUE)
    if phase is S.DETENIDO:
        kwargs["stop_cause"] = "SEGURIDAD"
    return ServiceState("S01", phase, **kwargs)


def global_state(phase=S.PENDIENTE):
    services = (service(phase), ServiceState("S02", S.PENDIENTE))
    confirmed = ConfirmedState("REG-1", 1, "GEN-1", "a" * 64, "VERS-1", services)
    return GlobalState(confirmed, "EXE-1", services, authority=TRUE)


def context(transition, **changes):
    refs = {"start_verified": "INI-1", "termination_verified": "FIN-1",
            "cleanup_verified": "LIM-1", "outcome_structured": "RESULT-completed",
            "absence_verified": "INI-1", "external_wait_registered": "WAIT-1",
            "wait_resolved": "WAIT-1", "cause_verified": "REASON-1",
            "new_authorization": "NEW-AUTH-1", "pause_authorized": "PAUSE-AUTH-1"}
    args = dict(record_id="REG-1", execution_id="EXE-1", generation=1,
                configuration_sha256="a" * 64, event_reference="EVENT-" + transition.value,
                facts=tuple(GuardFact(name, TRUE, refs.get(name, "PROOF-1")) for name in EDGES[transition][2]))
    if transition in {T.CERRAR, T.PAUSAR, T.DETENER}:
        args["reason_reference"] = "REASON-1"
    if transition is T.CERRAR:
        args["closure"] = criteria(ES=TRUE, LE=TRUE)
    if transition is T.PAUSAR:
        args["wait_reference"] = "WAIT-1"
    if transition is T.DETENER:
        args["stop_cause"] = "SEGURIDAD"
    args.update(changes)
    return TransitionContext(**args)


def move(state, transition, **changes):
    return transition_service(state, "S01", transition, context(transition, **changes))


def reserved():
    return reserve_attempt(global_state(), deepcopy(FIXTURES["request"]))


def received(name, state=None):
    state = reserved() if state is None else state
    query = FIXTURES["query"] if name.startswith("status_") else None
    return record_report(state, "ATT-1", deepcopy(FIXTURES[name]), query=deepcopy(query))


def phase_state(phase, *, no_start=False):
    if phase in {S.PREPARADO, S.PENDIENTE, S.PAUSADO, S.CERRADO, S.DETENIDO}:
        state = global_state(phase)
        if phase is S.PENDIENTE:
            return received("result_not_started" if no_start else "result_completed", reserve_attempt(state, FIXTURES["request"]))
        return state
    state = move(received("result_completed"), T.ACREDITAR_INICIO)
    if phase is S.ACTIVO:
        return state
    state = move(state, T.VALIDAR_RESULTADO)
    if phase is S.VALIDACION:
        return state
    return move(state, T.APLICAR_RESULTADO)


class StateTests(unittest.TestCase):
    def assert_code(self, code, action):
        with self.assertRaises(StateError) as caught:
            action()
        self.assertEqual(caught.exception.code, code)

    def test_eight_service_states_and_separate_invocation(self):
        self.assertEqual({s.value for s in S}, {"PREPARADO", "PENDIENTE", "ACTIVO", "VALIDACION",
                                              "ACTUALIZADO", "PAUSADO", "CERRADO", "DETENIDO"})
        self.assertEqual({s.value for s in InvocationPhase}, {"EN_CURSO", "FINALIZADA", "PAUSADA", "DETENIDA"})
        self.assertNotEqual(S.DETENIDO, InvocationPhase.DETENIDA)

    def test_all_service_edges_and_forbidden_origins(self):
        for transition, (origins, target, _) in EDGES.items():
            for phase in S:
                with self.subTest(transition=transition.value, phase=phase.value):
                    state = phase_state(phase, no_start=transition is T.APLICAR_NO_INICIO)
                    if transition is T.APLICAR_CONTROL and phase is S.PENDIENTE:
                        state = global_state()
                    if phase not in origins:
                        self.assert_code("terminal_state" if phase in {S.CERRADO, S.DETENIDO} else "transition_forbidden",
                                         lambda: move(state, transition))
                    else:
                        result = move(state, transition)
                        self.assertIs(result.services[0].phase, target)
                        self.assertIs(result.confirmed, state.confirmed)
                        self.assertEqual(result.confirmed.generation, 1)
                        self.assertEqual(result.services[1], state.services[1])
                        self.assertEqual(len(result.services[0].local_trace), len(state.services[0].local_trace) + 1)

    def test_false_and_nd_never_enable_guards(self):
        for transition, (origins, _, _) in EDGES.items():
            phase = sorted(origins, key=lambda x: x.value)[0]
            state = phase_state(phase, no_start=transition is T.APLICAR_NO_INICIO)
            if transition is T.APLICAR_CONTROL:
                state = global_state()
            original = context(transition)
            for index in range(len(original.facts)):
                for value in (Truth.FALSO, Truth.ND):
                    facts = list(original.facts)
                    facts[index] = replace(facts[index], value=value)
                    with self.subTest(transition=transition, guard=facts[index].name, value=value):
                        self.assert_code("guard_not_true", lambda: transition_service(
                            state, "S01", transition, replace(original, facts=tuple(facts))))

    def test_guard_fields_are_exact(self):
        c = context(T.PREPARAR)
        for facts in (c.facts[:-1], (*c.facts, GuardFact("extra", TRUE, "REF-1"))):
            self.assert_code("guard_set_mismatch", lambda: move(global_state(S.PREPARADO), T.PREPARAR, facts=facts))
        with self.assertRaises(StateError):
            replace(c, facts=(*c.facts, c.facts[0]))
        for value in (True, False, 1, "VERDADERO", None):
            with self.assertRaises(StateError):
                GuardFact("guard", value, "REF-1")

    def test_acceptance_does_not_start_service_or_increment_count(self):
        state = received("acceptance")
        self.assertIs(state.services[0].phase, S.PENDIENTE)
        self.assertIs(state.attempts[0].phase, AttemptPhase.ACEPTADO)
        self.assertEqual(state.incorporated_execution_count, 0)
        self.assert_code("start_unverified", lambda: move(state, T.ACREDITAR_INICIO))

    def test_reservation_is_global_and_does_not_dispatch(self):
        state = reserved()
        request = deepcopy(FIXTURES["request"])
        request.update(service_scenario_id="S02", attempt_id="ATT-2", message_id="REQ-2")
        self.assert_code("dispatch_blocked", lambda: reserve_attempt(state, request))
        self.assertIs(state.attempts[0].phase, AttemptPhase.RESERVADO)
        self.assertEqual(state.pending_attempts, ("ATT-1",))

    def test_complete_path_remains_candidate(self):
        state = received("result_completed")
        original = state.confirmed
        for transition in (T.ACREDITAR_INICIO, T.VALIDAR_RESULTADO, T.APLICAR_RESULTADO, T.CONTINUAR):
            state = move(state, transition)
        self.assertIs(state.confirmed, original)
        self.assertIs(state.services[0].phase, S.PENDIENTE)
        self.assertIn("candidate_unpublished", state.dispatch_blockers)
        self.assertIn("attempt_pending_incorporation", state.dispatch_blockers)
        self.assertEqual(state.incorporated_execution_count, 0)

    def test_no_start_skips_active_and_keeps_zero(self):
        state = move(received("result_not_started"), T.APLICAR_NO_INICIO)
        self.assertEqual([step.after for step in state.services[0].local_trace], [S.ACTUALIZADO])
        self.assertEqual(state.incorporated_execution_count, 0)
        self.assertIs(state.confirmed.services[0].phase, S.PENDIENTE)

    def test_uncertainty_cannot_close_pause_or_continue(self):
        for name in ("acceptance", "status_running", "result_uncertain"):
            state = received(name)
            for transition in (T.CERRAR, T.PAUSAR, T.APLICAR_CONTROL):
                with self.subTest(name=name, transition=transition):
                    self.assert_code("attempt_unresolved", lambda: move(state, transition))
            self.assert_code("dispatch_blocked", lambda: reserve_attempt(state, FIXTURES["request"]))

    def test_cleanup_pending_unknown_failed_block_validation(self):
        for status in ("pending", "unknown", "failed"):
            message = deepcopy(FIXTURES["result_completed"])
            message["payload"]["snapshot"]["cleanup"] = {
                "status": status, "reference": "FAIL-1" if status == "failed" else None,
            }
            message["payload"]["snapshot"]["reconciliation_required"] = True
            state = record_report(reserved(), "ATT-1", message)
            state = move(state, T.ACREDITAR_INICIO)
            self.assert_code("attempt_unresolved", lambda: move(state, T.VALIDAR_RESULTADO))
            self.assertTrue(state.attempts[0].pending)

    def test_interrupted_is_not_unknown(self):
        state = received("result_interrupted")
        self.assertTrue(state.attempts[0].technical_resolved)
        self.assertIs(state.attempts[0].phase, AttemptPhase.INTERRUMPIDO)
        state = move(state, T.ACREDITAR_INICIO)
        c = context(T.VALIDAR_RESULTADO)
        facts = tuple(replace(f, reference="RESULT-interrupted") if f.name == "outcome_structured" else f for f in c.facts)
        state = move(state, T.VALIDAR_RESULTADO, facts=facts)
        self.assertIs(state.services[0].phase, S.VALIDACION)
        self.assertTrue(state.attempts[0].pending)

    def test_replay_is_idempotent_and_conflict_rejected(self):
        state = received("acceptance")
        self.assertIs(record_report(state, "ATT-1", FIXTURES["acceptance"]), state)
        changed = deepcopy(FIXTURES["acceptance"])
        changed["created_at"] = "2026-10-19T12:00:02Z"
        self.assert_code("duplicate_conflict", lambda: record_report(state, "ATT-1", changed))

    def test_lost_connection_retains_identity_and_known_start(self):
        state = received("status_running")
        changed = mark_uncertain(state, "ATT-1", "CONNECTION-LOST-1")
        self.assertEqual(changed.attempts[0].request, state.attempts[0].request)
        self.assertEqual(changed.attempts[0].snapshot["start"], state.attempts[0].snapshot["start"])
        self.assertIs(changed.attempts[0].phase, AttemptPhase.INCIERTO)
        self.assertFalse(changed.attempts[0].technical_resolved)
        replay = record_report(changed, "ATT-1", FIXTURES["status_running"], query=FIXTURES["query"])
        self.assertIs(replay, changed)

    def test_query_reconciliation_does_not_release_reservation(self):
        state = received("result_uncertain")
        state = record_report(state, "ATT-1", FIXTURES["status_completed"], query=FIXTURES["query"])
        self.assertTrue(state.attempts[0].technical_resolved)
        self.assertEqual(state.pending_attempts, ("ATT-1",))
        self.assertIs(state.services[0].phase, S.PENDIENTE)

    def test_queries_require_correlation_and_identity(self):
        self.assert_code("query_required", lambda: record_report(reserved(), "ATT-1", FIXTURES["status_running"]))
        for field in ("record_id", "execution_id", "attempt_id", "service_scenario_id", "correlation_id"):
            message = deepcopy(FIXTURES["status_running"])
            message[field] = "OTHER-1"
            with self.assertRaises(StateError):
                record_report(reserved(), "ATT-1", message, query=FIXTURES["query"])

    def test_reports_cannot_erase_verified_facts(self):
        state = received("status_running")
        self.assert_code("attempt_regression", lambda: record_report(state, "ATT-1", FIXTURES["acceptance"]))
        self.assert_code("established_fact_conflict", lambda: record_report(state, "ATT-1", FIXTURES["result_uncertain"]))
        completed = received("result_completed")
        self.assert_code("attempt_regression", lambda: record_report(completed, "ATT-1", FIXTURES["status_running"], query=FIXTURES["query"]))

    def test_fresh_result_can_resolve_loss_without_duplicate_count(self):
        state = mark_uncertain(received("status_running"), "ATT-1", "LOSS-1")
        state = record_report(state, "ATT-1", FIXTURES["result_completed"])
        self.assertTrue(state.attempts[0].technical_resolved)
        self.assertEqual(state.incorporated_execution_count, 0)

    def test_stale_reports_and_journal_switch_rejected(self):
        for field, value, code in (("observed_at", "2026-10-19T11:59:59Z", "stale_report"),
                                   ("journal_reference", "OTHER-JOURNAL", "journal_mismatch")):
            message = deepcopy(FIXTURES["status_running"])
            message["payload"]["snapshot"][field] = value
            self.assert_code(code, lambda: record_report(received("acceptance"), "ATT-1", message, query=FIXTURES["query"]))

    def test_counter_needs_confirmed_incorporation(self):
        state = received("result_completed")
        attempt = replace(state.attempts[0], incorporation=Incorporation("EVENT-1", 2))
        self.assert_code("incorporation_unconfirmed", lambda: replace(state, attempts=(attempt,)))
        confirmed = replace(state.confirmed, generation=2, generation_reference="GEN-2", incorporated_events=("EVENT-1",))
        loaded = replace(state, confirmed=confirmed, attempts=(attempt,))
        self.assertFalse(loaded.pending_attempts)
        self.assertEqual(loaded.incorporated_execution_count, 1)
        self.assertIs(record_report(loaded, "ATT-1", FIXTURES["result_completed"]), loaded)
        no_start = received("result_not_started").attempts[0]
        no_start = replace(no_start, incorporation=Incorporation("EVENT-1", 2))
        self.assertEqual(replace(loaded, attempts=(no_start,)).incorporated_execution_count, 0)

    def test_attempt_identity_cannot_be_reused_after_incorporation(self):
        state = received("result_completed")
        receipt = Incorporation("EVENT-1", 2)
        confirmed = replace(state.confirmed, generation=2, incorporated_events=("EVENT-1",))
        state = replace(state, confirmed=confirmed, attempts=(replace(state.attempts[0], incorporation=receipt),))
        request = deepcopy(FIXTURES["request"])
        request.update(message_id="REQ-NEW", decision_index=2)
        self.assert_code("attempt_reuse", lambda: reserve_attempt(state, request))

    def test_simulation_does_not_enter_real_state_or_counters(self):
        request = deepcopy(FIXTURES["request"])
        request["simulation"] = True
        self.assert_code("simulation_mismatch", lambda: reserve_attempt(global_state(), request))
        state = reserve_attempt(replace(global_state(), simulation=True), request)
        message = deepcopy(FIXTURES["result_completed"])
        message["simulation"] = True
        state = record_report(state, "ATT-1", message)
        self.assert_code("incorporation_forbidden", lambda: replace(state.attempts[0], incorporation=Incorporation("EVENT-1", 2)))

    def test_stop_invocation_does_not_fabricate_service_stop(self):
        state = mark_uncertain(reserved(), "ATT-1", "LOSS-1")
        result = finish_invocation(state, InvocationPhase.DETENIDA, "UNRESOLVED-1")
        self.assertIs(result.confirmed, state.confirmed)
        self.assertEqual(result.services, state.services)
        self.assertEqual(result.attempts, state.attempts)
        self.assert_code("invocation_terminal", lambda: reserve_attempt(result, FIXTURES["request"]))
        self.assert_code("invocation_terminal", lambda: finish_invocation(result, InvocationPhase.FINALIZADA, "END-1"))

    def test_unverified_authority_stops_only_invocation(self):
        for authority in (Truth.ND, Truth.FALSO):
            state = replace(global_state(), authority=authority)
            self.assert_code("dispatch_blocked", lambda: reserve_attempt(state, FIXTURES["request"]))
            self.assert_code("authority_unverified", lambda: move(state, T.DETENER))
            result = finish_invocation(state, InvocationPhase.DETENIDA, "AUTHORITY-UNKNOWN")
            self.assertEqual(result.confirmed, state.confirmed)

    def test_terminal_services_never_reopen(self):
        for phase in (S.CERRADO, S.DETENIDO):
            state = global_state(phase)
            for transition in T:
                self.assert_code("terminal_state", lambda: move(state, transition))
            self.assert_code("terminal_state", lambda: replace(state, services=(service(S.PENDIENTE), state.services[1])))

    def test_pause_requires_external_wait_and_new_authorization(self):
        state = move(global_state(), T.PAUSAR)
        self.assertEqual(state.services[0].wait_reference, "WAIT-1")
        self.assert_code("reference_mismatch", lambda: move(state, T.REANUDAR, facts=tuple(
            replace(f, reference="OTHER-WAIT") if f.name == "wait_resolved" else f for f in context(T.REANUDAR).facts)))
        resumed = move(state, T.REANUDAR)
        self.assertIs(resumed.services[0].phase, S.PENDIENTE)
        self.assertIn("candidate_unpublished", resumed.dispatch_blockers)
        self.assertIs(resumed.confirmed, state.confirmed)

    def test_closure_records_all_criteria_and_declared_priority(self):
        for expected, values in (("ES", dict(ES=TRUE, SA=TRUE, CV=TRUE, LE=TRUE)),
                                 ("SA", dict(SA=TRUE, LE=TRUE)), ("CV", dict(CV=TRUE)), ("LE", dict(LE=TRUE))):
            c = criteria(**values)
            result = move(global_state(), T.CERRAR, closure=c)
            self.assertEqual(result.services[0].closure.primary_reason, expected)
            self.assertIs(result.services[0].closure, c)
        for unknown in (Truth.FALSO, Truth.ND):
            self.assert_code("closure_not_satisfied", lambda: move(global_state(), T.CERRAR, closure=criteria(ES=unknown)))

    def test_control_and_no_start_do_not_create_execution(self):
        state = move(global_state(), T.APLICAR_CONTROL)
        self.assertEqual(state.attempts, ())
        self.assertEqual(state.confirmed.generation, 1)
        self.assertIs(state.services[0].phase, S.ACTUALIZADO)

    def test_wrong_context_or_scope_rejected(self):
        for changes in (dict(record_id="OTHER"), dict(execution_id="OTHER"), dict(generation=2),
                        dict(configuration_sha256="b" * 64)):
            self.assert_code("context_mismatch", lambda: move(global_state(S.PREPARADO), T.PREPARAR, **changes))
        self.assert_code("out_of_scope", lambda: transition_service(global_state(), "S99", T.CERRAR, context(T.CERRAR)))
        self.assert_code("scope_mismatch", lambda: replace(global_state(), services=(service(S.PENDIENTE),)))

    def test_immutable_inputs_and_snapshot_copies(self):
        request = deepcopy(FIXTURES["request"])
        state = reserve_attempt(global_state(), request)
        request["attempt_id"] = "MUTATED"
        self.assertEqual(state.attempts[0].identity["attempt_id"], "ATT-1")
        state = received("acceptance", state)
        snapshot = state.attempts[0].snapshot
        snapshot["start"]["status"] = "VERIFICADO"
        self.assertEqual(state.attempts[0].snapshot["start"]["status"], "NO_ACREDITADO")
        with self.assertRaises(FrozenInstanceError):
            state.execution_id = "OTHER"

    def test_exact_generation_types_and_boundaries(self):
        original = global_state().confirmed
        self.assertEqual(replace(global_state(S.PREPARADO).confirmed, generation=0,
                                 services=(service(S.PREPARADO),)).generation, 0)
        for value in (2**53 + 1, 2**63 - 1):
            self.assertEqual(replace(original, generation=value).generation, value)
        for value in (True, False, -1, 2**63, 1.0, "1", None):
            with self.assertRaises(StateError):
                replace(original, generation=value)
        for collection in ([], list(original.services)):
            with self.assertRaises(StateError):
                replace(original, services=collection)

    def test_local_phases_cannot_be_loaded_as_confirmed(self):
        for phase in (S.ACTIVO, S.VALIDACION, S.ACTUALIZADO):
            with self.assertRaises(StateError):
                global_state(phase)
        state = move(global_state(), T.APLICAR_CONTROL)
        with self.assertRaises(StateError):
            replace(state.confirmed, services=state.services)

    def test_pending_results_block_finalization_even_if_technically_resolved(self):
        state = received("result_completed")
        for outcome in (InvocationPhase.FINALIZADA, InvocationPhase.PAUSADA):
            self.assert_code("unconfirmed_output", lambda: finish_invocation(state, outcome, "END-1"))
        candidate = move(global_state(), T.CERRAR)
        self.assert_code("unconfirmed_output", lambda: finish_invocation(candidate, InvocationPhase.FINALIZADA, "END-1"))

    def test_final_and_paused_invocation_require_confirmed_service_states(self):
        for phases, outcome in (((S.CERRADO, S.DETENIDO), InvocationPhase.FINALIZADA),
                                ((S.PAUSADO, S.CERRADO), InvocationPhase.PAUSADA)):
            services = (service(phases[0]), replace(service(phases[1]), service_scenario_id="S02"))
            confirmed = replace(global_state().confirmed, services=services)
            state = GlobalState(confirmed, "EXE-1", services, authority=TRUE)
            result = finish_invocation(state, outcome, "END-1")
            self.assertIs(result.invocation, outcome)
            self.assertIs(result.confirmed, confirmed)
        self.assert_code("unfinished_services", lambda: finish_invocation(global_state(), InvocationPhase.FINALIZADA, "END-1"))

    def test_discovery_uses_prepared_service_without_case(self):
        request = deepcopy(FIXTURES["discovery_request"])
        state = reserve_attempt(global_state(S.PREPARADO), request)
        state = record_report(state, "ATT-1", FIXTURES["discovery_result"])
        self.assertIsNone(state.attempts[0].identity["derived_case_id"])
        self.assertTrue(state.attempts[0].technical_resolved)
        self.assertIs(state.services[0].phase, S.PREPARADO)
        self.assert_code("dispatch_blocked", lambda: reserve_attempt(global_state(), request))

    def test_message_rejection_is_not_proof_of_no_start(self):
        with self.assertRaises(StateError):
            record_report(reserved(), "ATT-1", FIXTURES["rejection"])
        self.assert_code("attempt_unresolved", lambda: move(reserved(), T.APLICAR_NO_INICIO))

    def test_stop_with_uncertainty_keeps_candidate_and_reservation(self):
        state = move(received("result_uncertain"), T.DETENER)
        self.assertIs(state.services[0].phase, S.DETENIDO)
        self.assertIs(state.confirmed.services[0].phase, S.PENDIENTE)
        self.assertEqual(state.pending_attempts, ("ATT-1",))
        self.assert_code("unconfirmed_output", lambda: finish_invocation(state, InvocationPhase.FINALIZADA, "END-1"))


    def test_resume_requires_a_new_authorization_reference(self):
        state = global_state(S.PAUSADO)
        facts = tuple(replace(f, reference="PAUSE-AUTH-1") if f.name == "new_authorization" else f
                      for f in context(T.REANUDAR).facts)
        self.assert_code("authorization_not_new", lambda: move(state, T.REANUDAR, facts=facts))

    def test_confirmed_event_cannot_be_applied_again(self):
        state = global_state()
        state = replace(state, confirmed=replace(state.confirmed, incorporated_events=("EVENT-T5_CONTROL",)))
        self.assert_code("event_already_incorporated", lambda: move(state, T.APLICAR_CONTROL))

    def test_count_requires_verified_authority(self):
        state = replace(global_state(), authority=Truth.ND)
        self.assert_code("authority_unverified", lambda: state.incorporated_execution_count)

    def test_three_valued_guards_have_no_implicit_boolean_conversion(self):
        for value in Truth:
            with self.assertRaises(TypeError):
                bool(value)

    def test_two_pending_attempts_are_invalid_even_on_distinct_services(self):
        request = deepcopy(FIXTURES["request"])
        request.update(service_scenario_id="S02", message_id="REQ-2", attempt_id="ATT-2")
        first = reserved().attempts[0]
        second = AttemptState(encode_message(request))
        self.assert_code("multiple_pending_attempts", lambda: replace(global_state(), attempts=(first, second)))

    def test_new_invocation_preserves_prior_attempt_identity(self):
        old = received("result_uncertain")
        loaded = GlobalState(old.confirmed, "EXE-NEW", old.services, old.attempts, authority=TRUE)
        self.assertEqual(loaded.attempts[0].identity["execution_id"], "EXE-1")
        self.assert_code("dispatch_blocked", lambda: reserve_attempt(loaded, FIXTURES["request"]))
        resolved = record_report(loaded, "ATT-1", FIXTURES["status_completed"], query=FIXTURES["query"])
        self.assertEqual(resolved.pending_attempts, ("ATT-1",))
        self.assertEqual(resolved.confirmed.generation, old.confirmed.generation)

    def test_initial_generation_requires_prepared_services_and_no_events(self):
        with self.assertRaises(StateError):
            replace(global_state().confirmed, generation=0)
        prepared = replace(global_state(S.PREPARADO).confirmed, services=(service(S.PREPARADO),))
        self.assert_code("invalid_initial_generation", lambda: replace(prepared, generation=0, incorporated_events=("EVENT-1",)))

    def test_active_candidate_cannot_exist_without_its_attempt(self):
        state = global_state()
        trace = (TransitionRecord(T.ACREDITAR_INICIO, S.PENDIENTE, S.ACTIVO, context(T.ACREDITAR_INICIO)),)
        candidate = ServiceState("S01", S.ACTIVO, local_trace=trace)
        self.assert_code("attempt_required", lambda: replace(state, services=(candidate, state.services[1])))


if __name__ == "__main__":
    unittest.main()
