"""Interrupciones reales y propiedades de autoridad del almacén durable."""

from copy import deepcopy
from dataclasses import replace
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from ardrec.messages import encode_message
from ardrec.persistence import DurableStore, StorageError
from ardrec.persistence.codec import canonical, digest, pack, parse, unpack
from ardrec.state import (
    ConfirmedState, GlobalState, GuardFact, InvocationPhase, ServicePhase,
    ServiceState, StateError, Transition, TransitionContext, Truth,
)

FIXTURES = json.loads((Path(__file__).resolve().parents[1] / "fixtures/messages-temporal-v1.json").read_text())
BASE = ConfirmedState("REG-1", 0, "GEN-0", "a" * 64, "VERS-1",
                      (ServiceState("S01", ServicePhase.PREPARADO), ServiceState("S02", ServicePhase.PREPARADO)))
INITIAL = GlobalState(BASE, "EXE-1", BASE.services)
OBJECT_POINTS = ("created", "partial", "written", "synced", "installed", "durable")
HEAD_POINTS = ("head:created", "head:partial", "head:written", "head:synced", "head:before_replace",
               "head:replaced", "head:durable", "commit:acknowledge")


def context(store, transition):
    names = {
        Transition.PREPARAR: ("preparation_authorized", "preconditions_valid"),
        Transition.ACREDITAR_INICIO: ("start_verified",),
        Transition.VALIDAR_RESULTADO: ("termination_verified", "cleanup_verified", "outcome_structured"),
        Transition.APLICAR_RESULTADO: ("outcome_processable", "effects_calculated"),
        Transition.APLICAR_NO_INICIO: ("absence_verified", "effects_calculated"),
        Transition.CONTINUAR: ("work_available", "precedence_resolved"),
    }
    refs = {"start_verified": "INI-1", "absence_verified": "INI-1", "termination_verified": "FIN-1",
            "cleanup_verified": "LIM-1", "outcome_structured": "RESULT-completed"}
    return TransitionContext("REG-1", "EXE-1", store.state.confirmed.generation, "a" * 64,
                             "EV-" + transition.value,
                             tuple(GuardFact(name, Truth.VERDADERO, refs.get(name, "REF-1"))
                                   for name in names[transition]))


def prepare(store):
    store.transition("S01", Transition.PREPARAR, context(store, Transition.PREPARAR))
    store.publish(expected_generation=0, reference="GEN-1", event="PUB-1")


def reserve(store):
    store.reserve(deepcopy(FIXTURES["request"]), decision_reference="DEC-1")


def outcome(store, no_start=False):
    store.report("ATT-1", deepcopy(FIXTURES["result_not_started" if no_start else "result_completed"]))
    steps = (Transition.APLICAR_NO_INICIO,) if no_start else (
        Transition.ACREDITAR_INICIO, Transition.VALIDAR_RESULTADO, Transition.APLICAR_RESULTADO)
    for step in (*steps, Transition.CONTINUAR):
        store.transition("S01", step, context(store, step))


def reopen(path, **kwargs):
    return DurableStore.open(path, record_id="REG-1", configuration_sha256="a" * 64, **kwargs)


# El hijo se termina sin ejecutar finally ni cerrar de manera ordenada.
CHILD = '''
import os, signal, sys
from test_persistence import *
path, point, operation = sys.argv[1:]
def crash(current):
    if current == point:
        os.kill(os.getpid(), signal.SIGKILL)
if operation == "create":
    DurableStore.create(path, INITIAL, fault=crash)
else:
    with reopen(path, fault=crash) as store:
        if operation == "reserve": reserve(store)
        elif operation == "report": store.report("ATT-1", deepcopy(FIXTURES["result_completed"]))
        else: store.publish(expected_generation=1, reference="GEN-2", event="PUB-2")
raise RuntimeError("El punto de interrupción no fue alcanzado")
'''


class PersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ardrec-durable-test-")
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "store"

    def create(self, prepared=False):
        store = DurableStore.create(self.path, INITIAL)
        self.addCleanup(store.close)
        if prepared:
            prepare(store)
        return store

    def assert_error(self, code, operation):
        with self.assertRaises(StorageError) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)

    def crash(self, point, operation):
        root = Path(__file__).resolve().parents[2]
        env = dict(os.environ, PYTHONPATH=os.pathsep.join((str(root / "src"), str(root / "tests/unit"))),
                   PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run([sys.executable, "-c", CHILD, str(self.path), point, operation],
                                env=env, capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, -signal.SIGKILL, result.stdout + result.stderr)

    def test_initial_generation_and_identity(self):
        with self.create() as store:
            self.assertEqual(store.state.confirmed, BASE)
            self.assertIs(store.state.authority, Truth.VERDADERO)
            self.assertEqual(store.recovery_action, "NONE")
            token = store.head_sha256
        with reopen(self.path, expected_head=token) as store:
            self.assertEqual(store.state.confirmed.generation, 0)
            self.assertEqual(store.head_sha256, token)
        self.assert_error("store_identity_mismatch", lambda: DurableStore.open(
            self.path, record_id="OTHER", configuration_sha256="a" * 64))
        self.assert_error("store_identity_mismatch", lambda: DurableStore.open(
            self.path, record_id="REG-1", configuration_sha256="b" * 64))

    def test_candidate_remains_separate_until_publication(self):
        with self.create() as store:
            original = store.state.confirmed
            store.transition("S01", Transition.PREPARAR, context(store, Transition.PREPARAR))
            self.assertEqual(store.state.confirmed, original)
            self.assertEqual(store.recovery_action, "PUBLISH_CANDIDATE")
        with reopen(self.path) as store:
            self.assertEqual(store.state.confirmed.generation, 0)
            store.publish(expected_generation=0, reference="GEN-1", event="PUB-1")
            self.assertEqual(store.state.confirmed.generation, 1)
            self.assertFalse(store.state.services[0].local_trace)

    def test_reservation_survives_recovery_and_blocks_reexecution(self):
        with self.create(prepared=True) as store:
            reserve(store)
            request = store.state.attempts[0].request
        for _ in range(3):
            with reopen(self.path) as store:
                self.assertEqual(store.recovery_action, "RECONCILE_ATTEMPT")
                self.assertEqual(store.state.attempts[0].request, request)
                self.assertEqual(store.state.pending_attempts, ("ATT-1",))
                with self.assertRaises(StateError):
                    reserve(store)

    def test_result_is_durable_but_not_yet_incorporated(self):
        with self.create(prepared=True) as store:
            reserve(store)
            store.report("ATT-1", deepcopy(FIXTURES["result_completed"]))
        with reopen(self.path) as store:
            self.assertEqual(store.recovery_action, "INCORPORATE_RESULT")
            self.assertEqual(store.state.incorporated_execution_count, 0)
            self.assertEqual(store.state.pending_attempts, ("ATT-1",))
            self.assert_error("effects_not_staged", lambda: store.publish(
                expected_generation=1, reference="GEN-2", event="PUB-2"))

    def test_atomic_receipt_count_and_recovery_idempotence(self):
        with self.create(prepared=True) as store:
            reserve(store)
            outcome(store)
            self.assertEqual(store.state.incorporated_execution_count, 0)
            store.publish(expected_generation=1, reference="GEN-2", event="PUB-2")
            expected = store.state
            token = store.head_sha256
        for _ in range(3):
            with reopen(self.path) as store:
                self.assertEqual(store.state, expected)
                self.assertEqual(store.head_sha256, token)
                self.assertEqual(store.state.incorporated_execution_count, 1)
                self.assertFalse(store.state.pending_attempts)
                self.assertEqual(store.state.attempts[0].incorporation.event_reference, "PUB-2")
                self.assert_error("stale_generation", lambda: store.publish(
                    expected_generation=1, reference="GEN-2", event="PUB-2"))

    def test_verified_absence_never_increments_execution_count(self):
        with self.create(prepared=True) as store:
            reserve(store)
            outcome(store, no_start=True)
            store.publish(expected_generation=1, reference="GEN-2", event="PUB-2")
        with reopen(self.path) as store:
            self.assertEqual(store.state.incorporated_execution_count, 0)
            self.assertFalse(store.state.pending_attempts)

    def test_duplicate_reports_are_exact_noops(self):
        with self.create(prepared=True) as store:
            reserve(store)
            report = deepcopy(FIXTURES["result_completed"])
            store.report("ATT-1", report)
            before = store.head_sha256
            store.report("ATT-1", report)
            self.assertEqual(store.head_sha256, before)
            store.uncertain("ATT-1", "NETWORK-1")
            before = store.head_sha256
            store.report("ATT-1", report)
            self.assertEqual(store.head_sha256, before)
            self.assertEqual(store.recovery_action, "RECONCILE_ATTEMPT")

    def test_uncertainty_blocks_publication_and_keeps_start(self):
        with self.create(prepared=True) as store:
            reserve(store)
            store.report("ATT-1", deepcopy(FIXTURES["result_completed"]))
            store.uncertain("ATT-1", "LOSS-1")
        with reopen(self.path) as store:
            self.assertEqual(store.state.attempts[0].snapshot["start"]["status"], "VERIFICADO")
            self.assert_error("attempt_unresolved", lambda: store.publish(
                expected_generation=1, reference="GEN-2", event="PUB-2"))

    def test_invocation_stop_is_durable_without_fabricated_service_stop(self):
        with self.create(prepared=True) as store:
            reserve(store)
            store.finish(InvocationPhase.DETENIDA, "NETWORK-1")
        with reopen(self.path) as store:
            self.assertEqual(store.recovery_action, "INVOCATION_ENDED")
            self.assertEqual(store.state.pending_attempts, ("ATT-1",))
            self.assertIs(store.state.services[0].phase, ServicePhase.PENDIENTE)

    def test_exact_codec_and_canonical_protocol_bytes(self):
        with self.create(prepared=True) as store:
            request = deepcopy(FIXTURES["request"])
            reserve(store)
            value = store.state
            self.assertEqual(unpack(parse(canonical(pack(value)))), value)
            self.assertEqual(value.attempts[0].request, encode_message(request))
        for value in (-(2**63), 2**53 + 1, 2**63 - 1, b"\x00\xff", Truth.ND):
            self.assertEqual(unpack(parse(canonical(pack(value)))), value)
        for value in (1.5, 2**63, object()):
            with self.assertRaises(StorageError):
                pack(value)

    def test_malformed_codec_and_version_rejections(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":1.0}', b'{"x":NaN}', b'{ "x":1}', b'\xff', b''):
            with self.subTest(raw=raw), self.assertRaises(StorageError):
                parse(raw)
        for value in ({"@": "os.system", "value": "x"}, {"@": "bytes", "value": "!"},
                      {"@": "ServiceState", "fields": {}}, {"@": "tuple", "value": False},
                      {"@": "Truth", "value": "TRUE"}):
            with self.subTest(value=value), self.assertRaises(StorageError):
                unpack(value)

    def test_generation_files_are_never_overwritten(self):
        with self.create() as store:
            old = {p.name: p.read_bytes() for p in (self.path / "generations").iterdir()}
            prepare(store)
            for name, raw in old.items():
                self.assertEqual((self.path / "generations" / name).read_bytes(), raw)
            self.assertEqual(len(list((self.path / "generations").glob("*.json"))), 2)
        with self.assertRaises(FileExistsError):
            DurableStore.create(self.path, INITIAL)

    def test_missing_head_does_not_promote_orphans(self):
        self.create().close()
        (self.path / "HEAD").unlink()
        with self.assertRaises(FileNotFoundError):
            reopen(self.path)
        self.assertFalse((self.path / "HEAD").exists())

    def test_corrupted_head_is_not_repaired_from_generations(self):
        self.create().close()
        head = self.path / "HEAD"
        head.chmod(0o600)
        head.write_bytes(b'{"head":')
        with self.assertRaises(StorageError):
            reopen(self.path)
        self.assertEqual(head.read_bytes(), b'{"head":')

    def test_corrupt_journal_and_generation_fail_closed(self):
        for folder in ("journal", "generations"):
            with self.subTest(folder=folder), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "store"
                DurableStore.create(path, INITIAL).close()
                target = next((path / folder).glob("*.json"))
                target.chmod(0o600)
                target.write_bytes(target.read_bytes() + b" ")
                self.assert_error("object_hash_mismatch", lambda: reopen(path))

    def test_missing_referenced_object_fails_closed(self):
        self.create().close()
        next((self.path / "journal").glob("*.json")).unlink()
        with self.assertRaises(FileNotFoundError):
            reopen(self.path)

    def test_orphan_files_are_ignored_without_deletion(self):
        self.create().close()
        for folder in ("generations", "journal"):
            (self.path / folder / ("f" * 64 + ".json")).write_bytes(b"incomplete")
        (self.path / ".pending-unused").write_bytes(b"partial")
        with reopen(self.path) as store:
            self.assertEqual(store.state.confirmed, BASE)
        self.assertTrue((self.path / ".pending-unused").exists())

    def test_two_sessions_cannot_share_writer_lock(self):
        store = self.create()
        self.assert_error("writer_busy", lambda: reopen(self.path))
        store.close()
        with reopen(self.path) as second:
            self.assertEqual(second.state.confirmed, BASE)

    def test_separate_process_cannot_write_under_held_lock(self):
        self.create()
        code = '''
import sys
from ardrec.persistence import DurableStore, StorageError
try:
    DurableStore.open(sys.argv[1], record_id="REG-1", configuration_sha256="a"*64)
except StorageError as error:
    sys.exit(0 if error.code == "writer_busy" else 2)
sys.exit(3)
'''
        # El proceso hijo no hereda las modificaciones de sys.path del verificador.
        root = Path(__file__).resolve().parents[2]
        child_env = dict(os.environ, PYTHONPATH=str(root / "src"), PYTHONDONTWRITEBYTECODE="1")
        result = subprocess.run([sys.executable, "-c", code, str(self.path)], timeout=15,
                                capture_output=True, text=True, env=child_env)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_same_session_rejects_other_thread_and_fork(self):
        store = self.create()
        codes = []
        def check():
            try:
                store.state
            except StorageError as error:
                codes.append(error.code)
        thread = threading.Thread(target=check)
        thread.start()
        thread.join(timeout=5)
        self.assertEqual(codes, ["session_owner_mismatch"])
        pid = os.fork()
        if pid == 0:
            try:
                store.state
                os._exit(3)
            except StorageError as error:
                store.close()
                os._exit(0 if error.code == "session_owner_mismatch" else 2)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(os.waitstatus_to_exitcode(status), 0)
        self.assert_error("writer_busy", lambda: reopen(self.path))

    def test_symlinks_and_hardlinks_are_rejected(self):
        self.create().close()
        alias = self.path.parent / "alias"
        alias.symlink_to(self.path, target_is_directory=True)
        with self.assertRaises(OSError):
            reopen(alias)
        head = self.path / "HEAD"
        head.rename(self.path / "saved")
        head.symlink_to("saved")
        with self.assertRaises(OSError):
            reopen(self.path)
        head.unlink()
        os.link(self.path / "saved", head)
        self.assert_error("file_invalid", lambda: reopen(self.path))

    def test_lock_replacement_poison_session(self):
        store = self.create()
        (self.path / "LOCK").unlink()
        (self.path / "LOCK").write_bytes(b"")
        self.assert_error("path_replaced", lambda: store.state)
        self.assert_error("session_unavailable", lambda: store.state)

    def test_changed_head_poison_session(self):
        store = self.create()
        head = self.path / "HEAD"
        head.chmod(0o600)
        head.write_bytes(b"invalid")
        self.assert_error("head_changed", lambda: store.state)
        self.assert_error("session_unavailable", lambda: store.state)

    def test_checkpoint_anchor_detects_old_valid_head(self):
        with self.create() as store:
            old = (self.path / "HEAD").read_bytes()
            prepare(store)
            current = store.head_sha256
        head = self.path / "HEAD"
        head.chmod(0o600)
        head.write_bytes(old)
        self.assert_error("head_anchor_mismatch", lambda: reopen(self.path, expected_head=current))

    def test_publication_guards_leave_disk_unchanged(self):
        with self.create(prepared=True) as store:
            token = store.head_sha256
            for generation, reference, event, code in (
                (0, "GEN-2", "PUB-2", "stale_generation"),
                (True, "GEN-2", "PUB-2", "index_invalid"),
                (1, "GEN-1", "PUB-2", "generation_reference_reused"),
                (1, "GEN-2", "PUB-2", "empty_publication"),
            ):
                self.assert_error(code, lambda: store.publish(expected_generation=generation,
                                                              reference=reference, event=event))
                self.assertEqual(store.head_sha256, token)
            reserve(store)
            store.report("ATT-1", deepcopy(FIXTURES["result_completed"]))
            store.transition("S01", Transition.ACREDITAR_INICIO, context(store, Transition.ACREDITAR_INICIO))
            self.assert_error("candidate_not_publishable", lambda: store.publish(
                expected_generation=1, reference="GEN-2", event="PUB-2"))

    def test_short_writes_are_completed(self):
        original = os.write
        with patch("ardrec.persistence.os.write", side_effect=lambda fd, data: original(fd, data[:7])):
            self.create().close()
        with reopen(self.path) as store:
            self.assertEqual(store.state.confirmed, BASE)

    def test_zero_write_fails_without_acknowledgement(self):
        store = self.create(prepared=True)
        with patch("ardrec.persistence.os.write", return_value=0):
            self.assert_error("write_stalled", lambda: reserve(store))
        self.assert_error("session_unavailable", lambda: store.state)
        store.close()
        with reopen(self.path) as store:
            self.assertFalse(store.state.attempts)

    def test_disk_full_and_fsync_errors_poison_session(self):
        for target, err in (("os.write", errno.ENOSPC), ("os.fsync", errno.EIO)):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "store"
                store = DurableStore.create(path, INITIAL)
                prepare(store)
                with patch("ardrec.persistence." + target, side_effect=OSError(err, "fallo inyectado")):
                    with self.assertRaises(OSError):
                        reserve(store)
                self.assert_error("session_unavailable", lambda: store.state)
                store.close()
                with reopen(path) as recovered:
                    self.assertFalse(recovered.state.attempts)

    def test_directory_sync_failure_after_replace_requires_recovery(self):
        store = self.create(prepared=True)
        original = os.fsync
        def fail_root(fd):
            if fd == store._root:
                raise OSError(errno.EIO, "fallo de sincronización del puntero")
            original(fd)
        with patch("ardrec.persistence.os.fsync", side_effect=fail_root):
            with self.assertRaises(OSError):
                reserve(store)
        self.assert_error("session_unavailable", lambda: store.state)
        store.close()
        with reopen(self.path) as recovered:
            self.assertEqual(recovered.state.pending_attempts, ("ATT-1",))

    def test_recovery_sync_failure_never_returns_authority(self):
        self.create().close()
        with patch("ardrec.persistence.os.fsync", side_effect=OSError(errno.EIO, "fallo")):
            with self.assertRaises(OSError):
                reopen(self.path)
        with reopen(self.path) as store:
            self.assertIs(store.state.authority, Truth.VERDADERO)

    def test_object_size_and_journal_capacity_limits(self):
        with patch("ardrec.persistence.codec.MAX_OBJECT_BYTES", 20):
            self.assert_error("object_too_large", lambda: canonical({"text": "x" * 30}))
        with self.create() as store:
            token = store.head_sha256
            with patch("ardrec.persistence.MAX_RECORDS", 1):
                self.assert_error("journal_capacity", lambda: store.transition(
                    "S01", Transition.PREPARAR, context(store, Transition.PREPARAR)))
            self.assertEqual(store.head_sha256, token)

    def test_rehashed_invalid_operation_and_version_are_rejected(self):
        for invalid in ("operation", "version", "sequence"):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "store"
                DurableStore.create(path, INITIAL).close()
                head = parse((path / "HEAD").read_bytes())["head"]
                if invalid == "version":
                    head["format"] = "ardrec-store-99"
                else:
                    event_path = path / "journal" / (head["journal_digest"] + ".json")
                    event = parse(event_path.read_bytes())
                    if invalid == "operation":
                        event["operation"] = "execute_tool"
                    else:
                        event["sequence"] = True
                    raw = canonical(event)
                    new_digest = digest(raw)
                    (path / "journal" / (new_digest + ".json")).write_bytes(raw)
                    head["journal_digest"] = new_digest
                target = path / "HEAD"
                target.chmod(0o600)
                target.write_bytes(canonical({"head": head, "sha256": digest(canonical(head))}))
                with self.assertRaises(StorageError):
                    reopen(path)

    def test_generation_state_must_equal_replayed_journal(self):
        self.create().close()
        head_path = self.path / "HEAD"
        head = parse(head_path.read_bytes())["head"]
        generation = parse((self.path / "generations" / (head["generation_digest"] + ".json")).read_bytes())
        generation["state"]["fields"]["confirmed"]["fields"]["generation"] = False
        raw = canonical(generation)
        forged = digest(raw)
        (self.path / "generations" / (forged + ".json")).write_bytes(raw)
        event = parse((self.path / "journal" / (head["journal_digest"] + ".json")).read_bytes())
        event["generation_digest"] = forged
        raw = canonical(event)
        journal = digest(raw)
        (self.path / "journal" / (journal + ".json")).write_bytes(raw)
        head.update(generation_digest=forged, journal_digest=journal)
        head_path.chmod(0o600)
        head_path.write_bytes(canonical({"head": head, "sha256": digest(canonical(head))}))
        self.assert_error("generation_mismatch", lambda: reopen(self.path))

    def test_reused_publication_event_is_rejected(self):
        with self.create(prepared=True) as store:
            reserve(store)
            outcome(store)
            token = store.head_sha256
            self.assert_error("event_reused", lambda: store.publish(
                expected_generation=1, reference="GEN-2", event="PUB-1"))
            self.assertEqual(store.head_sha256, token)

    def test_initialization_rejects_simulation_and_nonzero_generation(self):
        with self.assertRaises(StorageError):
            DurableStore.create(self.path, replace(INITIAL, simulation=True))
        with self.assertRaises(StorageError):
            DurableStore.create(self.path, replace(INITIAL, confirmed=replace(BASE, generation=1)))
        self.assertFalse(self.path.exists())

    def test_private_directory_and_closed_session(self):
        store = self.create()
        store.close()
        self.assert_error("session_unavailable", lambda: store.state)
        self.path.chmod(0o755)
        self.assert_error("directory_not_private", lambda: reopen(self.path))
        self.path.chmod(0o700)

    def test_process_death_at_each_initialization_boundary(self):
        points = tuple(f"{folder}:{p}" for folder in ("generations", "journal") for p in OBJECT_POINTS) + HEAD_POINTS
        for index, point in enumerate(points):
            with self.subTest(point=point):
                self.path = Path(self.temporary.name) / f"init-{index}"
                self.crash(point, "create")
                if point in ("head:replaced", "head:durable", "commit:acknowledge"):
                    with reopen(self.path) as store:
                        self.assertEqual(store.state.confirmed, BASE)
                else:
                    with self.assertRaises(FileNotFoundError):
                        reopen(self.path)

    def test_process_death_at_each_intention_boundary(self):
        points = tuple("journal:" + p for p in OBJECT_POINTS) + HEAD_POINTS
        for index, point in enumerate(points):
            with self.subTest(point=point):
                self.path = Path(self.temporary.name) / f"intent-{index}"
                with DurableStore.create(self.path, INITIAL) as store:
                    prepare(store)
                self.crash(point, "reserve")
                with reopen(self.path) as store:
                    committed = point in ("head:replaced", "head:durable", "commit:acknowledge")
                    self.assertEqual(bool(store.state.pending_attempts), committed)
                    self.assertEqual(store.state.confirmed.generation, 1)
                    if committed:
                        self.assertEqual(store.recovery_action, "RECONCILE_ATTEMPT")

    def test_process_death_at_each_result_boundary(self):
        points = tuple("journal:" + p for p in OBJECT_POINTS) + HEAD_POINTS
        for index, point in enumerate(points):
            with self.subTest(point=point):
                self.path = Path(self.temporary.name) / f"result-{index}"
                with DurableStore.create(self.path, INITIAL) as store:
                    prepare(store)
                    reserve(store)
                self.crash(point, "report")
                with reopen(self.path) as store:
                    committed = point in ("head:replaced", "head:durable", "commit:acknowledge")
                    self.assertEqual(store.state.attempts[0].technical_resolved, committed)
                    self.assertEqual(store.state.incorporated_execution_count, 0)
                    self.assertEqual(store.state.pending_attempts, ("ATT-1",))

    def test_process_death_at_each_generation_publication_boundary(self):
        points = tuple(f"{folder}:{p}" for folder in ("generations", "journal") for p in OBJECT_POINTS) + HEAD_POINTS
        for index, point in enumerate(points):
            with self.subTest(point=point):
                self.path = Path(self.temporary.name) / f"publish-{index}"
                with DurableStore.create(self.path, INITIAL) as store:
                    prepare(store)
                    reserve(store)
                    outcome(store)
                self.crash(point, "publish")
                for _ in range(2):
                    with reopen(self.path) as store:
                        committed = point in ("head:replaced", "head:durable", "commit:acknowledge")
                        self.assertEqual(store.state.confirmed.generation, 2 if committed else 1)
                        self.assertEqual(store.state.incorporated_execution_count, int(committed))
                        self.assertEqual(bool(store.state.pending_attempts), not committed)
                        self.assertEqual(store.state.attempts[0].incorporation is not None, committed)


if __name__ == "__main__":
    unittest.main(verbosity=2)
