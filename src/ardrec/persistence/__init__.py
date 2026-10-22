"""Generaciones inmutables y diario transaccional para un escritor local Linux."""

from copy import deepcopy
from dataclasses import replace
import fcntl
import os
from pathlib import Path
import re
import stat
import threading
import uuid

from ardrec.messages import decode_message, encode_message
from ardrec.state import (
    ConfirmedState, GlobalState, Incorporation, InvocationPhase, PUBLISHABLE,
    Truth, Transition, finish_invocation, mark_uncertain, record_report, reserve_attempt,
    transition_service,
)
from .codec import (
    MAX_OBJECT_BYTES, StorageError, canonical, digest, exact_fields, pack,
    parse, require, unpack,
)

FORMAT = "ardrec-store-1"
MAX_RECORDS = 100_000


def _hash(value):
    require(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None, "hash_invalid")


def _id(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is not None,
            "identifier_invalid")


def _index(value):
    require(type(value) is int and 0 <= value < 2**63, "index_invalid")


def _initial(state):
    require(type(state) is GlobalState and state.confirmed.generation == 0
            and state.services == state.confirmed.services and not state.attempts
            and not state.simulation and state.invocation is InvocationPhase.EN_CURSO,
            "initial_state_invalid")
    return replace(state, authority=Truth.VERDADERO)


def _publish(state, expected_generation, reference, event):
    _index(expected_generation)
    _id(reference)
    _id(event)
    require(state.invocation is InvocationPhase.EN_CURSO and not state.simulation, "publication_forbidden")
    require(state.confirmed.generation == expected_generation, "stale_generation")
    require(reference != state.confirmed.generation_reference, "generation_reference_reused")
    require(all(s.phase in PUBLISHABLE for s in state.services), "candidate_not_publishable")
    pending = tuple(a for a in state.attempts if a.pending)
    require(all(a.technical_resolved for a in pending), "attempt_unresolved")
    require(state.services != state.confirmed.services or pending, "empty_publication")
    for attempt in pending:
        service = next(s for s in state.services if s.service_scenario_id == attempt.identity["service_scenario_id"])
        steps = {step.transition for step in service.local_trace}
        expected = (Transition.PREPARAR if attempt.identity["scope"] == "discovery" else
                    Transition.APLICAR_NO_INICIO if attempt.snapshot["phase"] == "not_started" else
                    Transition.APLICAR_RESULTADO)
        require(expected in steps or Transition.DETENER in steps, "effects_not_staged")
    events = [step.context.event_reference for s in state.services for step in s.local_trace]
    require(event not in events, "event_reused")
    events.append(event)
    require(len(events) == len(set(events))
            and not set(events).intersection(state.confirmed.incorporated_events), "event_reused")
    # El recibo y la generación se publican juntos; no existe una marca posterior indispensable.
    generation = expected_generation + 1
    services = tuple(replace(s, local_trace=()) for s in state.services)
    confirmed = replace(state.confirmed, generation=generation, generation_reference=reference,
                        services=services, incorporated_events=(*state.confirmed.incorporated_events, *events))
    attempts = tuple(replace(a, incorporation=Incorporation(event, generation)) if a.pending else a
                     for a in state.attempts)
    return replace(state, confirmed=confirmed, services=services, attempts=attempts)


def _reduce(state, operation, args):
    require(type(operation) is str and type(args) is dict, "operation_invalid")
    if operation == "initialize":
        exact_fields(args, ("state",))
        require(state is None, "duplicate_initialization")
        return _initial(args["state"])
    require(state is not None, "initialization_missing")
    if operation in {"reconcile_query_v1", "reconcile_reply_v1"}:
        from ardrec.reconciliation import reduce_record
        return reduce_record(state, operation, args)
    if operation == "reserve":
        exact_fields(args, ("request", "decision_reference"))
        _id(args["decision_reference"])
        return reserve_attempt(state, decode_message(args["request"]))
    if operation == "report":
        exact_fields(args, ("attempt_id", "message", "query"))
        return record_report(state, args["attempt_id"], decode_message(args["message"]),
                             query=None if args["query"] is None else decode_message(args["query"]))
    if operation == "uncertain":
        exact_fields(args, ("attempt_id", "reason_reference"))
        return mark_uncertain(state, **args)
    if operation == "transition":
        exact_fields(args, ("service_id", "transition", "context"))
        return transition_service(state, **args)
    if operation == "publish":
        exact_fields(args, ("expected_generation", "reference", "event"))
        return _publish(state, **args)
    if operation == "finish":
        exact_fields(args, ("outcome", "reason_reference"))
        return finish_invocation(state, **args)
    raise StorageError("operation_unknown")


class DurableStore:
    """Sesión exclusiva; nunca despacha herramientas ni confirma soportes externos."""

    def __init__(self):
        raise TypeError("Usar DurableStore.create u open")

    @classmethod
    def _session(cls, path, record_id, configuration_sha256, creating, fault):
        _id(record_id)
        _hash(configuration_sha256)
        self = object.__new__(cls)
        self._fds = []
        self._pid = os.getpid()
        self._thread = threading.get_ident()
        self._closed = False
        self._poisoned = True
        self._fault = fault or (lambda point: None)
        self._record = record_id
        self._configuration = configuration_sha256
        self._path = Path(os.path.abspath(path))
        self._head_raw = None
        self._head = None
        self._state = None
        self._queries = {}
        try:
            # Abrir cada componente sin seguir enlaces, conservando descriptores propios.
            parent = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                parts = self._path.parts[1:]
                require(bool(parts), "root_forbidden")
                for part in parts[:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    dir_fd=parent)
                    os.close(parent)
                    parent = child
                if creating:
                    os.mkdir(parts[-1], mode=0o700, dir_fd=parent)
                    os.fsync(parent)
                self._root = os.open(parts[-1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     dir_fd=parent)
                self._fds.append(self._root)
            finally:
                os.close(parent)
            root_stat = os.fstat(self._root)
            require(root_stat.st_uid == os.geteuid() and root_stat.st_mode & 0o077 == 0, "directory_not_private")
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
            if creating:
                flags |= os.O_CREAT | os.O_EXCL
            self._lock = os.open("LOCK", flags, 0o600, dir_fd=self._root)
            self._fds.append(self._lock)
            self._regular(self._lock)
            try:
                fcntl.flock(self._lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise StorageError("writer_busy") from error
            if creating:
                os.fsync(self._lock)
            self._directories = {}
            for name in ("generations", "journal"):
                if creating:
                    os.mkdir(name, mode=0o700, dir_fd=self._root)
                fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=self._root)
                self._fds.append(fd)
                self._directories[name] = fd
                info = os.fstat(fd)
                require(info.st_dev == root_stat.st_dev and info.st_uid == os.geteuid()
                        and info.st_mode & 0o077 == 0, "directory_invalid")
                os.fsync(fd)
            os.fsync(self._root)
            self._poisoned = False
            return self
        except BaseException:
            self.close()
            raise

    @classmethod
    def create(cls, path, initial, *, fault=None):
        initial = _initial(initial)
        self = cls._session(path, initial.confirmed.record_id,
                            initial.confirmed.configuration_sha256, True, fault)
        try:
            self._commit("initialize", {"state": initial})
            return self
        except BaseException:
            self.close()
            raise

    @classmethod
    def open(cls, path, *, record_id, configuration_sha256, expected_head=None, fault=None):
        self = cls._session(path, record_id, configuration_sha256, False, fault)
        try:
            self._recover(expected_head)
            return self
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _regular(fd):
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                and info.st_uid == os.geteuid(), "file_invalid")
        return info

    def _read(self, folder, name):
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=folder)
        try:
            info = self._regular(fd)
            require(info.st_size <= MAX_OBJECT_BYTES, "object_too_large")
            data = bytearray()
            while True:
                chunk = os.read(fd, min(65536, MAX_OBJECT_BYTES + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                require(len(data) <= MAX_OBJECT_BYTES, "object_too_large")
            require(len(data) == info.st_size, "file_changed")
            return bytes(data)
        finally:
            os.close(fd)

    def _object(self, folder, sha):
        _hash(sha)
        raw = self._read(self._directories[folder], sha + ".json")
        require(digest(raw) == sha, "object_hash_mismatch")
        return parse(raw)

    def _check(self):
        require(not self._closed and not self._poisoned, "session_unavailable")
        require(os.getpid() == self._pid and threading.get_ident() == self._thread, "session_owner_mismatch")
        try:
            pairs = [(self._lock, self._root, "LOCK")]
            pairs.extend((fd, self._root, name) for name, fd in self._directories.items())
            for fd, parent, name in pairs:
                actual = os.stat(name, dir_fd=parent, follow_symlinks=False)
                opened = os.fstat(fd)
                require((actual.st_dev, actual.st_ino) == (opened.st_dev, opened.st_ino), "path_replaced")
            actual = os.stat(self._path, follow_symlinks=False)
            opened = os.fstat(self._root)
            require((actual.st_dev, actual.st_ino) == (opened.st_dev, opened.st_ino), "path_replaced")
            if self._head_raw is not None:
                require(self._read(self._root, "HEAD") == self._head_raw, "head_changed")
        except BaseException:
            self._poisoned = True
            raise

    def _temp(self, folder, raw, label):
        name = ".pending-" + uuid.uuid4().hex
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=folder)
        try:
            self._fault(label + ":created")
            # Tratar escrituras cortas y rechazar un escritor sin progreso.
            middle = max(1, len(raw) // 2)
            for index, part in enumerate((raw[:middle], raw[middle:])):
                view = memoryview(part)
                while view:
                    written = os.write(fd, view)
                    require(written > 0, "write_stalled")
                    view = view[written:]
                self._fault(label + (":partial" if index == 0 else ":written"))
            os.fchmod(fd, 0o400)
            os.fsync(fd)
            self._fault(label + ":synced")
            return name
        finally:
            os.close(fd)

    def _install(self, folder_name, value):
        folder = self._directories[folder_name]
        raw = canonical(value)
        sha = digest(raw)
        name = sha + ".json"
        temp = self._temp(folder, raw, folder_name)
        try:
            os.link(temp, name, src_dir_fd=folder, dst_dir_fd=folder, follow_symlinks=False)
        except FileExistsError:
            require(self._read(folder, name) == raw, "object_collision")
        os.unlink(temp, dir_fd=folder)
        self._fault(folder_name + ":installed")
        os.fsync(folder)
        self._fault(folder_name + ":durable")
        return sha

    def _commit(self, operation, args):
        self._check()
        # Validar completamente antes de abrir la frontera de escritura.
        from ardrec.reconciliation import QUERY, REPLY, advance_index
        queries = advance_index(self._queries, self._state, operation, args)
        if operation == REPLY and queries is self._queries:
            return self.state
        new_state = _reduce(self._state, operation, args)
        if self._state == new_state and operation not in {QUERY, REPLY}:
            return self.state
        packed_args = pack(args)
        state_hash = digest(canonical(pack(new_state)))
        seq = 0 if self._head is None else self._head["sequence"] + 1
        require(seq < MAX_RECORDS, "journal_capacity")
        old_gen = None if self._head is None else self._head["generation_digest"]
        generation_value = None
        if operation in {"initialize", "publish"}:
            generation_value = {"format": FORMAT, "previous": old_gen, "state": pack(new_state)}
            canonical(generation_value)
        # Las referencias de generaciones son únicas en toda la observación.
        if operation == "publish":
            require(args["reference"] not in self._generation_refs, "generation_reference_reused")
        canonical(packed_args)
        try:
            gen = self._install("generations", generation_value) if generation_value is not None else old_gen
            event = {"format": FORMAT, "sequence": seq,
                     "previous": None if self._head is None else self._head["journal_digest"],
                     "operation": operation, "args": packed_args, "state_sha256": state_hash,
                     "generation_digest": gen}
            journal = self._install("journal", event)
            head = {"format": FORMAT, "record_id": self._record, "configuration_sha256": self._configuration,
                    "sequence": seq, "journal_digest": journal, "generation_digest": gen,
                    "generation": new_state.confirmed.generation}
            raw = canonical({"head": head, "sha256": digest(canonical(head))})
            temp = self._temp(self._root, raw, "head")
            self._fault("head:before_replace")
            os.replace(temp, "HEAD", src_dir_fd=self._root, dst_dir_fd=self._root)
            self._fault("head:replaced")
            os.fsync(self._root)
            self._fault("head:durable")
            # Solo después de sincronizar el directorio se devuelve confirmación.
            self._head, self._head_raw, self._state = head, raw, new_state
            self._queries = queries
            if operation == "initialize":
                self._generation_refs = {new_state.confirmed.generation_reference}
            elif operation == "publish":
                self._generation_refs.add(new_state.confirmed.generation_reference)
            self._fault("commit:acknowledge")
            return self.state
        except BaseException:
            self._poisoned = True
            raise

    def _recover(self, expected_head):
        raw = self._read(self._root, "HEAD")
        envelope = parse(raw)
        exact_fields(envelope, ("head", "sha256"))
        head = envelope["head"]
        exact_fields(head, ("format", "record_id", "configuration_sha256", "sequence",
                            "journal_digest", "generation_digest", "generation"))
        require(envelope["sha256"] == digest(canonical(head)), "head_hash_mismatch")
        require(head["format"] == FORMAT, "storage_version_incompatible")
        require(head["record_id"] == self._record and head["configuration_sha256"] == self._configuration,
                "store_identity_mismatch")
        if expected_head is not None:
            _hash(expected_head)
            require(digest(raw) == expected_head, "head_anchor_mismatch")
        _index(head["sequence"])
        _index(head["generation"])
        require(head["sequence"] < MAX_RECORDS, "journal_capacity")
        _hash(head["generation_digest"])
        chain = []
        sha = head["journal_digest"]
        for seq in range(head["sequence"], -1, -1):
            event = self._object("journal", sha)
            exact_fields(event, ("format", "sequence", "previous", "operation", "args",
                                 "state_sha256", "generation_digest"))
            _index(event["sequence"])
            require(event["format"] == FORMAT and event["sequence"] == seq, "journal_sequence_invalid")
            chain.append(event)
            sha = event["previous"]
        require(sha is None, "journal_root_invalid")
        state, gen = None, None
        self._generation_refs = set()
        from ardrec.reconciliation import advance_index
        queries = {}
        for event in reversed(chain):
            args = unpack(event["args"])
            queries = advance_index(queries, state, event["operation"], args)
            state = _reduce(state, event["operation"], args)
            require(digest(canonical(pack(state))) == event["state_sha256"], "replay_mismatch")
            if event["operation"] in {"initialize", "publish"}:
                value = self._object("generations", event["generation_digest"])
                require(canonical(value) == canonical({"format": FORMAT, "previous": gen, "state": pack(state)}),
                        "generation_mismatch")
                ref = state.confirmed.generation_reference
                require(ref not in self._generation_refs, "generation_reference_reused")
                self._generation_refs.add(ref)
                gen = event["generation_digest"]
            require(event["generation_digest"] == gen, "generation_mismatch")
        require(state.confirmed.record_id == self._record
                and state.confirmed.configuration_sha256 == self._configuration
                and state.confirmed.generation == head["generation"]
                and gen == head["generation_digest"], "authority_mismatch")
        # Estabilizar una sustitución visible cuyo acuse pudo perderse antes del cierre.
        fd = os.open("HEAD", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self._root)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(self._root)
        require(self._read(self._root, "HEAD") == raw, "head_changed")
        self._head, self._head_raw, self._state = head, raw, state
        self._queries = queries
        self._check()

    @property
    def state(self):
        self._check()
        return self._state

    @property
    def head_sha256(self):
        self._check()
        return digest(self._head_raw)

    @property
    def recovery_action(self):
        state = self.state
        if state.invocation is not InvocationPhase.EN_CURSO:
            return "INVOCATION_ENDED"
        if any(entry["reply"] is None for entry in self._queries.values()):
            return "RECONCILE_QUERY_INCOMPLETE"
        pending = [a for a in state.attempts if a.pending]
        if pending:
            return "INCORPORATE_RESULT" if pending[0].technical_resolved else "RECONCILE_ATTEMPT"
        return "PUBLISH_CANDIDATE" if state.services != state.confirmed.services else "NONE"

    @property
    def reconciliation_history(self):
        self._check()
        return tuple(deepcopy(entry) for entry in self._queries.values())

    def record_reconciliation(self, operation, args):
        require(operation in {"reconcile_query_v1", "reconcile_reply_v1"}, "operation_unknown")
        return self._commit(operation, args)

    def reserve(self, request, *, decision_reference):
        """Persistir decisión e intención juntas, antes de cualquier posible envío externo."""
        return self._commit("reserve", {"request": encode_message(request),
                                        "decision_reference": decision_reference})

    def report(self, attempt_id, message, *, query=None):
        return self._commit("report", {"attempt_id": attempt_id, "message": encode_message(message),
                                       "query": None if query is None else encode_message(query)})

    def uncertain(self, attempt_id, reason_reference):
        return self._commit("uncertain", {"attempt_id": attempt_id, "reason_reference": reason_reference})

    def transition(self, service_id, transition, context):
        return self._commit("transition", {"service_id": service_id, "transition": transition, "context": context})

    def publish(self, *, expected_generation, reference, event):
        return self._commit("publish", {"expected_generation": expected_generation,
                                        "reference": reference, "event": event})

    def finish(self, outcome, reason_reference):
        return self._commit("finish", {"outcome": outcome, "reason_reference": reason_reference})

    def close(self):
        if not self._closed:
            require(os.getpid() != self._pid or threading.get_ident() == self._thread, "session_owner_mismatch")
            self._closed = True
            # Cerrar sin LOCK_UN evita liberar por error el bloqueo heredado tras fork.
            for fd in reversed(self._fds):
                os.close(fd)
            self._fds.clear()

    def __enter__(self):
        self._check()
        return self

    def __exit__(self, *exc):
        self.close()
