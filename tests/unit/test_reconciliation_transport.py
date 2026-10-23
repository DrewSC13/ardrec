"""Canales incompletos conservan la consulta y nunca publican efectos analíticos."""
import socket
import threading
import time
import unittest

from ardrec.reconciliation import inspect_recovery
from ardrec.reconciliation_transport import ExchangeError, exchange_query
from ardrec.transport import MAX_FRAME_BYTES, read_frame
from test_persistence import DurableStore, INITIAL, prepare, reserve, reopen
from test_reconciliation import query, reply
from pathlib import Path
import tempfile


def frame(raw):
    return len(raw).to_bytes(4, "big") + raw


class ReconciliationTransportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="ardrec-query-channel-")
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "python"
        self.store = DurableStore.create(self.path, INITIAL)
        self.addCleanup(self.store.close)
        prepare(self.store)
        reserve(self.store)
        self.raw = query(self.store)
        self.before = self.store.head_sha256

    def channel(self, data, *, fragments=False, delay=0, timeout=1):
        client, peer = socket.socketpair()
        failures = []

        def server():
            try:
                with peer, peer.makefile("rwb", buffering=0) as stream:
                    peer.settimeout(2)
                    self.assertEqual(read_frame(stream).encode(), self.raw)
                    self.assertEqual(stream.read(1), b"")
                    if delay:
                        time.sleep(delay)
                    parts = (data[i:i + 1] for i in range(len(data))) if fragments else (data,)
                    for part in parts:
                        peer.sendall(part)
            except (BrokenPipeError, ConnectionResetError):
                pass
            except BaseException as error:
                failures.append(error)

        worker = threading.Thread(target=server)
        worker.start()
        try:
            return exchange_query(self.store, client, timeout=timeout)
        finally:
            client.close()
            worker.join(3)
            self.assertFalse(worker.is_alive())
            if failures:
                raise failures[0]

    def pending(self):
        self.assertEqual(self.store.head_sha256, self.before)
        decision = inspect_recovery(self.store)
        self.assertEqual((decision.action, decision.open_query, decision.queries_used),
                         ("QUERY_INCOMPLETE", self.raw, 1))
        self.assertFalse(decision.new_execution_authorized)
        self.assertEqual(self.store.state.confirmed.generation, 1)
        self.assertEqual(self.store.state.incorporated_execution_count, 0)

    def test_complete_pair_and_restart(self):
        response, result = reply(self.raw)
        decision = self.channel(frame(response) + frame(result))
        self.assertEqual(decision.action, "READY_FOR_VALIDATION")
        self.assertEqual(decision.result, result)
        self.assertFalse(decision.new_execution_authorized)
        self.assertEqual(self.store.state.confirmed.generation, 1)
        self.store.close()
        with reopen(self.path) as recovered:
            self.assertEqual(inspect_recovery(recovered), decision)

    def test_fragmented_pair(self):
        response, result = reply(self.raw)
        self.assertEqual(self.channel(frame(response) + frame(result), fragments=True).result, result)

    def test_missing_and_truncated_frames(self):
        response, result = reply(self.raw)
        for data in (b"", b"\0", frame(response)[:-1], frame(response),
                     frame(response) + frame(result)[:-1]):
            with self.subTest(length=len(data)), self.assertRaises(ExchangeError):
                self.channel(data)
            self.pending()

    def test_oversized_and_invalid_utf8(self):
        for data in (b"\0\0\0\0", (MAX_FRAME_BYTES + 1).to_bytes(4, "big"), frame(b"\xff")):
            with self.assertRaises(ExchangeError):
                self.channel(data)
            self.pending()

    def test_trailing_bytes_and_duplicate_response(self):
        response, result = reply(self.raw)
        for suffix in (b"x", frame(response), frame(result)):
            with self.assertRaises(ExchangeError):
                self.channel(frame(response) + frame(result) + suffix)
            self.pending()

    def test_invalid_json_and_version(self):
        response, _ = reply(self.raw)
        for raw in (b"{", b"{}", response.replace(b'"2.0"', b'"9.0"'),
                    response.replace(b'"schema_version":"2.0"', b'"schema_version":"2.0","schema_version":"2.0"')):
            with self.assertRaises(ExchangeError):
                self.channel(frame(raw))
            self.pending()

    def test_canonical_encoding_required(self):
        response, result = reply(self.raw)
        with self.assertRaises(ExchangeError):
            self.channel(frame(b" " + response) + frame(result))
        self.pending()

    def test_correlation_and_result_identity(self):
        response, result = reply(self.raw)
        for raw_response, raw_result in (
            (response.replace(b'"QUERY-1"', b'"OTHER-QUERY"'), result),
            (response, result.replace(b'"RESULT-completed"', b'"OTHER-RESULT"')),
        ):
            with self.assertRaises(ExchangeError):
                self.channel(frame(raw_response) + frame(raw_result))
            self.pending()

    def test_uncertain_response_does_not_confirm_absence(self):
        response, result = reply(self.raw, "uncertain")
        self.assertIsNone(result)
        decision = self.channel(frame(response))
        self.assertEqual(decision.action, "QUERY_REQUIRED")
        self.assertFalse(decision.new_execution_authorized)
        self.assertFalse(self.store.state.attempts[0].technical_resolved)

    def test_query_required_and_socket_consumed(self):
        response, result = reply(self.raw)
        self.channel(frame(response) + frame(result))
        client, peer = socket.socketpair()
        with peer, self.assertRaises(ExchangeError) as error:
            exchange_query(self.store, client)
        self.assertEqual(error.exception.code, "open_query_required")
        self.assertEqual(client.fileno(), -1)

    def test_timeout_keeps_same_query_for_retry(self):
        with self.assertRaises(ExchangeError) as error:
            self.channel(b"", delay=0.1, timeout=0.02)
        self.assertEqual(error.exception.code, "timeout")
        self.pending()
        response, result = reply(self.raw)
        self.assertEqual(self.channel(frame(response) + frame(result)).queries_used, 1)

    def test_whole_exchange_deadline_against_trickle(self):
        client, peer = socket.socketpair()
        def slow_peer():
            with peer, peer.makefile("rb", buffering=0) as stream:
                read_frame(stream)
                stream.read(1)
                try:
                    for _ in range(30):
                        peer.sendall(b"\0")
                        time.sleep(0.03)
                except OSError:
                    pass
        worker = threading.Thread(target=slow_peer)
        worker.start()
        start = time.monotonic()
        try:
            with self.assertRaises(ExchangeError):
                exchange_query(self.store, client, timeout=0.05)
            self.assertLess(time.monotonic() - start, 0.5)
        finally:
            client.close()
            worker.join(2)
        self.pending()

    def test_invalid_timeout_and_channel_type(self):
        for timeout in (0, -1, True, "1", None, float("inf"), float("nan"), 61):
            client, peer = socket.socketpair()
            with peer, self.assertRaises(ExchangeError):
                exchange_query(self.store, client, timeout=timeout)
            self.assertEqual(client.fileno(), -1)
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        with self.assertRaises(ExchangeError):
            exchange_query(self.store, connection)
        self.assertEqual(connection.fileno(), -1)
        self.pending()

    def test_result_without_status_is_rejected(self):
        _, result = reply(self.raw)
        with self.assertRaises(ExchangeError):
            self.channel(frame(result))
        self.pending()
