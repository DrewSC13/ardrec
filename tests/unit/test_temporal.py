"""Causalidad actual, compatibilidad histórica y duración independiente de UTC."""
import json
import os
from pathlib import Path
import pickle
import tempfile
import unittest
from unittest.mock import patch
from ardrec.messages import MessageError, correlate, encode_message
from ardrec.persistence import DurableStore
from ardrec.reconciliation import complete_query, inspect_recovery
from ardrec.temporal import MonotonicTimer, correlate_current
from test_persistence import INITIAL, FIXTURES, prepare, reserve, reopen
from test_reconciliation import query, reply
ROOT=Path(__file__).resolve().parents[2]
OLD=json.loads((ROOT/'tests/fixtures/messages-v2.json').read_text())
CASES=json.loads((ROOT/'tests/fixtures/temporal-policy-v1.json').read_text())['cases']

class TemporalTests(unittest.TestCase):
    def test_independent_temporal_oracles(self):
        for case in CASES:
            with self.subTest(case=case['id']):
                if case['expected_error'] is None:
                    correlate_current(case['request'],case['related'])
                else:
                    with self.assertRaises(MessageError) as caught:correlate_current(case['request'],case['related'])
                    self.assertEqual(caught.exception.code,case['expected_error'])

    def test_legacy_structural_reader_unchanged(self):
        correlate(OLD['request'],OLD['result_completed'])
        with self.assertRaisesRegex(MessageError,'temporal_inversion'):correlate_current(OLD['request'],OLD['result_completed'])

    def test_current_journal_rejects_before_write(self):
        with tempfile.TemporaryDirectory() as d:
            with DurableStore.create(Path(d)/'store',INITIAL) as store:
                prepare(store);store.reserve(OLD['request'],decision_reference='DEC-1')
                before=store.head_sha256
                with self.assertRaisesRegex(MessageError,'temporal_inversion'):store.report('ATT-1',OLD['result_completed'])
                self.assertEqual(store.head_sha256,before)
                self.assertFalse(store.state.attempts[0].technical_resolved)
                self.assertFalse(inspect_recovery(store).new_execution_authorized)

    def test_historical_journal_readable_but_not_promoted(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'store'
            # Simular exclusivamente la admisión del escritor anterior.
            with patch('ardrec.temporal.audit_current'),DurableStore.create(path,INITIAL) as store:
                prepare(store);store.reserve(OLD['request'],decision_reference='DEC-1')
                store.report('ATT-1',OLD['result_completed']);head=store.head_sha256
            saved={str(p.relative_to(path)):p.read_bytes() for p in path.rglob('*') if p.is_file()}
            with reopen(path) as store:
                self.assertEqual(store.head_sha256,head)
                self.assertEqual(store.state.attempts[0].reports[0].message,encode_message(OLD['result_completed']))
                self.assertEqual(store.temporal_status,'TEMPORAL_REVIEW_REQUIRED')
                self.assertEqual(inspect_recovery(store).action,'TEMPORAL_REVIEW_REQUIRED')
                self.assertFalse(inspect_recovery(store).new_execution_authorized)
                with self.assertRaisesRegex(MessageError,'temporal_inversion'):store.report('ATT-1',OLD['result_completed'])
                self.assertEqual(store.head_sha256,head)
            self.assertEqual(saved,{str(p.relative_to(path)):p.read_bytes() for p in path.rglob('*') if p.is_file()})

    def test_reconciliation_rejects_old_start_and_retains_query(self):
        with tempfile.TemporaryDirectory() as d:
            with DurableStore.create(Path(d)/'store',INITIAL) as store:
                prepare(store);store.reserve(OLD['request'],decision_reference='DEC-1')
                q=query(store);response,result=reply(q,result=OLD['result_completed']);before=store.head_sha256
                with self.assertRaisesRegex(MessageError,'temporal_inversion'):complete_query(store,q,response,result=result)
                self.assertEqual(store.head_sha256,before)
                self.assertEqual(inspect_recovery(store).action,'QUERY_INCOMPLETE')
                self.assertFalse(inspect_recovery(store).new_execution_authorized)

    def test_valid_current_journal_reopens(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'store'
            with DurableStore.create(path,INITIAL) as store:
                prepare(store);reserve(store);store.report('ATT-1',FIXTURES['result_completed']);before=store.head_sha256
            with reopen(path) as store:
                self.assertEqual(store.temporal_status,'PASS');self.assertEqual(store.head_sha256,before)

    def test_integer_duration_rounding(self):
        for ticks,expected in ((0,0),(999999,0),(1000000,1),(1999999,1),((2**53+1)*1000000,2**53+1)):
            with self.subTest(ticks=ticks),patch('ardrec.temporal.time.monotonic_ns',side_effect=[12,12+ticks]):
                self.assertEqual(MonotonicTimer().elapsed_ms(),expected)

    def test_utc_clock_never_used_for_duration(self):
        with patch('ardrec.temporal.time.time',side_effect=AssertionError('UTC must not be read')),patch('ardrec.temporal.time.monotonic_ns',side_effect=[10,2000010]):
            self.assertEqual(MonotonicTimer().elapsed_ms(),2)

    def test_duration_overflow_rejected(self):
        with patch('ardrec.temporal.time.monotonic_ns',side_effect=[0,2**63*1000000]):
            with self.assertRaisesRegex(ValueError,'duration_overflow'):MonotonicTimer().elapsed_ms()

    def test_monotonic_regression_rejected(self):
        with patch('ardrec.temporal.time.monotonic_ns',side_effect=[2,1]):
            with self.assertRaisesRegex(ValueError,'monotonic_regression'):MonotonicTimer().elapsed_ms()

    def test_timer_cannot_be_persisted(self):
        with self.assertRaisesRegex(TypeError,'not_persistable'):pickle.dumps(MonotonicTimer())

    def test_real_fork_cannot_reuse_timer(self):
        timer=MonotonicTimer();pid=os.fork()
        if pid==0:
            try:timer.elapsed_ms()
            except ValueError as error:os._exit(0 if str(error)=='clock_origin_changed' else 2)
            os._exit(3)
        self.assertEqual(os.waitpid(pid,0)[1],0)
