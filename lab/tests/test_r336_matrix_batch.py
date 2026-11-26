"""Native batch tests: synthetic only, no operational observations."""
import csv
import io
import unittest
import os
import tempfile
from pathlib import Path

from ardrec.experiments import matrix_batch as m, r149_scenario_design as r149
import test_r228_baseline_preparation as fixture


class MatrixBatchTests(unittest.TestCase):
    def setUp(self):
        self.t = fixture.BaselineTests(); self.t.setUp()
        self.proposal = r149.csv_bytes(r149.draft(fixture.CAT, self.t.protocol, self.t.registry)[2])
        self.rows = [{**{k: '' for k in m.FIELDS}, **r} for r in self.t.rows]
        self.objects = self.t.supports.copy()
        entry = self.t.entry
        self.rows[0]['configuration_sha256'] = entry['configuration_sha256']
        for d, rating in entry['ratings'].items():
            for k, v in rating.items(): self.rows[0][f'{d}_{k}'] = str(v)

    def raw(self):
        buf = io.StringIO(newline='')
        writer = csv.DictWriter(buf, fieldnames=m.FIELDS, lineterminator='\n')
        writer.writeheader(); writer.writerows(self.rows)
        return buf.getvalue().encode()

    def run_batch(self, pin=None):
        raw = self.raw()
        def read(ref):
            if ref not in self.objects: raise FileNotFoundError(ref)
            return self.objects[ref]
        return m.build(fixture.CAT, self.t.protocol, self.t.registry, self.t.plan,
                       self.t.checklist, self.proposal, raw, read,
                       expected_matrix_sha256=pin or m.i2.sha(raw))

    def test_single_native_candidate(self):
        report = self.run_batch()
        self.assertEqual(report['counts']['DOCUMENTARY_CANDIDATE_UNVERIFIED'], 1)
        d = report['records'][0]['decision']
        self.assertEqual((d['candidate_initial_risk'], d['candidate_normalized_criticality'],
                          d['hypothetical_rf_lower'], d['hypothetical_rf_upper']),
                         ('1/2','1/2','1/2','2/3'))
        self.assertEqual(report['records'][0]['i2_candidate_sha256'], self.t.calculate()['candidate']['sha256'])
        self.assertEqual(report['counts']['PENDING_FIELDS'], 53)
        self.assertEqual(report, self.run_batch())

    def test_full_batch(self):
        for row in self.rows[1:]:
            for k in m.EDITABLE: row[k] = self.rows[0][k]
            slot = row['slot_id']
            row.update(chosen_family=row['candidate_family'], case_id='C-'+slot,
                       scenario_id='S-'+slot, service_instance_id='I-'+slot)
        report = self.run_batch()
        self.assertEqual(report['counts']['DOCUMENTARY_CANDIDATE_UNVERIFIED'], 54)
        self.assertEqual(len({r['i2_candidate_sha256'] for r in report['records']}), 54)
        self.assertTrue(all(r['decision']['confirmed_rf'] is None for r in report['records']))
        self.assertEqual(report['experimental_admitted'], 0)
        self.assertEqual(report['p8'], 'NO-GO')

    def test_partial_supports_checked(self):
        row = self.rows[1]; ref = 'a'*64; row['configuration_sha256'] = ref
        r = self.run_batch()['records'][1]
        self.assertEqual(r['status'], 'PENDING_FIELDS'); self.assertEqual(r['missing_supports'], [ref])
        self.objects[ref] = b'invalid'
        with self.assertRaisesRegex(ValueError, 'MATRIX_SUPPORT_INTEGRITY_INVALID'):
            self.run_batch()

    def test_missing_complete_support(self):
        self.objects.pop(self.rows[0]['configuration_sha256'])
        report = self.run_batch()
        self.assertEqual(report['counts']['PENDING_SUPPORTS'], 1)
        self.assertIsNone(report['records'][0]['decision'])

    def test_bad_pin(self):
        with self.assertRaisesRegex(ValueError, 'MATRIX_PIN_INVALID'):
            self.run_batch('a'*64)

    def test_bad_partial_ordinal(self):
        self.rows[-1]['impact_ordinal'] = '6'
        with self.assertRaisesRegex(ValueError, 'MATRIX_ORDINAL_INVALID'):
            self.run_batch()

    def test_bad_partial_pilot(self):
        self.rows[-1]['service_instance_id'] = 'pilot-SMB-01'
        with self.assertRaisesRegex(ValueError, 'PILOT_IDENTITY_REUSE_FORBIDDEN'):
            self.run_batch()

    def test_duplicate_scenario(self):
        self.rows[1]['scenario_id'] = self.rows[0]['scenario_id']
        with self.assertRaisesRegex(ValueError, 'DUPLICATE_SCENARIO_ID'):
            self.run_batch()

    def filesystem(self, root):
        registry = root / 'registro'; selection = root / 'seleccion'
        m.r148.initialize(registry, fixture.CAT, self.t.protocol['head'])
        r149.create(selection, fixture.CAT, self.t.protocol, self.t.registry)
        matrix = root / 'matrix.csv'; matrix.write_bytes(self.raw()); matrix.chmod(0o600)
        supports = root / 'supports'; supports.mkdir(mode=0o700)
        for ref, raw in self.objects.items():
            path = supports / (ref+'.bin'); path.write_bytes(raw); path.chmod(0o600)
        catalog = fixture.ROOT / 'lab/operational-catalog-v1/catalog.json'
        return (registry, selection, matrix, supports, catalog, m.i2.sha(self.raw()))

    def test_private_file_batch(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.filesystem(Path(tmp))
            report = m.evaluate(*args)
            self.assertEqual(report, self.run_batch())
            self.assertEqual(args[2].read_bytes(), self.raw())
            self.assertEqual(m.evaluate(*args), report)

    def test_source_fifo_rejected_without_blocking(self):
        with tempfile.TemporaryDirectory() as tmp:
            args = self.filesystem(Path(tmp))
            path = args[0] / 'protocol.json'; path.unlink(); os.mkfifo(path, 0o600)
            with self.assertRaisesRegex(ValueError, 'I2_PRIVATE_FILE_INVALID'):
                m.evaluate(*args)
