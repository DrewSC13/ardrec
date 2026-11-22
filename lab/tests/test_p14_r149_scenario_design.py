"""R149: catalog-grounded 54-unit selection workspace, never physical claims."""
from __future__ import annotations
import copy
import csv
import io
import os
from pathlib import Path
import tempfile
import unittest
from ardrec.experiments import r148_paired_register as r148
from ardrec.experiments import r149_scenario_design as m

HERE=Path(__file__).resolve().parents[2]
CAT=(HERE/'lab/operational-catalog-v1/catalog.json').read_bytes()
HEAD='cca70b5044d363bc03a31716bb9c65e29de365f0'
HASH='a'*64

class Tests(unittest.TestCase):
    def setUp(self):
        self.protocol,self.register=r148.build(CAT,HEAD)
        self.plan,self.checklist,self.rows=m.draft(CAT,self.protocol,self.register)
    def validate(self,rows=None,plan=None,checklist=None):
        return m.validate_selection(plan or self.plan,checklist or self.checklist,
           m.csv_bytes(self.rows if rows is None else rows),CAT,self.protocol,self.register)
    def selection(self,idx=0):
        rows=copy.deepcopy(self.rows)
        row=rows[idx]
        row.update({'chosen_family':row['candidate_family'],
            'case_id':f'case-{idx:02}', 'scenario_id':f'scenario-{idx:02}',
            'service_instance_id':f'instance-{idx//18}',
            'variation_reason':f'Distinct condition for unit {idx:02}',
            'scope_authorization_sha256':HASH,'preregistration_sha256':HASH,
            'static_estimate':'5','static_support_sha256':HASH})
        return rows
    def denied(self,code,rows=None,plan=None,checklist=None):
        with self.assertRaisesRegex(m.Stop,code):
            self.validate(rows,plan,checklist)
    def test_01_schema(self):self.assertEqual(self.plan['schema'],m.SCHEMA)
    def test_02_families(self):self.assertEqual(self.checklist['count'],25)
    def test_03_count(self):self.assertEqual(len(self.rows),54)
    def test_04_ssh(self):self.assertEqual(self.rows[0]['slot_id'],'SSH-01')
    def test_05_ftp(self):self.assertEqual(self.rows[18]['slot_id'],'FTP-01')
    def test_06_smb(self):self.assertEqual(self.rows[36]['slot_id'],'SMB-01')
    def test_07_last(self):self.assertEqual(self.rows[-1]['slot_id'],'SMB-18')
    def test_08_no_real_assigned(self):self.assertTrue(all(not x['case_id'] for x in self.rows))
    def test_09_candidate_coverage(self):self.assertEqual(self.validate()['candidate_family_coverage'],25)
    def test_10_18_by_proto(self):self.assertEqual([sum(x['protocol']==p for x in self.rows) for p in m.PROTOS],[18]*3)
    def test_11_not_p7(self):self.assertEqual(self.validate()['p7'],'DRAFT_NOT_FROZEN')
    def test_12_not_p8(self):self.assertEqual(self.validate()['p8'],'NO-GO')
    def test_13_no_a9(self):self.assertEqual(self.validate()['a9'],'NOT_PUBLISHED')
    def test_14_no_physical(self):self.assertEqual(self.validate()['physical_observations'],0)
    def test_15_initial_empty(self):self.assertEqual(self.validate()['statuses']['EMPTY'],54)
    def test_16_one_complete(self):self.assertEqual(self.validate(self.selection())['statuses']['COMPLETE'],1)
    def test_17_one_partial(self):
        x=copy.deepcopy(self.rows);x[0]['case_id']='case-0'
        self.assertEqual(self.validate(x)['statuses']['PARTIAL'],1)
    def test_18_fully_filled_remains_unverified(self):
        x=copy.deepcopy(self.rows)
        for i in range(54):x[i]=self.selection(i)[i]
        result=self.validate(x)
        self.assertEqual(result['readiness'],'CANDIDATE_COMPLETE_UNVERIFIED')
        self.assertEqual(result['physical_observations'],0)
    def test_19_tamper_slot(self):
        x=self.selection();x[0]['slot_id']='FTP-01';self.denied('SLOT_OR_PROPOSAL_TAMPERED',x)
    def test_20_tamper_family_proposal(self):
        x=self.selection();x[0]['candidate_family']='SSH-T08';self.denied('SLOT_OR_PROPOSAL_TAMPERED',x)
    def test_21_tamper_protocol(self):
        x=self.selection();x[0]['protocol']='FTP';self.denied('SLOT_OR_PROPOSAL_TAMPERED',x)
    def test_22_cross_family(self):
        x=self.selection();x[0]['chosen_family']='FTP-T01';self.denied('CHOSEN_FAMILY_INVALID',x)
    def test_23_bad_case(self):
        x=self.selection();x[0]['case_id']='bad case';self.denied('IDENTIFIER_INVALID',x)
    def test_24_bad_scenario(self):
        x=self.selection();x[0]['scenario_id']='';
        self.assertEqual(self.validate(x)['statuses']['PARTIAL'],1)
    def test_25_bad_instance(self):
        x=self.selection();x[0]['service_instance_id']='../../etc/passwd';self.denied('IDENTIFIER_INVALID',x)
    def test_26_duplicate_case(self):
        x=self.selection();x[1]=self.selection(1)[1];x[1]['case_id']=x[0]['case_id']
        self.denied('DUPLICATE_CASE_ID',x)
    def test_27_duplicate_scenario(self):
        x=self.selection();x[1]=self.selection(1)[1];x[1]['scenario_id']=x[0]['scenario_id']
        self.denied('DUPLICATE_SCENARIO_ID',x)
    def test_28_short_reason(self):
        x=self.selection();x[0]['variation_reason']='short';self.denied('VARIATION_REASON_INVALID',x)
    def test_29_bad_hash(self):
        x=self.selection();x[0]['scope_authorization_sha256']='bad';self.denied('DIGEST_REFERENCE_INVALID',x)
    def test_30_bad_static(self):
        x=self.selection();x[0]['static_estimate']='NaN';self.denied('DECIMAL_RANGE_OR_FINITE',x)
    def test_31_negative_static(self):
        x=self.selection();x[0]['static_estimate']='-5';self.denied('SPREADSHEET_FORMULA_DENIED',x)
    def test_32_formula(self):
        x=self.selection();x[0]['variation_reason']='=cmd()';self.denied('SPREADSHEET_FORMULA_DENIED',x)
    def test_33_plan_seal(self):
        p=copy.deepcopy(self.plan);p['p7']='FROZEN';self.denied('DOCUMENT_SEAL_INVALID',plan=p)
    def test_34_forged_plan_with_valid_sha(self):
        p=copy.deepcopy(self.plan);p['p7']='FROZEN';p.pop('sha256');p=m.sealed(p)
        self.denied('PLAN_OR_CATALOG_CHECKLIST_CHANGED',plan=p)
    def test_35_duplicate_header(self):
        s=m.csv_bytes(self.rows).replace(b'candidate_family',b'case_id',1)
        with self.assertRaisesRegex(m.Stop,'CSV_HEADER_OR_ROWS_INVALID'):m.parse_csv(s)
    def test_36_missing_row(self):
        with self.assertRaisesRegex(m.Stop,'CSV_HEADER_OR_ROWS_INVALID'):m.parse_csv(m.csv_bytes(self.rows[:-1]))
    def test_37_utf8_bom(self):
        with self.assertRaisesRegex(m.Stop,'CSV_HEADER_OR_ROWS_INVALID'):m.parse_csv(b'\xef\xbb\xbf'+m.csv_bytes(self.rows))
    def test_38_catalog_tamper(self):
        with self.assertRaises(Exception):m.draft(CAT+b'x',self.protocol,self.register)
    def test_39_registry_not_empty(self):
        self.register['slots'][0]['case_id']='fake'
        self.register['sha256']=r148.digest(r148.canonical({k:v for k,v in self.register.items() if k!='sha256'}))
        with self.assertRaises(Exception):m.draft(CAT,self.protocol,self.register)
    def test_40_candidate_balance(self):
        c=self.plan['candidate_counts'];self.assertEqual(sum(sum(x.values()) for x in c.values()),54)
        self.assertEqual({k:sum(v.values()) for k,v in c.items()},{'SSH':18,'FTP':18,'SMB':18})
        self.assertEqual(sorted(c['SMB'].values()),[2]*9)
    def test_41_checklist_preconditions(self):
        self.assertTrue(all(x['preconditions'] for x in self.checklist['families']))
    def test_42_csv_header(self):
        self.assertEqual(tuple(m.parse_csv(m.csv_bytes(self.rows))[0]),m.FIELDS)
    def test_43_duplicate_json(self):
        with self.assertRaises(m.Stop):m.decode(b'{"a":1,"a":2}\n')
    def test_44_code_nonauthority(self):
        self.assertEqual(self.validate()['claim'],'NEVER_THESIS_RESULT_OR_AUTHORIZATION')
    @unittest.skipIf(os.geteuid()==0,'tests need non-root')
    def test_45_create_read(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'r149';out=m.create(p,CAT,self.protocol,self.register)
            self.assertEqual(out['statuses']['EMPTY'],54)
            self.assertEqual(m.read(p,CAT,self.protocol,self.register),out)
    @unittest.skipIf(os.geteuid()==0,'tests need non-root')
    def test_46_not_overwrite(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'r149';m.create(p,CAT,self.protocol,self.register)
            with self.assertRaisesRegex(m.Stop,'NEW_FOLDER_REQUIRED'):m.create(p,CAT,self.protocol,self.register)
    @unittest.skipIf(os.geteuid()==0,'tests need non-root')
    def test_47_permissions(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'r149';m.create(p,CAT,self.protocol,self.register);p.chmod(0o755)
            with self.assertRaisesRegex(m.Stop,'DIRECTORY_UNSAFE'):m.read(p,CAT,self.protocol,self.register)
    @unittest.skipIf(os.geteuid()==0,'tests need non-root')
    def test_48_hardlink(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'r149';m.create(p,CAT,self.protocol,self.register)
            os.link(p/'plan.json',p/'alias.json')
            with self.assertRaisesRegex(m.Stop,'FILE_UNSAFE'):m.read(p,CAT,self.protocol,self.register)
    @unittest.skipIf(os.geteuid()==0,'tests need non-root')
    def test_49_symlink(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'r149';m.create(p,CAT,self.protocol,self.register)
            (p/'plan.json').unlink();(p/'plan.json').symlink_to(p/'family-checklist.json')
            with self.assertRaises(OSError):m.read(p,CAT,self.protocol,self.register)
    @unittest.skipIf(os.geteuid()==0,'tests need non-root')
    def test_50_file_mode(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'r149';m.create(p,CAT,self.protocol,self.register)
            (p/'selection-working.csv').chmod(0o644)
            with self.assertRaisesRegex(m.Stop,'FILE_UNSAFE'):m.read(p,CAT,self.protocol,self.register)
    @unittest.skipIf(os.geteuid()==0,'tests need non-root')
    def test_51_edited_selection(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'r149';m.create(p,CAT,self.protocol,self.register)
            (p/'selection-working.csv').write_bytes(m.csv_bytes(self.selection()))
            self.assertEqual(m.read(p,CAT,self.protocol,self.register)['statuses']['COMPLETE'],1)
    @unittest.skipIf(os.geteuid()==0,'tests need non-root')
    def test_52_original_proposal_immutable(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'r149';m.create(p,CAT,self.protocol,self.register)
            (p/'family-proposal.csv').write_bytes(b'fake')
            with self.assertRaisesRegex(m.Stop,'ORIGINAL_PROPOSAL_CHANGED'):m.read(p,CAT,self.protocol,self.register)
    @unittest.skipIf(os.geteuid()==0,'tests need non-root')
    def test_53_target_symlink(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'real';p.mkdir(mode=0o700)
            alias=Path(t)/'alias';alias.symlink_to(p,target_is_directory=True)
            with self.assertRaisesRegex(m.Stop,'NEW_FOLDER_REQUIRED'):m.create(alias,CAT,self.protocol,self.register)
    @unittest.skipIf(os.geteuid()==0,'tests need non-root')
    def test_54_wrong_parent_mode(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t);p.chmod(0o777)
            with self.assertRaisesRegex(m.Stop,'PARENT_UNSAFE'):m.create(p/'out',CAT,self.protocol,self.register)
    @unittest.skipIf(os.geteuid()==0,'tests need non-root')
    def test_55_outside_root(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaisesRegex(m.Stop,'NEW_FOLDER_REQUIRED'):
                m.create(Path(t)/'..'/'strange',CAT,self.protocol,self.register)
