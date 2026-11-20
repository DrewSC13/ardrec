"""Independent negative-boundary regression of R115-F1's offline contract."""
import copy
import json
import unittest
from pathlib import Path
from ardrec.coordination import r115_dev_admission_contract as m

ROOT = Path(__file__).resolve().parents[2]
CAT_RAW = (ROOT / 'lab/operational-catalog-v1/catalog.json').read_bytes()
CAT = m.load(CAT_RAW)


def source():
    return {
        'schema':m.SCHEMA, 'case_id':'FTP-T01-R115-DEV', 'family_id':'FTP-T01',
        'stage':'DEV', 'created_at':'2026-11-20T12:00:00-04:00',
        'valid_from':'2026-11-20T12:00:00-04:00',
        'valid_until':'2026-11-20T13:00:00-04:00',
        'source_commit':'a652195a544a549dbad6a44120e3d447cf4d4994',
        'catalog_sha256':m.digest(CAT_RAW),
        'target':{'vm':'ardrec-r33-dev-ftp','ip':'10.203.31.2','port':21,
                  'mac':'52:54:00:00:00:01','network':'ardrec-r33-dev-net-ftp'},
        **{x:{'id':'R115_REFERENCE_ONLY','sha256':'a'*64}
           for x in ('client','profile','authority','isolation','service')},
        'limits':{'ordinary_attempts':1,'additional_attempts':0,
                  'timeout_seconds':10,'operation_count':1,'request_count':1,
                  'transfer_bytes':1024,'output_bytes':2048,'memory_mib':64}
    }


class ContractTests(unittest.TestCase):
    def test_offline_report_never_enables_execution(self):
        report=m.validate(source(), CAT, CAT_RAW)
        self.assertTrue(report['static_contract_valid'])
        self.assertEqual(set(report['a3_status']),set(m.GATES))
        self.assertEqual(set(report['a3_status'].values()), {'ND'})
        self.assertFalse(report['a5_executable'])
        self.assertEqual(report['p8'],'NO-GO')
        self.assertIsNone(report['a7_final_risk'])
        self.assertIsNone(report['a9_published_generation'])

    def test_strict_limits(self):
        for key in m.LIMIT_KEYS:
            for invalid in (None,0,-1,True,1.1,m.MAXIMUMS[key]+1):
                with self.subTest(key=key,value=invalid):
                    x=source(); x['limits'][key]=invalid
                    with self.assertRaises(m.Rejected):m.validate(x,CAT,CAT_RAW)

    def test_attempt_scope_and_target(self):
        changes=[('limits','additional_attempts',1),('limits','ordinary_attempts',2),
                 ('target','ip','10.203.30.2'),('target','port',445),
                 ('target','network','external'),('target','mac','bad')]
        for section,key,value in changes:
            with self.subTest(section=section,key=key):
                x=source();x[section][key]=value
                with self.assertRaises(m.Rejected):m.validate(x,CAT,CAT_RAW)

    def test_reject_draft_catalog_promotion(self):
        for key,value in (('execution_enabled',True),('catalog_frozen',True),
                          ('pilot_completed',True),('status','EXECUTABLE')):
            d=copy.deepcopy(CAT);d[key]=value
            x=source();r=m.canonical(d);x['catalog_sha256']=m.digest(r)
            with self.subTest(key=key),self.assertRaises(m.Rejected):m.validate(x,d,r)

    def test_contract_integrity_and_window(self):
        cases=[('stage','PILOT'),('family_id','SSH-T01'),('catalog_sha256','0'*64),
               ('valid_until','2026-11-22T12:00:00-04:00'),
               ('valid_from','2026-11-20T14:00:00-04:00')]
        for key,value in cases:
            x=source();x[key]=value
            with self.subTest(key=key),self.assertRaises(m.Rejected):m.validate(x,CAT,CAT_RAW)

    def test_untrusted_reference_and_unknown_keys(self):
        x=source(); x['authority']['sha256']='NOT_HASH'
        with self.assertRaises(m.Rejected):m.validate(x,CAT,CAT_RAW)
        x=source();x['authorization_granted']=True
        with self.assertRaises(m.Rejected):m.validate(x,CAT,CAT_RAW)

    def test_duplicate_json_and_nonfinite(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'[]',b''):
            with self.subTest(raw=raw), self.assertRaises(m.Rejected):m.load(raw)

    def test_deterministic_report(self):
        raw=m.canonical(source())
        self.assertEqual(m.validate_bytes(raw,CAT_RAW),m.validate_bytes(raw,CAT_RAW))
        self.assertTrue(m.validate_bytes(raw,CAT_RAW).endswith(b'\n'))

if __name__ == '__main__':unittest.main()
