"""P8-R9 regression: 15 operator observations and 29 never-authorized candidates."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'lab/verify_p8_material_inventory.py'
spec = importlib.util.spec_from_file_location('verify_p8_material_inventory', SOURCE)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def documents():
    base = ROOT / 'lab/p8-material-inventory-v1'
    inv=json.loads((base/'inventory.json').read_text())
    comp=json.loads((base/'compatibility.json').read_text())
    ids=checker.canonical_ids()
    fids=sorted({p.rsplit('-',1)[0] for p in ids})
    p7={'families':[{'id':fid, 'protocol':fid.split('-')[0].lower()} for fid in fids]}
    p8={'profile_slot_count':29,'count_by_protocol':{'ssh':8,'ftp':10,'smb':11},
        'execution_enabled':False,'profile_frozen':False,'cases_authorized':0,'real_cases':0,
        'policy':{'pilot_numeric_limits':None},'status':'P8_R1_UNBOUND_PROFILE_DESIGN_ONLY',
        'profiles':[{'profile_id':pid,'family_id':pid.rsplit('-',1)[0],
                     'protocol':pid.split('-')[0].lower(),'binding':{'b'+str(j):None for j in range(12)},
                     'status':'BLOCKED_UNBOUND_NO_EXECUTION'} for pid in ids]}
    stages={s:{'stage':s,'status':'RESERVED_NOT_DEPLOYED',
               'services':[],'scenarios':[],'cases':[],'executions':[],'attempts':[],'units':[]}
            for s in ('dev','pilot','exp')}
    return inv,comp,p7,p8,stages


class P8MaterialInventoryTests(unittest.TestCase):
    def setUp(self):
        self.d=list(documents())

    def reject(self):
        with self.assertRaises(checker.InventoryError):
            checker.validate(*self.d)

    def test_normal_deny_only_inventory(self):
        result=checker.validate(*self.d)
        self.assertEqual(result['status'],'PASS_P8_R9_REPORTED_MATERIAL_INVENTORY_DENY_ALL')
        self.assertEqual(result['binary_hashes'],15)
        self.assertEqual(result['candidate_profile_slots'],29)
        self.assertFalse(result['dispatch_allowed'])

    def test_exact_three_protocol_counts(self):
        p=self.d[1]['profiles']
        self.assertEqual([sum(x['profile_id'].startswith(prefix) for x in p)
                          for prefix in ('SSH','FTP','SMB')],[8,10,11])

    def test_image_digest_tamper(self):
        self.d[0]['image']['sha256']='a'*64
        self.reject()

    def test_image_backing_file_tamper(self):
        self.d[0]['image']['backing_file']='/tmp/overlay'
        self.reject()

    def test_image_size_tamper(self):
        self.d[0]['image']['observed_file_bytes']=0
        self.reject()

    def test_binary_sha_tamper(self):
        self.d[0]['binary_observations'][9]['sha256']='a'*64
        self.reject()

    def test_binary_duplicate_rejected(self):
        self.d[0]['binary_observations'][3]=copy.deepcopy(self.d[0]['binary_observations'][0])
        self.reject()

    def test_binary_synthetic_unclaimed_size(self):
        self.d[0]['binary_observations'][8]['observed_file_bytes']=100
        self.reject()

    def test_missing_sshpass_promoted_rejected(self):
        self.d[0]['absent_paths']=[]
        self.reject()

    def test_package_version_drift(self):
        self.d[0]['guest_package_matches']['curl']='UNVERIFIED'
        self.reject()

    def test_public_authority_promotion_rejected(self):
        for field in ('trusted_issuer_verified','private_authorization_verified',
                      'future_runtime_material_identity_verified','dispatch_allowed'):
            with self.subTest(field=field):
                d=copy.deepcopy(self.d)
                d[0][field]=True
                with self.assertRaises(checker.InventoryError):checker.validate(*d)

    def test_no_approved_profiles_or_cases(self):
        self.d[0]['authorized_case_count']=1
        self.reject()

    def test_no_binding_in_p8(self):
        self.d[3]['profiles'][0]['binding']['b0']='x'
        self.reject()

    def test_unknown_profile_rejected(self):
        self.d[1]['profiles'][0]['profile_id']='SSH-FAKE'
        self.reject()

    def test_profile_reordering_rejected(self):
        self.d[1]['profiles'].reverse()
        self.reject()

    def test_no_candidate_capability_promotion(self):
        self.d[1]['profiles'][0]['capability_tested']=True
        self.reject()

    def test_no_candidate_approval(self):
        self.d[1]['profiles'][0]['approval_verified']=True
        self.reject()

    def test_password_mechanism_not_invented(self):
        row=next(x for x in self.d[1]['profiles'] if x['profile_id']=='SSH-T03-BASE')
        self.assertEqual(row['additional_gate'],'PASSWORD_MECHANISM_NOT_VERIFIED')
        row['additional_gate']='SUPPORTED'
        self.reject()

    def test_write_requires_cleanup_evidence(self):
        row=next(x for x in self.d[1]['profiles'] if x['profile_id']=='SMB-T09-WRITE')
        row['additional_gate']='EXACT_OPERATION_NOT_VERIFIED'
        self.reject()

    def test_stages_must_remain_empty(self):
        self.d[4]['dev']['cases'].append({'not':'authorized'})
        self.reject()

    def test_no_change_to_p7_family_inventory(self):
        self.d[2]['families'].pop()
        self.reject()

    def test_json_duplicate_key_rejected(self):
        with self.assertRaises(checker.InventoryError):
            checker.parse(b'{"x":1,"x":2}')

    def test_json_nonfinite_rejected(self):
        with self.assertRaises(checker.InventoryError):
            checker.parse(b'{"x":NaN}')

    def test_does_not_import_runtime_dispatch(self):
        text=SOURCE.read_text()
        self.assertNotIn('from ardrec.attempts',text)
        self.assertNotIn('from ardrec.state import reserve_attempt',text)
        self.assertNotIn('std::process::Command',text)

    def test_source_only_not_experimental(self):
        self.assertFalse(self.d[0]['experiments_performed'])
        self.assertFalse(self.d[1]['dispatch_allowed'])


if __name__=='__main__':unittest.main()
