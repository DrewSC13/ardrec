import importlib.util,json,tempfile,unittest,shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('verify_p5',ROOT/'lab/verify_restoration_isolation.py');mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod)
class RecordTests(unittest.TestCase):
 def test_reviewed_record(self):self.assertEqual(mod.verify(ROOT)['status'],'PASS_DOCUMENT_CONSISTENCY_ONLY')
 def test_widened_claims_rejected(self):
  for section,key,value in [('gui','automatic_ui_verification',True),('limits','physical_power_loss_tested',True),('limits','open_findings',[]),('isolation','prohibited_witness_frames',1),('restoration','analytical_counter_rollback_tested',True)]:
   with self.subTest(key=key),tempfile.TemporaryDirectory() as td:
    target=Path(td)/'lab';target.mkdir();shutil.copytree(ROOT/'lab/restoration-isolation-v1',target/'restoration-isolation-v1');shutil.copy(ROOT/'lab/verification-plan-v1.json',target)
    p=target/'restoration-isolation-v1/record.json';r=json.loads(p.read_text());r[section][key]=value;p.write_text(json.dumps(r))
    with self.assertRaises(ValueError):mod.verify(td)
 def test_missing_plan_coverage_rejected(self):
  with tempfile.TemporaryDirectory() as td:
   target=Path(td)/'lab';target.mkdir();shutil.copytree(ROOT/'lab/restoration-isolation-v1',target/'restoration-isolation-v1');r=json.loads((ROOT/'lab/verification-plan-v1.json').read_text());r['checks']=[x for x in r['checks'] if x['id']!='LAB-V03'];(target/'verification-plan-v1.json').write_text(json.dumps(r))
   with self.assertRaises(ValueError):mod.verify(td)
if __name__=='__main__':unittest.main()
