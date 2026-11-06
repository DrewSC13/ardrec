"""Mutation/oracle tests for stage separation; no real host, credentials or network."""
import copy
import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('ardrec_p6_validator', ROOT/'lab/verify_scenario_separation.py')
V = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(V)
STAGES = ('dev','pilot','exp')


class SeparationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='ardrec-p6-')
        self.root=Path(self.tmp.name)
        base=self.root/'lab/scenario-separation-v1'
        base.parent.mkdir(parents=True)
        shutil.copytree(ROOT/'lab/scenario-separation-v1', base)
        (self.root/'lab/tests').mkdir(exist_ok=True)
        shutil.copy(ROOT/'lab/verify_scenario_separation.py',self.root/'lab/verify_scenario_separation.py')
        shutil.copy(ROOT/'lab/tests/test_scenario_separation.py',self.root/'lab/tests/test_scenario_separation.py')
        (self.root/'docs/traceability').mkdir(parents=True)
        shutil.copy(ROOT/'docs/traceability/scenario-separation-v1.json',
                    self.root/'docs/traceability/scenario-separation-v1.json')
        self._json('lab/topology-v1.json',{'status':'DESIGN_ONLY_NOT_DEPLOYED', 'max_active_environments':1,
            'networks':[{'id':f'ardrec-{stage}-{proto}','environment':stage,'protocol':proto,
                         'status':'RESERVED_DESIGN_RECHECK_BEFORE_DEPLOYMENT',
                         'cidr':f'10.203.{octet}.0/28','runner':f'10.203.{octet}.1','target':f'10.203.{octet}.2'}
                 for stage,octets in [('dev',(30,31,32)),('pilot',(40,41,42)),('exp',(50,51,52))]
                 for proto,octet in zip(('ssh','ftp','smb'),octets)]})
        self._json('lab/services-v1/evidence.json',{'environment':'dev','experimental_data':False})
        self._json('lab/restoration-isolation-v1/record.json',{'limits':{'environment':'development_only',
            'pilot_and_experiment_deployed':False,'experimental_validation':'NOT_RUN'}})
        self._json('docs/traceability/development-v2.json',{'requirements':[{'id':x} for x in
            ('AC-24','AC-25','AC-27','MET-09','MET-10','MET-12','MET-13')]})

    def tearDown(self): self.tmp.cleanup()

    def _json(self,path, obj):
        p=self.root/path;p.parent.mkdir(parents=True,exist_ok=True)
        p.write_text(json.dumps(obj,sort_keys=True,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    def _load(self,path): return json.loads((self.root/path).read_text(encoding='utf-8'))
    def _alter(self,path,mutator):
        r=self._load(path);mutator(r);self._json(path,r)
    def _assert_bad(self):
        with self.assertRaises((ValueError,KeyError,TypeError)): V.validate(self.root)
    def _scenario(self,stage='dev',protocol='ssh'):
        mpath=f'lab/scenario-separation-v1/{stage}.json';m=self._load(mpath)
        prefix=f'{stage}'
        m['services'].append({'id':f'{prefix}-svc-a','protocol':protocol,'network_id':f'ardrec-{stage}-{protocol}',
                              'instance_ref':'local-fixture-not-real'})
        profile={'version':'DEBIAN13_TEST','configuration_sha256':'1'*64,'exposure':'synthetic',
                 'authentication':'synthetic-account','controls_sha256':'2'*64,
                 'initial_state_sha256':'3'*64,'context_sha256':'4'*64}
        m['scenarios'].append({'id':f'{prefix}-scn-a','service_id':f'{prefix}-svc-a',
            'profile':profile,'technical_fingerprint':V.canonical_sha({'protocol':protocol,'profile':profile}),
            'prior_use':[],'origin_scenario_ids':[]})
        self._json(mpath,m)
        return mpath
    def _records(self):
        path=self._scenario('dev')
        m=self._load(path)
        m['cases']=[{'id':'dev-case-a','scenario_id':'dev-scn-a','family_id':'SSH-T01'}]
        m['executions']=[{'id':'dev-exec-a','scenario_id':'dev-scn-a','unit_id':None}]
        m['attempts']=[{'id':'dev-att-a','execution_id':'dev-exec-a','case_id':'dev-case-a','repetition_of':None}]
        m['artifacts']=[{'id':'dev-art-a','scenario_id':'dev-scn-a','execution_id':'dev-exec-a',
              'attempt_id':'dev-att-a','category':'evidence','path':'private/dev/evidence/fixture/a.txt',
              'sha256':'a'*64,'origin_stage':'dev','prior_use':['dev']}]
        self._json(path,m)
        return path

    def test_empty_stage_manifests_are_consistent(self):
        self.assertEqual(V.validate(self.root)['status'],'PASS_LOGICAL_SEPARATION_ONLY')
    def test_valid_synthetic_relation_chain(self):
        self._records();self.assertEqual(V.validate(self.root)['registered_scenarios'],1)
    def test_real_repository_manifest_consistency(self):
        if (ROOT/'lab/topology-v1.json').is_file():
            self.assertEqual(V.validate(ROOT)['status'],'PASS_LOGICAL_SEPARATION_ONLY')

    def test_traceability_status_cannot_be_promoted(self):
        self._alter('docs/traceability/scenario-separation-v1.json',
                    lambda r:r['verification'].update(ci='PASS'))
        self._assert_bad()
    def test_same_service_instance_in_two_stages_rejected(self):
        a=self._scenario('dev')
        b=self._scenario('pilot')
        self._assert_bad()

    def test_source_and_freeze_guards(self):
        for key,value in [('sample_frozen',True),('pilot_completed',True),('experimental_validation','PASS')]:
            with self.subTest(key=key):
                reg=self._load('lab/scenario-separation-v1/registry.json')
                reg['experimental_design'][key]=value
                self._json('lab/scenario-separation-v1/registry.json',reg);self._assert_bad()
                shutil.copy(ROOT/'lab/scenario-separation-v1/registry.json',self.root/'lab/scenario-separation-v1/registry.json')
    def test_cross_stage_network_rejected(self):
        self._alter('lab/scenario-separation-v1/pilot.json',lambda m: m.update(network_ids=['ardrec-dev-ssh','ardrec-pilot-ftp','ardrec-pilot-smb']))
        self._assert_bad()
    def test_cross_stage_private_root_rejected(self):
        self._alter('lab/scenario-separation-v1/registry.json',lambda r:r['stages']['exp'].update(private_root='private/pilot'))
        self._assert_bad()
    def test_shared_base_containing_prior_observations_rejected(self):
        self._alter('lab/scenario-separation-v1/exp.json',lambda m:m['shared_bases'].append({
          'id':'base','sha256':'f'*64,'provenance':'test','purpose':'GENERIC_TOOL_OR_OS_BASE',
          'contains_prior_observations':True}))
        self._assert_bad()
    def test_promoted_experimental_unit_rejected(self):
        p=self._scenario('exp');self._alter(p,lambda m:m['units'].append({
          'id':'exp-unit-a','scenario_id':'exp-scn-a','protocol':'ssh','status':'PLANNED_NOT_FROZEN'}))
        self._assert_bad()
    def test_identical_technical_condition_dev_exp_rejected(self):
        self._scenario('dev');self._scenario('exp');self._assert_bad()
    def test_cross_stage_service_reference_rejected(self):
        p=self._scenario('dev');self._alter(p,lambda m:m['scenarios'][0].update(service_id='pilot-svc-a'));self._assert_bad()
    def test_wrong_namespace_rejected(self):
        p=self._scenario('pilot');self._alter(p,lambda m:m['services'][0].update(id='dev-svc-a'));self._assert_bad()
    def test_prior_use_pilot_in_dev_rejected(self):
        p=self._scenario('dev');self._alter(p,lambda m:m['scenarios'][0]['prior_use'].append({
          'stage':'pilot','purpose':'PILOT','record_id':'test'}));self._assert_bad()
    def test_technical_fingerprint_tamper_rejected(self):
        p=self._scenario('pilot');self._alter(p,lambda m:m['scenarios'][0].update(technical_fingerprint='0'*64));self._assert_bad()
    def test_wrong_family_rejected(self):
        p=self._records();self._alter(p,lambda m:m['cases'][0].update(family_id='SMB-T09'));self._assert_bad()
    def test_case_attempt_cross_scenario_rejected(self):
        p=self._records();self._alter(p,lambda m:m['attempts'][0].update(case_id='pilot-case-a'));self._assert_bad()
    def test_artifact_path_traversal_rejected(self):
        p=self._records();self._alter(p,lambda m:m['artifacts'][0].update(path='private/dev/evidence/../../exp/results/x'));self._assert_bad()
    def test_artifact_pilot_path_rejected(self):
        p=self._records();self._alter(p,lambda m:m['artifacts'][0].update(path='private/pilot/evidence/a.txt'));self._assert_bad()
    def test_artifact_prior_use_pilot_rejected(self):
        p=self._records();self._alter(p,lambda m:m['artifacts'][0].update(prior_use=['pilot']));self._assert_bad()
    def test_missing_attempt_identity_rejected(self):
        p=self._records();self._alter(p,lambda m:m['artifacts'][0].update(attempt_id='dev-att-missing'));self._assert_bad()
    def test_duplicate_json_key_rejected(self):
        p=self.root/'lab/scenario-separation-v1/dev.json'
        p.write_text(p.read_text().replace('"schema_version": "1.0",','"schema_version": "1.0", "schema_version": "1.0",'))
        self._assert_bad()
    def test_old_dev_evidence_not_relabelled(self):
        self._alter('lab/services-v1/evidence.json',lambda e:e.update(environment='exp'));self._assert_bad()
    def test_old_restoration_not_promoted(self):
        self._alter('lab/restoration-isolation-v1/record.json',lambda e:e['limits'].update(pilot_and_experiment_deployed=True));self._assert_bad()
    def test_too_many_networks_rejected(self):
        self._alter('lab/topology-v1.json',lambda t:t['networks'].append(copy.deepcopy(t['networks'][0])));self._assert_bad()
    def test_unknown_model_field_rejected(self):
        p=self._scenario('dev');self._alter(p,lambda m:m['scenarios'][0].update(unsafe_field='unreviewed'));self._assert_bad()
    def test_attempt_not_new_unit(self):
        p=self._records();self._alter(p,lambda m:m['units'].append({
            'id':'dev-unit-a','scenario_id':'dev-scn-a','protocol':'ssh','status':'PLANNED_NOT_FROZEN'}));self._assert_bad()


if __name__=='__main__': unittest.main()
