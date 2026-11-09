#!/usr/bin/env python3
"""P8-R16-R6 CI reproduction of all 55 P8-R16-R5 synthetic model checks."""
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent))
import p8_r16_ssh_precedence as m

CASES=HERE.parent/'p8-r16-ssh-precedence-v1'/'cases.json'

def doc():
    return json.loads(CASES.read_text())

def find(name):
    return next(c for c in doc()['cases'] if c['id']==name)

def dummy_r4():
    return {'scope':'P8_R16_R4_DOCUMENTARY_SEMANTIC_REVIEW_NO_RUNTIME',
            'base_main_commit':m.MAIN,
            'source_entries':25,'source_cross_references':17,
            'documentary_interpretations':[{'term':str(x)} for x in range(25)],
            'cross_option_dependencies':[{'id':str(x)} for x in range(17)],
            **m.DENIALS}

class PureModels(unittest.TestCase):
    def test_01_all_frozen_cases(self):
        f=doc();m.validate_fixture(f)
        self.assertEqual(len(m.test_oracles(f)),10)
    def test_02_exact_profile(self):
        self.assertEqual(doc()['profile_id'],'SSH-T01-BASE')
    def test_03_frozen_r4_sha(self):
        self.assertEqual(m.R4_SHA,'c2dbfcb7ab667008cb35c7432be883e3cb68b123fb5b1329216a7d012b2697ee')
    def test_04_fixture_frozen_sha(self):
        self.assertEqual(m.sha(CASES.read_bytes()),m.RULES_SHA)
    def test_05_report_deterministic(self):
        x=m.canonical(m.build_report(dummy_r4(),doc()))
        y=m.canonical(m.build_report(dummy_r4(),doc()))
        self.assertEqual(x,y)
    def test_06_report_deny_only(self):
        r=m.build_report(dummy_r4(),doc())
        self.assertFalse(r['configuration_effective_verified'])
        self.assertFalse(r['dispatch_allowed'])
        self.assertEqual(r['approved_cli_options'],0)
    def test_07_report_argv_is_absent(self):
        r=m.build_report(dummy_r4(),doc())
        self.assertEqual(r['runnable_argv_renderers'],0)
        self.assertTrue(all(x['runnable_argv'] is None for x in r['cases']))
    def test_08_no_actual_connection_material(self):
        raw=m.canonical(m.build_report(dummy_r4(),doc()))
        self.assertNotIn(b'BEGIN PRIVATE KEY',raw)
        self.assertNotIn(b'192.168.',raw)
        self.assertNotIn(b'/home/cicada/.ssh',raw)
    def test_09_first_value_early_wildcard(self):
        r=m.simulate(find('SYN_EARLY_GLOBAL_UNSAFE'))
        self.assertEqual(r['first_value_projection']['stricthostkeychecking']['value'],'no')
        self.assertIn('POLICY_MISMATCH:stricthostkeychecking',r['violations'])
    def test_10_first_value_specific_before_default(self):
        r=m.simulate(find('SYN_SPECIFIC_FIRST_FALLBACK'))
        self.assertEqual(r['first_value_projection']['proxyjump']['value'],'none')
        self.assertIn('IGNORED_LATER_VALUE',[x['resolution'] for x in r['trace']])
    def test_11_negation_has_priority(self):
        self.assertFalse(m.host_match(['*','!SIM_TGT_A'],'SIM_TGT_A'))
        self.assertTrue(m.host_match(['SIM_TGT_*'],'SIM_TGT_A'))
    def test_12_negation_only_never_matches(self):
        self.assertFalse(m.host_match(['!SIM_OTHER'],'SIM_TGT_A'))
    def test_13_user_before_system(self):
        c=find('SYN_CLI_FIRST_VALUE')
        c['layers']['cli']=[]
        c['layers']['system']=[{'patterns':['*'],
                              'directives':[{'name':'StrictHostKeyChecking','value':'ask'}]}]
        self.assertEqual(m.simulate(c)['first_value_projection']['stricthostkeychecking']['value'],'no')
    def test_14_cli_before_user(self):
        self.assertEqual(m.simulate(find('SYN_CLI_FIRST_VALUE'))['first_value_projection']['stricthostkeychecking']['value'],'yes')
    def test_15_identityfile_additive(self):
        r=m.simulate(find('SYN_IDENTITY_ADDITIVE'))
        self.assertEqual([x['symbolic_ref'] for x in r['additive_identity_projection']],['REF_KEY_A','REF_KEY_B'])
    def test_16_certificate_additive(self):
        c=find('SYN_IDENTITY_ADDITIVE')
        c['layers']['system']=[{'patterns':['*'],'directives':[{'name':'CertificateFile','value':'REF_CERT_A'},
                           {'name':'CertificateFile','value':'REF_CERT_B'}]}]
        self.assertEqual([x['symbolic_ref'] for x in m.simulate(c)['additive_certificate_projection']],
                         ['REF_CERT_A','REF_CERT_B'])
    def test_17_missing_explicit_is_not_default_safe(self):
        self.assertIn('REQUIRED_EXPLICIT_MISSING:stricthostkeychecking',
                     m.simulate(find('SYN_NO_HOSTKEY_POLICY'))['violations'])
    def test_18_batchmode_default_not_a_verified_timeout(self):
        r=m.simulate(find('SYN_DEBIAN_IMPLICIT_ALIVE'))
        self.assertIn('DEBIAN_DOCUMENTED_BATCHMODE_SERVERALIVE_300_NOT_RUNTIME_ATTESTED',
                      r['documented_derived_defaults'])
        self.assertIn('REQUIRED_EXPLICIT_MISSING:serveraliveinterval',r['violations'])
    def test_19_no_identity_is_not_proven(self):
        self.assertIn('NO_SYMBOLIC_IDENTITY_REFERENCE',
                       m.simulate(find('SYN_MISSING_SYMBOLIC_IDENTITY'))['violations'])
    def test_20_rewritten_host_not_accepted(self):
        self.assertIn('POLICY_MISMATCH:hostname',m.simulate(find('SYN_HOSTNAME_REWRITE'))['violations'])
    def test_21_jump_not_accepted(self):
        self.assertIn('POLICY_MISMATCH:proxyjump',m.simulate(find('SYN_PROXY_JUMP_FORBIDDEN'))['violations'])
    def test_22_match_exec_not_grammar(self):
        with self.assertRaises(m.ModelError): m.validate_directive({'name':'Match','value':'exec'})
    def test_23_include_not_grammar(self):
        with self.assertRaises(m.ModelError): m.validate_directive({'name':'Include','value':'foo'})
    def test_24_local_command_not_grammar(self):
        with self.assertRaises(m.ModelError): m.validate_directive({'name':'LocalCommand','value':'SIM_UNSAFE_EXTERNAL'})
    def test_25_ssh_config_path_not_grammar(self):
        with self.assertRaises(m.ModelError): m.validate_directive({'name':'IdentityFile','value':'/tmp/private.key'})
    def test_26_actual_hostname_not_grammar(self):
        with self.assertRaises(m.ModelError): m.validate_directive({'name':'Hostname','value':'example.com'})
    def test_27_value_domain_closed(self):
        with self.assertRaises(m.ModelError): m.validate_directive({'name':'BatchMode','value':'True'})
    def test_28_option_casefold(self):
        self.assertEqual(m.validate_directive({'name':'hOstnAME','value':'SIM_TGT_A'}),('hostname','SIM_TGT_A'))
    def test_29_extra_directive_field(self):
        with self.assertRaises(m.ModelError): m.validate_directive({'name':'BatchMode','value':'yes','argv':['ssh']})
    def test_30_invalid_host_pattern(self):
        with self.assertRaises(m.ModelError): m.validate_patterns(['[a-z]*'])
    def test_31_cli_has_no_host_pattern(self):
        f=doc();f['cases'][0]['layers']['cli']=[{'name':'Host','value':'*'}]
        with self.assertRaises(m.ModelError): m.validate_fixture(f)
    def test_32_no_real_host_override_in_document(self):
        f=doc();f['target_ref']='8.8.8.8'
        with self.assertRaises(m.ModelError): m.validate_fixture(f)
    def test_33_no_extra_root_fields(self):
        f=doc();f['runtime_authorized']=True
        with self.assertRaises(m.ModelError): m.validate_fixture(f)
    def test_34_reject_dispatch_promotion(self):
        f=doc();f['dispatch_allowed']=True
        with self.assertRaises(m.ModelError):m.validate_fixture(f)
    def test_35_reject_comprehensive_review_promotion(self):
        f=doc();f['complete_semantic_reviews']=1
        with self.assertRaises(m.ModelError):m.validate_fixture(f)
    def test_36_wrong_r4_hash(self):
        f=doc();f['source_r4_sha256']='0'*64
        with self.assertRaises(m.ModelError):m.validate_fixture(f)
    def test_37_wrong_main(self):
        f=doc();f['base_main_commit']='0'*40
        with self.assertRaises(m.ModelError):m.validate_fixture(f)
    def test_38_duplicate_case(self):
        f=doc();f['cases'].append(copy.deepcopy(f['cases'][0]))
        with self.assertRaises(m.ModelError):m.validate_fixture(f)
    def test_39_oracle_first_value_detects_drift(self):
        f=doc();f['cases'][0]['expected']['first_wins']['batchmode']='no'
        with self.assertRaises(m.ModelError):m.test_oracles(f)
    def test_40_oracle_additive_detects_drift(self):
        f=doc();f['cases'][2]['expected']['additive_identities']=[]
        with self.assertRaises(m.ModelError):m.test_oracles(f)
    def test_41_oracle_violations_detects_drift(self):
        f=doc();f['cases'][1]['expected']['violations']=[]
        with self.assertRaises(m.ModelError):m.test_oracles(f)
    def test_42_real_r4_not_automatically_authorized(self):
        fake=dummy_r4();fake['configuration_effective_verified']=True
        with self.assertRaises(m.ModelError):m.validate_r4(fake)
    def test_43_r4_bad_count_rejected(self):
        fake=dummy_r4();fake['cross_option_dependencies']=[]
        with self.assertRaises(m.ModelError):m.validate_r4(fake)
    def test_44_private_file_mode_0600(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'private.json';raw=b'{}\n';p.write_bytes(raw);p.chmod(0o600)
            self.assertEqual(m.bounded_private(p,m.sha(raw)),raw)
    def test_45_private_file_mode_0644_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'private.json';p.write_bytes(b'{}');p.chmod(0o644)
            with self.assertRaises(m.ModelError):m.bounded_private(p,m.sha(b'{}'))
    def test_46_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'private.json';p.write_bytes(b'{}');p.chmod(0o600)
            s=Path(d)/'alias.json';s.symlink_to(p)
            with self.assertRaises(m.ModelError):m.bounded_private(s,m.sha(b'{}'))
    def test_47_size_bound_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'private.json';p.write_bytes(b'x'*100);p.chmod(0o600)
            with self.assertRaises(m.ModelError):m.bounded_private(p,m.sha(b'x'*100),max_bytes=99)
    def test_48_hash_mismatch_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'private.json';p.write_bytes(b'{}');p.chmod(0o600)
            with self.assertRaises(m.ModelError):m.bounded_private(p,'0'*64)
    def test_49_fifo_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'pipe';os.mkfifo(p);p.chmod(0o600)
            with self.assertRaises(m.ModelError):m.bounded_private(p,'0'*64)
    def test_50_private_output_exclusive(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'result.json'
            got=m.write_once(p,b'{}\n')
            self.assertEqual(got,m.sha(b'{}\n'))
            self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
            with self.assertRaises(m.ModelError):m.write_once(p,b'new')
            self.assertEqual(p.read_bytes(),b'{}\n')
    def test_51_preexisting_output_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'result.json';t=Path(d)/'elsewhere';t.write_bytes(b'origin')
            p.symlink_to(t)
            with self.assertRaises(m.ModelError):m.write_once(p,b'mutated')
            self.assertEqual(t.read_bytes(),b'origin')
    def test_52_unapproved_profile(self):
        f=doc();f['profile_id']='SSH-T07-BASE'
        with self.assertRaises(m.ModelError):m.validate_fixture(f)
    def test_53_command_shell_marker_not_parsed_as_argv(self):
        c=find('SYN_SPECIFIC_FIRST_FALLBACK')
        c['layers']['cli']=[{'name':'ProxyCommand','value':'SIM_UNSAFE_EXTERNAL'}]
        self.assertIn('POLICY_MISMATCH:proxycommand',m.simulate(c)['violations'])
    def test_54_nonexecutable_source(self):
        src=Path(m.__file__).read_text()
        self.assertNotIn('subprocess.run([\'ssh\'',src)
        self.assertNotIn('socket.connect',src)
    def test_55_no_openssh_runtime_success_claim(self):
        report=m.build_report(dummy_r4(),doc())
        self.assertEqual(report['model_scope'],'STRICT_SYNTHETIC_JSON_NOT_REAL_SSH_CONFIG')
        self.assertTrue(all('AUTHENTICATED_EFFECTIVE_CONFIG_FROM_PINNED_GUEST_BINARY' in x['missing_operational_proofs'] for x in report['cases']))


class IntegratedModelBoundaries(unittest.TestCase):
    def test_56_complete_legacy_oracle_replay(self):
        self.assertEqual(len(m.test_oracles(doc())),10)
    def test_57_zero_runnable_argv(self):
        self.assertTrue(all(m.simulate(c)['runnable_argv'] is None for c in doc()['cases']))
    def test_58_private_r4_not_embedded(self):
        self.assertNotIn('candidate_roff',CASES.read_text())
    def test_59_no_ssh_or_subprocess_import(self):
        s=Path(m.__file__).read_text()
        self.assertNotIn('import subprocess',s)
        self.assertNotIn('import socket',s)
    def test_60_fixture_pin_is_identical_to_r5(self):
        self.assertEqual(m.sha(CASES.read_bytes()),'406cfeaf7fbd677235a520a56c4d324792b58996b9f1e8fe007f92798ba6fd5f')
    def test_61_main_pin_preexisting_baseline(self):
        self.assertEqual(m.MAIN,'4453c98720ba9ee86bcdf9909b71829f15b05dfa')
    def test_62_r4_pin_preexisting_receipt(self):
        self.assertEqual(m.R4_SHA,'c2dbfcb7ab667008cb35c7432be883e3cb68b123fb5b1329216a7d012b2697ee')
    def test_63_no_renderers_ever(self):
        self.assertEqual(doc()['runnable_argv_renderers'],0)
    def test_64_reject_case_with_runtime_approval(self):
        z=doc();z['cases'][0]['authorized']=True
        with self.assertRaises(m.ModelError):m.validate_fixture(z)
    def test_65_reject_unsafe_synthetic_directive(self):
        z=doc();z['cases'][0]['layers']['cli'].append({'name':'Match','value':'exec'})
        with self.assertRaises(m.ModelError):m.validate_fixture(z)
    def test_66_source_is_only_synthetic(self):
        self.assertEqual(doc()['scope'],'P8_R16_R5_SYNTHETIC_ONLY_NOT_OPENSSH_CONFIG')
    def test_67_no_network_target(self):
        raw=m.canonical(m.test_oracles(doc()))
        self.assertNotIn(b'10.0.0.',raw)
        self.assertNotIn(b'127.0.0.1',raw)
    def test_68_no_positive_authorization_from_full_fixture(self):
        f=doc();self.assertFalse(f['dispatch_allowed'])
        self.assertFalse(f['configuration_effective_verified'])

if __name__=='__main__':
    unittest.main(verbosity=2)
