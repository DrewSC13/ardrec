"""R112-F9: synthetic guard tests only; never count as physical runner proof."""
from __future__ import annotations
from copy import deepcopy
from pathlib import Path
import hashlib
import sys
import unittest

REPO=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(REPO/'src'),str(REPO/'scripts'),str(REPO/'lab/tests')]
from ardrec.coordination import r112_f9_runner_boot as f9
import ardrec_p14_r111_legacy_host_snapshot as legacy
import ardrec_p14_r112_f4_isolated_networks as f4
from test_p14_r112_f8_ssh_positive_boot import after_ssh, successful_command


def after_runner(before):
    after=deepcopy(before)
    after['snapshot']['probes']['vm-runner-state']['stdout']='running\n'
    for role in f9.NETWORKS:
        key='net-'+role+'-xml'
        old=after['snapshot']['probes'][key]['stdout']
        if '<network>' in old:
            count='2' if role=='ssh' else '1'
            after['snapshot']['probes'][key]['stdout']=old.replace(
                '<network>',f'<network connections="{count}">',1)
    after['snapshot']['summary']=legacy.summarize(after['snapshot']['probes'])
    return after


class RunnerBootGuardTests(unittest.TestCase):
    def setUp(self):
        self.before=after_ssh()
        self.after=after_runner(self.before)
        self.doc=f9.ticket(1795094100,'a'*64)
        digest=hashlib.sha256(f9.canon(self.doc)).hexdigest()
        self.grant={'directory_stat':'0:0 700 '+f9.ROOT,
                    'lease_stat':'0:0 600 1 '+str(len(f9.canon(self.doc)))+' '+f9.LEASE,
                    'lease_sha256':digest}
        self.claims={kind:{'stat':'0:0 600 1 65 '+path,
                           'content':digest+'\n'}
                     for kind,path in f9.MARKERS.items()}
        self.live=self.before['snapshot']['probes']['vm-runner-inactive-xml']['stdout']

    def classify(self,**kw):
        return f9.classify(kw.get('before',self.before),kw.get('after',self.after),
                           kw.get('start',successful_command()),kw.get('live',self.live),
                           kw.get('doc',self.doc),kw.get('grant',self.grant),
                           kw.get('claims',self.claims),legacy=legacy,f4=f4)

    def test_bounded_runner_boot(self):
        rec=self.classify()
        self.assertTrue(rec['runner_running'])
        self.assertTrue(rec['ssh_running'])
        self.assertEqual(rec['p8_operational'],'NO-GO')
        self.assertFalse(rec['traffic_authorized'])
        self.assertEqual(rec['a6'],'ND')

    def test_ticket_and_exact_guest(self):
        self.assertEqual(f9.GUEST,'ardrec-r33-dev-runner')
        self.assertEqual(f9.START[-1],f9.GUEST)
        self.assertEqual(self.doc['expires_at']-self.doc['issued_at'],180)
        self.assertEqual(self.doc['mode'],'ONE_START_ONLY_NO_TRAFFIC_AUTHORITY')

    def test_invalid_token_rejected(self):
        for nonce in ('abc','f'*63,'Z'*64):
            with self.assertRaises(ValueError): f9.ticket(12345,nonce)

    def test_precondition_runner_must_be_off(self):
        with self.assertRaisesRegex(ValueError,'WRONG_GUEST_STATE_runner'):
            f9.audited(self.after,runner_running=False,legacy=legacy,f4=f4)

    def test_after_requires_runner_running(self):
        with self.assertRaisesRegex(ValueError,'WRONG_GUEST_STATE_runner'):
            self.classify(after=self.before)

    def test_ssh_must_remain_running(self):
        changed=deepcopy(self.after)
        changed['snapshot']['probes']['vm-ssh-state']['stdout']='shut off\n'
        changed['snapshot']['summary']=legacy.summarize(changed['snapshot']['probes'])
        with self.assertRaises(ValueError): self.classify(after=changed)

    def test_ftp_must_remain_off(self):
        changed=deepcopy(self.after)
        changed['snapshot']['probes']['vm-ftp-state']['stdout']='running\n'
        changed['snapshot']['summary']=legacy.summarize(changed['snapshot']['probes'])
        with self.assertRaises(ValueError): self.classify(after=changed)

    def test_smb_must_remain_off(self):
        changed=deepcopy(self.after)
        changed['snapshot']['probes']['vm-smb-state']['stdout']='running\n'
        changed['snapshot']['summary']=legacy.summarize(changed['snapshot']['probes'])
        with self.assertRaises(ValueError): self.classify(after=changed)

    def test_network_connections_dynamic_allowed(self):
        self.assertTrue(f9.compare(self.before,self.after,legacy=legacy,f4=f4))

    def test_network_forward_change_rejected(self):
        changed=deepcopy(self.after)
        key='net-ftp-xml'
        xml=changed['snapshot']['probes'][key]['stdout']
        xml=xml.replace('</network>','<forward mode="nat"/></network>')
        changed['snapshot']['probes'][key]['stdout']=xml
        changed['snapshot']['summary']=legacy.summarize(changed['snapshot']['probes'])
        with self.assertRaises(ValueError): self.classify(after=changed)

    def test_f11_hook_drift_rejected(self):
        changed=deepcopy(self.after)
        changed['snapshot']['probes']['f11-hook-hash']['stdout']='0'*64+'  /x\n'
        changed['snapshot']['summary']=legacy.summarize(changed['snapshot']['probes'])
        with self.assertRaises(ValueError): self.classify(after=changed)

    def test_denial_filter_removed_rejected(self):
        changed=deepcopy(self.after)
        key='vm-runner-inactive-xml'
        xml=changed['snapshot']['probes'][key]['stdout']
        changed['snapshot']['probes'][key]['stdout']=xml.replace('ardrec-r33-block-until-containment','other-filter')
        changed['snapshot']['summary']=legacy.summarize(changed['snapshot']['probes'])
        with self.assertRaises(ValueError): self.classify(after=changed)

    def test_ticket_hash_tamper_rejected(self):
        changed=deepcopy(self.grant);changed['lease_sha256']='0'*64
        with self.assertRaises(ValueError):self.classify(grant=changed)

    def test_missing_claim_rejected(self):
        claims=deepcopy(self.claims);claims.pop('active')
        with self.assertRaises(ValueError):self.classify(claims=claims)

    def test_wrong_claim_permissions_rejected(self):
        claims=deepcopy(self.claims)
        claims['stage']['stat']=claims['stage']['stat'].replace('600','644')
        with self.assertRaises(ValueError):self.classify(claims=claims)

    def test_generic_start_error_rejected(self):
        command=successful_command();command['rc']=1
        with self.assertRaisesRegex(ValueError,'RUNNER_START_NOT_ATTESTED'):
            self.classify(start=command)

    def test_live_extra_interface_rejected(self):
        modified=self.live.replace('</devices>','<interface type="network"/></devices>')
        with self.assertRaises(ValueError):self.classify(live=modified)

    def test_network_ssh_bridge_drift_rejected(self):
        changed=deepcopy(self.after)
        key='net-ssh-xml'
        changed['snapshot']['probes'][key]['stdout']=changed['snapshot']['probes'][key]['stdout'].replace('br33d30','br33x30')
        changed['snapshot']['summary']=legacy.summarize(changed['snapshot']['probes'])
        with self.assertRaises(ValueError):self.classify(after=changed)

    def test_source_does_not_auto_destroy_or_enable_network(self):
        script=(REPO/'scripts/ardrec_p14_r112_f9_runner_boot.py').read_text()
        self.assertNotIn("'destroy',core.GUEST",script)
        self.assertNotIn("'net-start'",script)
        self.assertNotIn("'nft','add'",script)
        self.assertNotIn('subprocess.Popen(',script)
        self.assertIn('RUNNER_BOOT_ALREADY_ATTEMPTED',script)

if __name__=='__main__': unittest.main()
