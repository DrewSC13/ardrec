"""R42.0 non-operational isolation-counter baseline tests."""
from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r34_containment as r34
from ardrec.coordination import r35_inactive_deployment as r35
from ardrec.coordination import r365_first_boot as r365
from ardrec.coordination import r42_isolation_baseline as r42
from ardrec.coordination import r41_ssh_resume as r41


def live():
    return {'phase':'SSH_RUNNING',
            'active_networks':[r365.SSH_NETWORK],
            'active_domains':[r365.SSH_DOMAIN],
            'reserved_links': sorted([r365.t33.NET_BRIDGE['ssh'],'a33d30t']),
            'bridge_macs':dict(r35.R354_EXISTING_BRIDGE_MACS),
            'deny_first_still_verified':True}


def counters(n=0):
    return {key:{'handle':k+101,'packets':n,'bytes':n*64}
            for k,key in enumerate(r42.EXPECTED_RULES)}


def source():
    return {'r411_report_sha256':r42.R411_REPORT_PIN,
            'r411_file_sha256':'0'*64,
            'r41_report_sha256':'1'*64}


def now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def nft(n=0):
    rows=[{'table':{'family':'bridge','name':r34.NFT_TABLE,'handle':1}}]
    for idx,chain in enumerate(('input','output','forward')):
        rows.append({'chain':{'family':'bridge','table':r34.NFT_TABLE,
                 'name':chain,'type':'filter','hook':chain,
                 'prio':-200,'policy':'accept','handle':2+idx}})
    for idx,key in enumerate(r42.EXPECTED_RULES):
        chain,direction=key.split(':')
        rows.append({'rule':{'family':'bridge','table':r34.NFT_TABLE,
                     'chain':chain,'handle':101+idx,
                     'expr':[{'match':{'left':{'meta':{'key':direction}},
                                        'op':'==','right':{'set':list(sorted(r35.TAPS))}}},
                             {'counter':{'packets':n,'bytes':n*64}},
                             {'drop':None}]}})
    return json.dumps({'nftables':rows}).encode()


def report():
    return r42.make_report(source(),live(),live(),counters(2),counters(3),
                           captured_at_utc=now())


class BaselineTests(unittest.TestCase):
    def test_exact_nft_policy_passes(self):
        self.assertEqual(set(r42.parse_nft_counters(nft())),set(r42.EXPECTED_RULES))

    def test_nft_drop_removed_rejected(self):
        x=json.loads(nft());x['nftables'][-1]['rule']['expr'][-1]={'accept':None}
        with self.assertRaises(Exception):
            r42.parse_nft_counters(json.dumps(x).encode())

    def test_nft_unexpected_rule_rejected(self):
        x=json.loads(nft());x['nftables'].append(deepcopy(x['nftables'][-1]))
        with self.assertRaises(Exception):
            r42.parse_nft_counters(json.dumps(x).encode())

    def test_nft_unexpected_interface_rejected(self):
        x=json.loads(nft());x['nftables'][-1]['rule']['expr'][0]['match']['right']['set'][0]='wlan0'
        with self.assertRaises(Exception):
            r42.parse_nft_counters(json.dumps(x).encode())

    def test_nft_missing_handle_rejected(self):
        x=json.loads(nft());x['nftables'][-1]['rule'].pop('handle')
        with self.assertRaisesRegex(r42.R42Error,'counter_identity_or_handle_invalid'):
            r42.parse_nft_counters(json.dumps(x).encode())

    def test_policy_snapshot_passes(self):
        d=report()
        self.assertEqual(d['counter_delta_unattributed']['input:iifname']['packets'],1)
        self.assertFalse(d['counters_prove_isolation'])
        self.assertFalse(d['active_test_performed'])
        self.assertEqual(d['p8_operational'],'NO-GO')
        self.assertTrue(r42.verify_report(d))

    def test_counter_reset_rejected(self):
        with self.assertRaisesRegex(r42.R42Error,'counter_reset'):
            r42.validate_samples(live(),live(),counters(3),counters(2))

    def test_handle_switch_rejected(self):
        later=counters(2);later['input:iifname']['handle']+=10
        with self.assertRaisesRegex(r42.R42Error,'counter_reset'):
            r42.validate_samples(live(),live(),counters(1),later)

    def test_host_state_drift_rejected(self):
        later=live();later['active_domains']=[]
        with self.assertRaises(Exception):
            r42.validate_samples(live(),later,counters(1),counters(2))

    def test_wrong_mac_rejected(self):
        later=live();later['bridge_macs']['ssh']='00:00:00:00:00:00'
        with self.assertRaises(Exception):
            r42.validate_samples(live(),later,counters(1),counters(2))

    def test_missing_filter_rejected(self):
        later=live();later['deny_first_still_verified']=False
        with self.assertRaises(Exception):
            r42.validate_samples(live(),later,counters(1),counters(2))

    def test_rehash_false_isolation_claim_rejected(self):
        d=report();d['counters_prove_isolation']=True
        d['sha256']=r41.sha(r41.canon({k:v for k,v in d.items() if k!='sha256'}))
        with self.assertRaisesRegex(r42.R42Error,'false_authority'):
            r42.verify_report(d)

    def test_rehash_false_active_test_rejected(self):
        d=report();d['active_test_performed']=True
        d['sha256']=r41.sha(r41.canon({k:v for k,v in d.items() if k!='sha256'}))
        with self.assertRaisesRegex(r42.R42Error,'false_authority'):
            r42.verify_report(d)

    def test_rehash_final_risk_rejected(self):
        d=report();d['final_risk']=0.05
        d['sha256']=r41.sha(r41.canon({k:v for k,v in d.items() if k!='sha256'}))
        with self.assertRaisesRegex(r42.R42Error,'false_authority'):
            r42.verify_report(d)

    def test_rehash_delta_tamper_rejected(self):
        d=report();d['counter_delta_unattributed']['input:iifname']['packets']+=1
        d['sha256']=r41.sha(r41.canon({k:v for k,v in d.items() if k!='sha256'}))
        with self.assertRaisesRegex(r42.R42Error,'counter_delta_tampered'):
            r42.verify_report(d)

    def test_rehash_wrong_source_rejected(self):
        d=report();d['source_r411_report_sha256']='f'*64
        d['sha256']=r41.sha(r41.canon({k:v for k,v in d.items() if k!='sha256'}))
        with self.assertRaisesRegex(r42.R42Error,'false_authority'):
            r42.verify_report(d)

    def test_private_receipt_and_checksums(self):
        with tempfile.TemporaryDirectory() as root:
            parent=Path(root)/'private';parent.mkdir(mode=0o700)
            dest=parent/'r42'
            d=report();r42.persist_private(dest,d)
            self.assertEqual(dest.stat().st_mode & 0o777,0o700)
            self.assertEqual((dest/r42.OUTPUT).stat().st_mode & 0o777,0o600)
            self.assertEqual(set(p.name for p in dest.iterdir()),{r42.OUTPUT,'SHA256SUMS'})
            self.assertIn(r41.sha((dest/r42.OUTPUT).read_bytes()),(dest/'SHA256SUMS').read_text())
            with self.assertRaises(Exception): r42.persist_private(dest,d)

    def test_public_parent_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            parent=Path(root)/'public';parent.mkdir(mode=0o755)
            # mkdir permissions are masked by process umask (e.g. 077).
            parent.chmod(0o755)
            self.assertEqual(parent.stat().st_mode & 0o777, 0o755)
            with self.assertRaisesRegex(r41.R41Error, 'receipt_parent_not_private'):
                r42.persist_private(parent/'r42', report())
            self.assertFalse((parent/'r42').exists())

    def test_symlink_parent_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            private=Path(root)/'private';private.mkdir(mode=0o700)
            link=Path(root)/'alias';link.symlink_to(private,target_is_directory=True)
            with self.assertRaises(Exception): r42.persist_private(link/'r42',report())

    def test_host_denies_write_apis(self):
        allowed={'sudo':'/usr/bin/sudo','nft':'/usr/sbin/nft',
                 'ip':'/usr/sbin/ip','virsh':'/usr/bin/virsh',
                 'qemu-img':'/usr/bin/qemu-img','stat':'/usr/bin/stat',
                 'sha256sum':'/usr/bin/sha256sum',
                 'virt-xml-validate':'/usr/bin/virt-xml-validate'}
        host=r42.ReadOnlyHost(which=allowed.get)
        with self.assertRaisesRegex(r42.R42Error,'write_forbidden'):
            host.sudo([host.bin['nft'],'-f','-'])
        with self.assertRaisesRegex(r42.R42Error,'r42_activation_forbidden'):
            host.activate_ssh_domain()
        with self.assertRaisesRegex(r42.R42Error,'r42_virsh_write_forbidden'):
            host.virsh_write(['start',r365.SSH_DOMAIN])

    def test_source_pin_mismatch_rejected(self):
        fake=source();fake['r411_report_sha256']='a'*64
        with self.assertRaisesRegex(r42.R42Error,'source_not_pinned'):
            r42.make_report(fake,live(),live(),counters(),counters(),captured_at_utc=now())

    def test_capture_valid_only_snapshot_no_injection(self):
        fake=type('Host',(),{})()
        fake.bin={'nft':'/usr/sbin/nft'}
        fake.sudo=lambda cmd:nft(7)
        self.assertEqual(r42.capture_counters(fake)['output:oifname']['packets'],7)

    def test_readback_failure_no_receipt(self):
        with patch.object(r42,'load_source',return_value=source()),\
             patch.object(r42.r411,'readback',side_effect=RuntimeError('changed')),\
             patch.object(r42,'persist_private') as persist:
            with self.assertRaisesRegex(RuntimeError,'changed'):
                r42.perform(r411_dir=Path('/x'),r41_dir=Path('/x'),r40_dir=Path('/x'),
                            r39_dir=Path('/x'),r365_preflight_dir=Path('/x'),
                            r365_boot_dir=Path('/x'),receipt_dir=Path('/x'),host=object())
            persist.assert_not_called()

    def test_preflight_readbacks_envelope(self):
        with patch.object(r42,'load_source',return_value=source()),\
             patch.object(r42.r411,'readback',side_effect=[live(),live()]) as rb,\
             patch.object(r42,'capture_counters',side_effect=[counters(1),counters(2)]) as cc,\
             patch.object(r42,'persist_private') as persist:
            d=r42.perform(r411_dir=Path('/x'),r41_dir=Path('/x'),r40_dir=Path('/x'),
                            r39_dir=Path('/x'),r365_preflight_dir=Path('/x'),
                            r365_boot_dir=Path('/x'),receipt_dir=Path('/x'),host=object())
            self.assertEqual(rb.call_count,2)
            self.assertEqual(cc.call_count,2)
            persist.assert_called_once()
            self.assertEqual(d['status'],r42.STATUS)


if __name__ == '__main__':
    unittest.main()
