"""B6: real R124 parse API simulated, never promote a timer into root proof."""
from __future__ import annotations
import copy
from datetime import datetime,timezone
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ardrec.coordination import r124_root_deny_readback as r124
from ardrec.coordination import r127_failure_observer as b6
from test_p14_r124_root_deny_readback import Fake, timer

HEAD='7c1bf90c36b17ace9b670b360b6c183770297bec'
SESSION='0123456789abcdef'
BOOT='aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee'
NOW=datetime(2026,11,21,22,0,0,tzinfo=timezone.utc)


def sample(i=1,*,running=('ssh','runner','ftp'),session=SESSION,timer_state='active',
           boot=BOOT,head=HEAD):
    f=Fake(running,session)
    if session is not None:
        name='ardrec-r116-f1-deny-'+session+'.timer'
        command=(r124.SYSCTL,'show',name,'--no-pager', '-p','LoadState','-p','ActiveState',
                 '-p','Unit','-p','NextElapseUSecMonotonic')
        f.mutate[command]=(0,timer(name,state=timer_state,load='loaded'))
    report=r124.inspect(head=head,now=NOW,run=f)
    return {'started_ns':i*1_000_000_000,'finished_ns':i*1_000_000_000+120_000_000,
            'boot_id':boot,'readback':report,'marker_session':session}


class TestObserve(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='b6-r127-')
        self.addCleanup(self.tmp.cleanup)
        self.parent=Path(self.tmp.name)
        self.parent.chmod(0o700)

    def test_01_baseline_offline_no_timer(self):
        s=sample(session=None,running=())
        x=b6.assemble(head=HEAD,records=[s],session=None)
        self.assertEqual(x['status'],'OBSERVATION_ONLY_NO_SESSION')
        self.assertFalse(x['session_timer_seen_active'])
        self.assertEqual(x['p8'],'NO-GO')

    def test_02_five_one_arm_active(self):
        x=b6.assemble(head=HEAD,records=[sample()],session=SESSION)
        self.assertEqual(x['status'],'SESSION_TIMER_STILL_ACTIVE_NOT_CLOSURE_PROOF')
        self.assertTrue(x['session_timer_seen_active'])

    def test_03_observed_timer_then_inactive(self):
        x=b6.assemble(head=HEAD,records=[sample(1),sample(2,timer_state='inactive')],
                      session=SESSION)
        self.assertTrue(x['session_timer_seen_inactive_after_active'])
        self.assertFalse(x['verified_physical_60s_restore'])
        self.assertFalse(x['independent_signed_root_witness'])
        self.assertEqual(x['a6'],'ND')

    def test_04_post_offline_allowed(self):
        x=b6.assemble(head=HEAD,records=[sample(1),sample(2,timer_state='inactive',running=())],
                      session=SESSION)
        self.assertEqual(x['sample_chain'][1]['stage'],'OFFLINE_DENY_MATCH')

    def test_05_replay(self):
        x=b6.assemble(head=HEAD,records=[sample(1),sample(2,timer_state='inactive')],session=SESSION)
        self.assertTrue(b6.verify(x))

    def test_06_hash_chain(self):
        x=b6.assemble(head=HEAD,records=[sample(1),sample(2,timer_state='inactive')],session=SESSION)
        self.assertEqual(x['chain_head_sha256'],x['sample_chain'][-1]['sha256'])
        self.assertIsNone(x['sample_chain'][0]['previous_sha256'])

    def test_07_wrong_marker(self):
        s=sample();s['marker_session']='f'*16
        with self.assertRaisesRegex(b6.Stop,'ANOTHER_SESSION'):b6.assemble(head=HEAD,records=[s],session=SESSION)

    def test_08_marker_absent_but_active_claim(self):
        s=sample();s['marker_session']=None
        with self.assertRaisesRegex(b6.Stop,'MARKER_AND_READBACK'):b6.assemble(head=HEAD,records=[s],session=SESSION)

    def test_09_armed_session_never_seen(self):
        s=sample(session=None,running=('ssh','runner','ftp'))
        with self.assertRaisesRegex(b6.Stop,'NEVER_OBSERVED'):b6.assemble(head=HEAD,records=[s],session=SESSION)

    def test_10_other_head(self):
        with self.assertRaisesRegex(b6.Stop,'R124_ROOT_READBACK_UNVERIFIED'):
            b6.assemble(head='f'*40,records=[sample()],session=SESSION)

    def test_11_wrong_guard_hash_even_matching_report_hash(self):
        s=sample();s['readback']['root_guard_sha256']='f'*64
        s['readback']['sha256']=b6.sha({k:v for k,v in s['readback'].items() if k!='sha256'})
        with self.assertRaisesRegex(b6.Stop,'R124_ROOT_READBACK_UNVERIFIED'):
            b6.assemble(head=HEAD,records=[s],session=SESSION)

    def test_12_fake_allow_network(self):
        s=sample();s['readback']['p8']='GO'
        s['readback']['sha256']=b6.sha({k:v for k,v in s['readback'].items() if k!='sha256'})
        with self.assertRaises(b6.Stop):b6.assemble(head=HEAD,records=[s],session=SESSION)

    def test_13_fake_60s_claim(self):
        s=sample();s['readback']['root_60s_deadline_verified']=True
        s['readback']['sha256']=b6.sha({k:v for k,v in s['readback'].items() if k!='sha256'})
        with self.assertRaises(b6.Stop):b6.assemble(head=HEAD,records=[s],session=SESSION)

    def test_14_boot_changed(self):
        with self.assertRaisesRegex(b6.Stop,'BOOT_CHANGED'):
            b6.assemble(head=HEAD,records=[sample(1),sample(2,boot='f'*8+'-bbbb-4ccc-8ddd-eeeeeeeeeeee')],session=SESSION)

    def test_15_sample_order_reversed(self):
        with self.assertRaisesRegex(b6.Stop,'SAMPLE_MONOTONIC_ORDER'):
            b6.assemble(head=HEAD,records=[sample(2),sample(1)],session=SESSION)

    def test_16_bad_sample_start_bool(self):
        s=sample();s['started_ns']=True
        with self.assertRaisesRegex(b6.Stop,'SAMPLE_MONOTONIC_INVALID'):
            b6.assemble(head=HEAD,records=[s],session=SESSION)

    def test_17_single_read_too_slow(self):
        s=sample();s['finished_ns']+=25_000_000_000
        with self.assertRaisesRegex(b6.Stop,'SAMPLE_MONOTONIC_INVALID'):
            b6.assemble(head=HEAD,records=[s],session=SESSION)

    def test_18_timer_reactivated(self):
        with self.assertRaisesRegex(b6.Stop,'SESSION_TIMER_REARMED'):
            b6.assemble(head=HEAD,records=[sample(1),sample(2,timer_state='inactive'),sample(3)],session=SESSION)

    def test_19_timer_active_topology_offline(self):
        with self.assertRaisesRegex(b6.Stop,'OUTSIDE_FIVE_ONE'):
            b6.assemble(head=HEAD,records=[sample(running=())],session=SESSION)

    def test_20_missing_timer_state(self):
        s=sample();s['readback']['session_timer_state']=None
        s['readback']['sha256']=b6.sha({k:v for k,v in s['readback'].items() if k!='sha256'})
        with self.assertRaisesRegex(b6.Stop,'SESSION_TIMER_INVALID'):
            b6.assemble(head=HEAD,records=[s],session=SESSION)

    def test_21_tamper_report_status(self):
        x=b6.assemble(head=HEAD,records=[sample()],session=SESSION)
        x['status']='PHYSICAL_SUCCESS'
        with self.assertRaisesRegex(b6.Stop,'OBSERVATION_TAMPERED'):b6.verify(x)

    def test_22_tamper_chain(self):
        x=b6.assemble(head=HEAD,records=[sample()],session=SESSION)
        x['sample_chain'][0]['sha256']='0'*64
        with self.assertRaisesRegex(b6.Stop,'OBSERVATION_TAMPERED'):b6.verify(x)

    def test_23_persist_and_replay(self):
        x=b6.assemble(head=HEAD,records=[sample()],session=SESSION)
        p=b6.persist(x,root=self.parent)
        self.assertEqual(b6.verify_persisted(p),x)
        self.assertEqual(p.stat().st_mode&0o777,0o700)
        self.assertEqual((p/'observation.json').stat().st_mode&0o777,0o600)
        self.assertEqual(b6.persist(x,root=self.parent),p)

    def test_24_private_tamper_rejected(self):
        x=b6.assemble(head=HEAD,records=[sample()],session=SESSION)
        p=b6.persist(x,root=self.parent)
        (p/'observation.json').write_text('broken')
        with self.assertRaises(b6.Stop):b6.verify_persisted(p)
        with self.assertRaises(b6.Stop):b6.persist(x,root=self.parent)

    def test_25_private_extra_file_rejected(self):
        x=b6.assemble(head=HEAD,records=[sample()],session=SESSION)
        p=b6.persist(x,root=self.parent)
        (p/'rogue').write_text('x')
        with self.assertRaises(b6.Stop):b6.verify_persisted(p)

    def test_26_source_symlink_rejected(self):
        x=b6.assemble(head=HEAD,records=[sample()],session=SESSION)
        p=b6.persist(x,root=self.parent)
        source=p/'observation.json'
        source.unlink();source.symlink_to('/etc/passwd')
        with self.assertRaises(b6.Stop):b6.verify_persisted(p)

    def test_27_watch_two_samples(self):
        snapshots=iter([sample(1),sample(2,timer_state='inactive')])
        t=iter([0,1_000_000_000,2_000_000_000])
        report=b6.watch(head=HEAD,session=SESSION,sample=lambda:next(snapshots),
                        monotonic=lambda:next(t),sleep=lambda _:None)
        self.assertTrue(report['session_timer_seen_inactive_after_active'])
        self.assertFalse(report['physical_crash_injected_by_observer'])

    def test_28_watch_not_armed_rejected(self):
        with self.assertRaisesRegex(b6.Stop,'EXTERNAL_SESSION_NOT_ARMED'):
            b6.watch(head=HEAD,session=SESSION,
                     sample=lambda:sample(running=(),session=None))

    def test_29_watch_no_recovery_candidate(self):
        snapshots=iter([sample(1),sample(2),sample(3)])
        t=iter([0,0,2_000_000_000,4_000_000_000])
        x=b6.watch(head=HEAD,session=SESSION,sample=lambda:next(snapshots),
                   monotonic=lambda:next(t),sleep=lambda _:None,max_seconds=1)
        self.assertFalse(x['session_timer_seen_inactive_after_active'])

    def test_30_watch_bounds_rejected(self):
        with self.assertRaisesRegex(b6.Stop,'WATCH_BOUNDS_INVALID'):
            b6.watch(head=HEAD,session=SESSION,sample=lambda:sample(),max_seconds=90)

    def test_31_current_sample_reads_session(self):
        f=Fake(('ssh','runner','ftp'),SESSION)
        report=r124.inspect(head=HEAD,now=NOW,run=f)
        record=b6.current_sample(head=HEAD,reader=lambda **kw:report,
             marker_reader=lambda cmd:(0,r124.canonical({'session':SESSION,
                   'arm_attempted':True,'ordinary_p8':'NO-GO'})),
             clock=iter([1_000_000_000,1_100_000_000]).__next__,boot_reader=lambda:BOOT)
        self.assertEqual(record['marker_session'],SESSION)

    def test_32_current_sample_root_read_failure(self):
        report=r124.inspect(head=HEAD,now=NOW,run=Fake(('ssh','runner','ftp'),SESSION))
        with self.assertRaisesRegex(b6.Stop,'ROOT_MARKER_READ_FAILED'):
            b6.current_sample(head=HEAD,reader=lambda **kw:report,
             marker_reader=lambda cmd:(1,b''),boot_reader=lambda:BOOT)

    def test_33_current_sample_boot_changed(self):
        boot=iter([BOOT,'ffffffff-bbbb-4ccc-8ddd-eeeeeeeeeeee'])
        with self.assertRaisesRegex(b6.Stop,'BOOT_CHANGED_DURING_READBACK'):
            b6.current_sample(head=HEAD,reader=lambda **kw:r124.inspect(head=HEAD,now=NOW,run=Fake()),
             boot_reader=lambda:next(boot))

    def test_34_no_live_host_calls_in_offline_test(self):
        with patch('subprocess.run',side_effect=AssertionError('HOST_CALL')):
            b6.assemble(head=HEAD,records=[sample()],session=SESSION)

    def test_35_capabilities_false_physical(self):
        c=b6.capabilities()
        self.assertFalse(c['physical_60s_accepted'])
        self.assertTrue(c['requires_independent_crash_and_root_signature'])

    def test_36_wrong_session_code(self):
        with self.assertRaisesRegex(b6.Stop,'SESSION_INVALID'):
            b6.assemble(head=HEAD,records=[sample()],session='../../etc')

    def test_37_empty_samples(self):
        with self.assertRaisesRegex(b6.Stop,'SAMPLE_COUNT_INVALID'):
            b6.assemble(head=HEAD,records=[],session=SESSION)

    def test_38_too_many_samples(self):
        with self.assertRaisesRegex(b6.Stop,'SAMPLE_COUNT_INVALID'):
            b6.assemble(head=HEAD,records=[sample()]*91,session=SESSION)


    def test_47_default_root_is_private_dedicated_and_autocreated(self):
        report=b6.assemble(head=HEAD,records=[sample(session=None,running=())],session=None)
        sub=self.parent/'root-private'
        with patch.object(b6,'HOME',self.parent),patch.object(b6,'ROOT',sub):
            folder=b6.persist(report)
            self.assertEqual(folder.parent,sub)
            self.assertEqual(sub.stat().st_mode & 0o777,0o700)
            self.assertEqual(b6.verify_persisted(folder),report)
            self.assertEqual(b6.persist(report),folder)

    def test_48_default_parent_writable_group_refused(self):
        report=b6.assemble(head=HEAD,records=[sample(session=None,running=())],session=None)
        sub=self.parent/'root-private'
        self.parent.chmod(0o770)
        self.addCleanup(lambda:self.parent.chmod(0o700))
        with patch.object(b6,'HOME',self.parent),patch.object(b6,'ROOT',sub):
            with self.assertRaisesRegex(b6.Stop,'PRIVATE_PARENT_UNTRUSTED'):
                b6.persist(report)
            self.assertFalse(sub.exists())

    def test_49_default_root_preexisting_public_mode_refused(self):
        report=b6.assemble(head=HEAD,records=[sample(session=None,running=())],session=None)
        sub=self.parent/'root-private';sub.mkdir(mode=0o755)
        sub.chmod(0o755)
        self.assertEqual(sub.stat().st_mode & 0o777, 0o755)
        with patch.object(b6,'HOME',self.parent),patch.object(b6,'ROOT',sub):
            with self.assertRaisesRegex(b6.Stop,'REVIEW_ROOT_NOT_0700'):
                b6.persist(report)

    def test_50_default_root_symlink_refused(self):
        report=b6.assemble(head=HEAD,records=[sample(session=None,running=())],session=None)
        actual=self.parent/'actual';actual.mkdir(mode=0o700)
        sub=self.parent/'root-private';sub.symlink_to(actual)
        with patch.object(b6,'HOME',self.parent),patch.object(b6,'ROOT',sub):
            with self.assertRaisesRegex(b6.Stop,'REVIEW_PATH_INVALID'):
                b6.persist(report)

    def test_51_explicit_root_requires_existing_folder(self):
        report=b6.assemble(head=HEAD,records=[sample(session=None,running=())],session=None)
        with self.assertRaisesRegex(b6.Stop,'REVIEW_PATH_INVALID'):
            b6.persist(report,root=self.parent/'not-created')

    def test_52_explicit_root_requires_0700(self):
        report=b6.assemble(head=HEAD,records=[sample(session=None,running=())],session=None)
        folder=self.parent/'manual';folder.mkdir(mode=0o755)
        folder.chmod(0o755)
        self.assertEqual(folder.stat().st_mode & 0o777, 0o755)
        with self.assertRaisesRegex(b6.Stop,'REVIEW_ROOT_NOT_0700'):
            b6.persist(report,root=folder)

    def test_53_default_root_path_is_not_patch_archive(self):
        self.assertNotIn('ardrec-patches',str(b6.ROOT))
        self.assertEqual(b6.ROOT.parent,b6.HOME)

if __name__=='__main__':unittest.main()

# Integration: observer -> bounded F13 one-shot -> R128 -> R129/A10.
# A real independent physical witness is still absent; every output stays ND.
from ardrec.coordination import r115_f13_ftp_a5_journal as f13
from ardrec.coordination import r115_f12_ftp_budget_preflight as f12
from ardrec.coordination import r121_ftp_case_chain as r121
from ardrec.coordination import r128_ftp_pilot as r128
from ardrec.coordination import r129_a6_a10_recovery as r129

@unittest.skipIf(os.geteuid()==0,'non-root filesystem authority required')
class TestR128R129BoundB6(unittest.TestCase):
    def setUp(self):
        from test_p14_r126_r129_integrated import Integration, CAT
        self.catalog=CAT
        self.h=Integration('test_01_handoff_schema')
        self.h.setUp()
        self.addCleanup(self.h.doCleanups)
        self.h.intent=f13.make_intent(case_id='FTP-T01-S01-01',session_id=SESSION,
            assessment_index=1,attempt_id='ATT_R127_B6_01',head=HEAD,
            contract_sha256='b'*64,scope_authorization_sha256='c'*64,
            p8_window_sha256='d'*64)
        self.h.preparation=r128.prepare(handoff=self.h.handoff,intent=self.h.intent,
                                        profile=f12.DRAFT_BUDGET)
        self.folder=self.h.journal()
        self.observation=b6.assemble(head=HEAD,
                records=[sample(1),sample(2,timer_state='inactive')],session=SESSION)
        self.observer_folder=b6.persist(self.observation,root=self.h.root)

    def intake(self, folder=None):
        return r128.reconcile(preparation=self.h.preparation,
             journal=self.folder,catalog_raw=self.catalog,
             observer_folder=self.observer_folder if folder is None else folder)

    def test_39_r128_attaches_observer_candidate(self):
        item=self.intake()
        self.assertEqual(item['r127_observation_sha256'],self.observation['sha256'])
        self.assertEqual(item['a6'],'ND')
        self.assertFalse(item['autonomous_root_deny_recovered'])
        self.assertFalse(item['r127_observation_is_root_authority'])

    def test_40_r129_keeps_nd_and_observer_reference(self):
        intake=self.intake()
        case=r121.build(self.folder,self.catalog,self.h.unit)
        report=r129.reconcile(intake=intake,case=case,catalog_raw=self.catalog)
        self.assertEqual(report['r127_observation_candidate_sha256'],self.observation['sha256'])
        self.assertIsNone(report['a9_global_generation'])
        self.assertIsNone(report['a7_confirmed_rf'])

    def test_41_r129_durable_a10_has_observation(self):
        intake=self.intake()
        case=r121.build(self.folder,self.catalog,self.h.unit)
        report=r129.reconcile(intake=intake,case=case,catalog_raw=self.catalog)
        folder=r129.store_private(report,intake=intake,case=case,catalog_raw=self.catalog,
               root=self.h.root/'a10',observer_report=self.observation)
        self.assertEqual(r129.verify_private(folder,self.catalog),report)
        self.assertTrue((folder/'observer.json').is_file())

    def test_42_a10_refuses_observer_missing(self):
        intake=self.intake();case=r121.build(self.folder,self.catalog,self.h.unit)
        report=r129.reconcile(intake=intake,case=case,catalog_raw=self.catalog)
        with self.assertRaisesRegex(r129.Stop,'OBSERVER_NOT_REPLAYABLE'):
            r129.store_private(report,intake=intake,case=case,catalog_raw=self.catalog,
                               root=self.h.root/'a10')

    def test_43_wrong_intent_session_refused(self):
        bad=copy.deepcopy(self.observation)
        bad['session']='ffffffffffffffff';bad['sha256']=b6.sha({k:v for k,v in bad.items() if k!='sha256'})
        # Folder integrity cannot be bypassed by only changing the final hash.
        with self.assertRaises(b6.Stop):b6.verify(bad)

    def test_44_r128_detects_observer_tamper(self):
        (self.observer_folder/'observation.json').write_bytes(b'{}\n')
        with self.assertRaisesRegex(r128.Stop,'OBSERVER_NOT_REPLAYABLE'):
            self.intake()

    def test_45_a10_detects_tampered_observer_archive(self):
        intake=self.intake();case=r121.build(self.folder,self.catalog,self.h.unit)
        report=r129.reconcile(intake=intake,case=case,catalog_raw=self.catalog)
        folder=r129.store_private(report,intake=intake,case=case,catalog_raw=self.catalog,
               root=self.h.root/'a10',observer_report=self.observation)
        (folder/'observer.json').write_bytes(b'{}\n')
        with self.assertRaises((r129.Stop,b6.Stop)):
            r129.verify_private(folder,self.catalog)

    def test_46_a10_rejects_unrequested_observer(self):
        intake=r128.reconcile(preparation=self.h.preparation,journal=self.folder,
                              catalog_raw=self.catalog)
        case=r121.build(self.folder,self.catalog,self.h.unit)
        report=r129.reconcile(intake=intake,case=case,catalog_raw=self.catalog)
        with self.assertRaisesRegex(r129.Stop,'UNREQUESTED_R127_OBSERVER'):
            r129.store_private(report,intake=intake,case=case,catalog_raw=self.catalog,
                               root=self.h.root/'a10',observer_report=self.observation)
