"""Publicación conjunta, integridad histórica e interrupciones reales / joint publication."""
from dataclasses import replace
from fractions import Fraction
import multiprocessing
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch

from ardrec.analytical import ObjectReference, AnalyticalError
from ardrec.analytical_references import ROLES, canonical, ReferenceError
from ardrec.persistence import DurableStore
from ardrec.persistence.analytical_archive import AnalyticalArchive, digest
from ardrec.persistence.codec import StorageError, parse, canonical as storage_canonical
from ardrec.state import ServicePhase, Transition
from test_analytical_references import fixture
from test_persistence import INITIAL, context, reserve, outcome, OBJECT_POINTS, HEAD_POINTS


def snapshot(archive, state, generation, *, edit=None, context_override=None):
    template, manifest, _ = fixture()
    ctx = dict(record_id=state.confirmed.record_id, execution_id=state.execution_id,
               configuration_sha256=state.confirmed.configuration_sha256, generation_index=generation)
    ctx.update(context_override or {})
    projections, bindings, objects = [], [], {}
    for service in sorted(state.services, key=lambda s: s.service_scenario_id):
        sid = service.service_scenario_id
        refs = {}
        for role in ROLES:
            ref = sid + '-' + role
            raw = canonical(dict(format='ardrec-analytical-object-1', context={**ctx, 'generation_index': 0},
                                 service_scenario_id=sid, role=role, reference=ref,
                                 payload={'synthetic': True, 'semantics_not_validated': True}))
            sha = digest(raw); objects[sha] = raw
            refs[role] = ObjectReference(ref, sha)
            bindings.append(dict(service_scenario_id=sid, role=role, reference=ref, sha256=sha))
        p = replace(template, **ctx, service_scenario_id=sid, operational_state=service.phase,
                    frozen=replace(template.frozen, characterization=refs['characterization']),
                    analysis=replace(template.analysis, priority=None if service.phase is ServicePhase.PREPARADO else Fraction(7, 12)),
                    references=tuple(refs[r] for r in ROLES[1:]))
        projections.append(p if edit is None else edit(p))
    manifest.update(context=ctx, bindings=sorted(bindings, key=lambda b:(b['service_scenario_id'], b['role'])))
    raw = canonical(manifest)
    return archive.store(tuple(projections), raw, expected_manifest_sha256=digest(raw), load_object=objects.__getitem__)


def reopen(path, archive=None, **kw):
    return DurableStore.open(path, record_id='REG-1', configuration_sha256='a'*64,
                             analytical_archive=archive, **kw)


def crash_publish(root, point, sha):
    def kill(actual):
        if actual == point:
            os.kill(os.getpid(), signal.SIGKILL)
    with AnalyticalArchive(Path(root)/'archive') as archive, reopen(Path(root)/'store', archive, fault=kill) as store:
        store.publish_analytical(expected_generation=0, reference='GEN-1', event='PUB-1', snapshot_sha256=sha)
    raise RuntimeError('fault point not reached')


class AnalyticalPublicationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root/'store'
        self.archive = AnalyticalArchive(self.root/'archive', create=True)
        self.addCleanup(self.archive.close)

    def create(self, anchored=True):
        sha = snapshot(self.archive, INITIAL, 0) if anchored else None
        self.store = DurableStore.create(self.path, INITIAL, analytical_archive=self.archive, snapshot_sha256=sha)
        self.addCleanup(self.store.close)
        return sha

    def stage(self):
        self.store.transition('S01', Transition.PREPARAR, context(self.store, Transition.PREPARAR))
        return snapshot(self.archive, self.store.state, 1)

    def publish(self, sha, **kw):
        return self.store.publish_analytical(**dict(expected_generation=0, reference='GEN-1', event='PUB-1', snapshot_sha256=sha, **kw))

    def tree(self):
        return {str(p.relative_to(self.path)): p.read_bytes() for p in self.path.rglob('*') if p.is_file()}

    def test_legacy_store_roundtrip_has_no_anchor(self):
        self.create(False)
        before = self.tree(); self.store.close()
        with reopen(self.path) as s:
            self.assertIsNone(s.analytical_snapshot)
            self.assertIsNone(s.analytical_snapshot_sha256)
        self.assertEqual(before, self.tree())

    def test_initial_anchor_roundtrip_and_no_second_head(self):
        sha = self.create(); state = self.store.state; self.store.close()
        with reopen(self.path, self.archive) as s:
            self.assertEqual(s.state, state)
            self.assertEqual(s.analytical_snapshot_sha256, sha)
            self.assertEqual(s.analytical_snapshot.projections[0].generation_index, 0)
        self.assertFalse((self.root/'archive/HEAD').exists())

    def test_initial_invalid_context_creates_no_store(self):
        sha = snapshot(self.archive, INITIAL, 1)
        with self.assertRaises(ReferenceError):
            DurableStore.create(self.path, INITIAL, analytical_archive=self.archive, snapshot_sha256=sha)
        self.assertFalse(self.path.exists())

    def test_publish_binds_exact_snapshot_and_state(self):
        old = self.create(); sha = self.stage()
        self.assertEqual(self.store.analytical_snapshot_sha256, old)
        state = self.publish(sha)
        self.assertEqual(state.confirmed.generation, 1)
        self.assertEqual(self.store.analytical_snapshot_sha256, sha)
        self.assertEqual(self.store.analytical_snapshot.projections[0].operational_state, ServicePhase.PENDIENTE)
        generation = parse((self.path/'generations'/(self.store._head['generation_digest']+'.json')).read_bytes())
        self.assertEqual(generation['analytical_snapshot_sha256'], sha)
        self.store.close()
        with reopen(self.path, self.archive) as s:
            self.assertEqual(s.state, state); self.assertEqual(s.analytical_snapshot_sha256, sha)

    def test_legacy_adoption_preserves_existing_records(self):
        self.create(False); old = self.tree(); sha = self.stage(); self.publish(sha)
        for name, raw in old.items():
            if name != 'HEAD': self.assertEqual((self.path/name).read_bytes(), raw)
        self.store.close()
        with reopen(self.path, self.archive) as s:self.assertEqual(s.analytical_snapshot_sha256, sha)

    def test_legacy_publish_cannot_remove_anchor(self):
        self.create(); self.stage(); before=self.tree()
        with self.assertRaisesRegex(StorageError, 'analytical_anchor_required'):
            self.store.publish(expected_generation=0, reference='GEN-1', event='PUB-1')
        self.assertEqual(before, self.tree())

    def test_wrong_generation_rejected_before_store_write(self):
        old = self.create(); self.stage(); before=self.tree()
        with self.assertRaises(ReferenceError):self.publish(old)
        self.assertEqual(before, self.tree()); self.assertEqual(self.store.state.confirmed.generation, 0)

    def test_wrong_phase_rejected_before_store_write(self):
        self.create(); sha = snapshot(self.archive, INITIAL, 1); self.stage(); before=self.tree()
        with self.assertRaises(ReferenceError):self.publish(sha)
        self.assertEqual(before, self.tree())

    def test_wrong_record_rejected_before_store_write(self):
        self.create(); self.stage()
        sha=snapshot(self.archive,self.store.state,1,context_override={'record_id':'REG-OTHER'});before=self.tree()
        with self.assertRaises(ReferenceError):self.publish(sha)
        self.assertEqual(before,self.tree())

    def test_incomplete_service_set_rejected(self):
        self.create();self.stage()
        state=self.store.state
        other=replace(state,confirmed=replace(state.confirmed,services=state.confirmed.services[:1]),services=state.services[:1])
        sha=snapshot(self.archive,other,1);before=self.tree()
        with self.assertRaises(ReferenceError):self.publish(sha)
        self.assertEqual(before,self.tree())

    def test_frozen_value_change_rejected(self):
        self.create();self.stage()
        sha=snapshot(self.archive,self.store.state,1,edit=lambda p:replace(p,frozen=replace(p.frozen,normalized_criticality=Fraction(1,3))))
        before=self.tree()
        with self.assertRaises(AnalyticalError):self.publish(sha)
        self.assertEqual(before,self.tree())

    def test_invalid_hash_rejected_without_store_writes(self):
        self.create();self.stage();before=self.tree()
        for sha in ('../escape','',True,'A'*64):
            with self.assertRaises(StorageError):self.publish(sha)
        self.assertEqual(before,self.tree())

    def test_missing_snapshot_cannot_publish(self):
        self.create();self.stage();before=self.tree()
        with self.assertRaises(FileNotFoundError):self.publish('0'*64)
        self.assertEqual(before,self.tree())
        with self.assertRaises(StorageError):_ = self.store.state

    def test_open_requires_archive_when_anchor_exists(self):
        self.create();self.store.close();before=self.tree()
        with self.assertRaisesRegex(StorageError,'analytical_archive_required'):reopen(self.path)
        self.assertEqual(before,self.tree())

    def test_wrong_archive_is_not_repaired(self):
        self.create();self.store.close()
        with AnalyticalArchive(self.root/'other',create=True) as empty:
            with self.assertRaises(FileNotFoundError):reopen(self.path,empty)
            self.assertEqual({p.name for p in (self.root/'other').iterdir()},{'LOCK'})

    def test_corrupt_current_object_blocks_read_and_mutation(self):
        sha=self.create(); target=next(p for p in (self.root/'archive'/sha).iterdir() if p.name!=sha+'.json')
        target.chmod(0o600);target.write_bytes(b'{}');before=self.tree()
        with self.assertRaises((StorageError,ReferenceError)):_=self.store.state
        with self.assertRaisesRegex(StorageError,'session_unavailable'):self.store.finish(None,'STOP')
        self.assertEqual(before,self.tree())

    def test_missing_historical_snapshot_blocks_recovery(self):
        old=self.create();sha=self.stage();self.publish(sha);self.store.close()
        (self.root/'archive'/old).rename(self.root/'archive/retained')
        before=self.tree()
        with self.assertRaises(FileNotFoundError):reopen(self.path,self.archive)
        self.assertEqual(before,self.tree())

    def test_unpublished_newer_archive_is_not_promoted(self):
        old=self.create();self.stage();self.store.close()
        with reopen(self.path,self.archive) as s:
            self.assertEqual(s.state.confirmed.generation,0)
            self.assertEqual(s.analytical_snapshot_sha256,old)
            self.assertEqual(s.recovery_action,'PUBLISH_CANDIDATE')

    def test_external_expected_head_detects_complete_rollback(self):
        self.create();previous=(self.path/'HEAD').read_bytes();sha=self.stage();self.publish(sha)
        expected=self.store.head_sha256;self.store.close()
        (self.path/'HEAD').chmod(0o600);(self.path/'HEAD').write_bytes(previous)
        with self.assertRaisesRegex(StorageError,'head_anchor_mismatch'):reopen(self.path,self.archive,expected_head=expected)
        # Without an external checkpoint, restoring the entire valid old head is not detectable.
        with reopen(self.path,self.archive) as s:self.assertEqual(s.state.confirmed.generation,0)

    def test_stale_expected_generation_rejected(self):
        self.create();sha=self.stage();self.publish(sha);before=self.tree()
        with self.assertRaisesRegex(StorageError,'stale_generation'):self.publish(sha)
        self.assertEqual(before,self.tree())

    def test_empty_publication_not_used_to_attach_anchor(self):
        self.create(False);sha=snapshot(self.archive,INITIAL,1);before=self.tree()
        with self.assertRaisesRegex(StorageError,'empty_publication'):self.publish(sha)
        self.assertEqual(before,self.tree())

    def test_result_receipt_and_anchor_share_generation(self):
        self.create();self.publish(self.stage());reserve(self.store);outcome(self.store)
        sha=snapshot(self.archive,self.store.state,2)
        self.store.publish_analytical(expected_generation=1,reference='GEN-2',event='PUB-2',snapshot_sha256=sha)
        state=self.store.state;self.assertEqual(state.attempts[0].incorporation.generation,2)
        self.store.close()
        with reopen(self.path,self.archive) as s:
            self.assertEqual(s.state,state);self.assertEqual(s.analytical_snapshot_sha256,sha)
            self.assertEqual(s.recovery_action,'NONE')

    def test_unknown_anchor_fields_fail_closed(self):
        self.create();sha=self.stage();before=self.tree()
        with self.assertRaises(StorageError):
            self.store._commit('publish_analytical_v1',dict(expected_generation=0,reference='GEN-1',event='PUB-1',snapshot_sha256=sha,extra=True))
        self.assertEqual(before,self.tree())

    def test_sync_failure_after_head_replace_requires_recovery(self):
        self.create();sha=self.stage();original=os.fsync
        def sync(fd):
            if fd==self.store._root:raise OSError('root sync')
            original(fd)
        with patch('ardrec.persistence.os.fsync',side_effect=sync):
            with self.assertRaises(OSError):self.publish(sha)
        with self.assertRaises(StorageError):_=self.store.state
        self.store.close()
        with reopen(self.path,self.archive) as s:
            self.assertEqual(s.state.confirmed.generation,1);self.assertEqual(s.analytical_snapshot_sha256,sha)

    def test_sigkill_at_all_publication_boundaries_preserves_pair(self):
        points=tuple(f'{folder}:{point}' for folder in ('generations','journal') for point in OBJECT_POINTS)+HEAD_POINTS
        self.archive.close()
        for index,point in enumerate(points):
            with self.subTest(point=point):
                root=self.root/str(index);root.mkdir()
                with AnalyticalArchive(root/'archive',create=True) as archive:
                    old=snapshot(archive,INITIAL,0)
                    with DurableStore.create(root/'store',INITIAL,analytical_archive=archive,snapshot_sha256=old) as s:
                        s.transition('S01',Transition.PREPARAR,context(s,Transition.PREPARAR))
                        new=snapshot(archive,s.state,1)
                child=multiprocessing.get_context('fork').Process(target=crash_publish,args=(root,point,new))
                child.start();child.join(15)
                if child.is_alive():child.kill();child.join(5)
                self.assertEqual(child.exitcode,-signal.SIGKILL);child.close()
                committed=point in ('head:replaced','head:durable','commit:acknowledge')
                with AnalyticalArchive(root/'archive') as archive,reopen(root/'store',archive) as s:
                    self.assertEqual(s.state.confirmed.generation,int(committed))
                    self.assertEqual(s.analytical_snapshot_sha256,new if committed else old)
                    self.assertEqual(s.analytical_snapshot.projections[0].generation_index,int(committed))

if __name__=='__main__':unittest.main(verbosity=2)
