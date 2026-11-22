"""R127-B6: bounded live observation of an externally authorised DENY rollback.

Only root readbacks via R124 and local private evidence. Never arms a timer,
boots a VM, opens sockets, changes nftables, kills a process, signs witnesses,
or asserts that a systemd timer physically restored firewall state.
"""
from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import re
import stat
import time
from typing import Callable, Any

from ardrec.coordination import r115_dev_admission_contract as f1
from ardrec.coordination import r124_root_deny_readback as r124
from ardrec.coordination import r125_integrated_acceptance as r125

SCHEMA = 'ARDREC-R127-B6-BOUNDED-CRASH-OBSERVER-v1'
SESSION = re.compile(r'[0-9a-f]{16}\Z')
MAX_WATCH_NS = 75_000_000_000
MAX_SAMPLES = 90
MAX_FILE = 1_048_576
HOME = Path('/home/cicada')
ROOT = HOME / '.ardrec-r127-b6-observations-v1'

class Stop(ValueError):
    """Stable, fail-closed telemetry refusal."""


def need(ok: bool, code: str) -> None:
    if not ok:
        raise Stop(code)


def sha(value: dict) -> str:
    return f1.digest(f1.canonical(value))


def boot_id_live() -> str:
    value = Path('/proc/sys/kernel/random/boot_id').read_text(encoding='ascii').strip()
    need(re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',value) is not None,
         'BOOT_ID_INVALID')
    return value


def validate_sample(*, head: str, data: dict, session: str | None = None) -> dict:
    """Recompute the R124 readback, not just an untrusted field or hash."""
    need(type(data) is dict and set(data)=={'started_ns','finished_ns','boot_id',
         'readback','marker_session'}, 'SAMPLE_FIELDS')
    a,b=data['started_ns'],data['finished_ns']
    need(type(a) is int and type(b) is int and 0<=a<=b<2**63 and b-a <= 20_000_000_000,
         'SAMPLE_MONOTONIC_INVALID')
    boot=data['boot_id']
    need(type(boot) is str and re.fullmatch(
         r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',boot) is not None,
         'SAMPLE_BOOT_ID_INVALID')
    report=data['readback']
    try:
        r125.root_check(report,head=head)
    except (r125.Stop,ValueError,TypeError,KeyError) as exc:
        raise Stop('R124_ROOT_READBACK_UNVERIFIED') from exc
    marker=data['marker_session']
    need((marker is None and report['session_marker_consumed'] is False) or
         (type(marker) is str and SESSION.fullmatch(marker) is not None and
          report['session_marker_consumed'] is True), 'MARKER_AND_READBACK_DISAGREE')
    need(session is None or marker in (None,session), 'ANOTHER_SESSION_CONSUMED')
    timer=report['session_timer_state']
    need(timer is None if marker is None else timer in ('active','inactive','failed'),
         'SESSION_TIMER_INVALID')
    need(report['r34_is_session_45s_watchdog'] is False and
         report['root_60s_deadline_verified'] is False and
         report['session_autonomous_closure_verified'] is False,
         'R124_FALSE_PHYSICAL_CLAIM')
    return {'stage':report['host']['stage'], 'timer':timer,
            'marker_session':marker, 'readback_sha256':report['sha256'],
            'boot_id':boot,'started_ns':a,'finished_ns':b}


def assemble(*, head: str, records: list[dict], session: str | None) -> dict:
    """Chain immutable offline-verifiable observations; not a root testimony."""
    need(type(head) is str and r124.GIT.fullmatch(head) is not None,'HEAD_INVALID')
    need(session is None or (type(session) is str and SESSION.fullmatch(session) is not None),
         'SESSION_INVALID')
    need(type(records) is list and 1<=len(records)<=MAX_SAMPLES,'SAMPLE_COUNT_INVALID')
    boot=None
    prev=None
    armed_seen=False
    expiry_seen=False
    first_armed=None
    chain=[]
    for i,item in enumerate(records):
        state=validate_sample(head=head,data=item,session=session)
        if boot is None:boot=state['boot_id']
        need(boot==state['boot_id'],'BOOT_CHANGED_DURING_MONITOR')
        need(prev is None or item['started_ns']>=records[i-1]['finished_ns'],
             'SAMPLE_MONOTONIC_ORDER')
        if state['timer']=='active':
            need(not expiry_seen,'SESSION_TIMER_REARMED_OR_CHANGED')
            need(session is not None and state['marker_session']==session,
                 'ACTIVE_TIMER_WRONG_SESSION')
            need(state['stage']=='FIVE_ONE_DENY_MATCH','TIMER_ACTIVE_OUTSIDE_FIVE_ONE')
            armed_seen=True
            if first_armed is None:first_armed=item['started_ns']
        if armed_seen:
            need(state['marker_session']==session,'SESSION_MARKER_REMOVED')
            if state['timer']!='active':
                expiry_seen=True
                need(state['stage'] in ('FIVE_ONE_DENY_MATCH','OFFLINE_DENY_MATCH'),
                     'POST_TIMER_DENY_STAGE_INVALID')
        line={'ordinal':i+1,'start_ns':item['started_ns'],
              'end_ns':item['finished_ns'],'readback_sha256':state['readback_sha256'],
              'stage':state['stage'],'session_timer':state['timer'],
              'previous_sha256':prev}
        line['sha256']=sha(line)
        chain.append(line)
        prev=line['sha256']
    need(session is None or armed_seen, 'SESSION_TIMER_NEVER_OBSERVED_ACTIVE')
    span=records[-1]['finished_ns']-records[0]['started_ns']
    need(span<=MAX_WATCH_NS+20_000_000_000,'OBSERVATION_WINDOW_TOO_LONG')
    elapsed=None if first_armed is None else records[-1]['finished_ns']-first_armed
    out={'schema':SCHEMA,'head':head,'session':session,'boot_id':boot,
         'samples':records,'sample_chain':chain,'chain_head_sha256':prev,
         'sample_count':len(records),'session_timer_seen_active':armed_seen,
         'session_timer_seen_inactive_after_active':expiry_seen,
         'elapsed_ns_from_first_observation':elapsed,
         'status':'TIMER_ENDED_DENY_OBSERVED_NOT_INDEPENDENT_PROOF' if expiry_seen else
                  'OBSERVATION_ONLY_NO_SESSION' if session is None else
                  'SESSION_TIMER_STILL_ACTIVE_NOT_CLOSURE_PROOF',
         'physical_crash_injected_by_observer':False,
         'independent_signed_root_witness':False,
         'verified_physical_60s_restore':False,
         'root_auth_issued':False,'dispatch':False,
         'network_connections':0,'vm_starts':0,'nft_writes':0,
         'p8':'NO-GO','a6':'ND','a9':None}
    need(len(f1.canonical(out))<MAX_FILE,'OBSERVATION_TOO_LARGE')
    out['sha256']=sha(out)
    return out


def verify(report: dict) -> bool:
    need(type(report) is dict and type(report.get('head')) is str and
         type(report.get('samples')) is list and
         type(report.get('session')) in (str,type(None)), 'OBSERVATION_FIELDS')
    try:
        expected=assemble(head=report['head'],records=report['samples'],
                          session=report['session'])
    except (Stop,TypeError,KeyError,ValueError) as exc:
        raise Stop('OBSERVATION_SOURCE_REPLAY_REJECTED') from exc
    need(report==expected,'OBSERVATION_TAMPERED')
    return True


def current_sample(*, head: str,
                   clock: Callable[[],int] = time.monotonic_ns,
                   reader: Callable[...,dict] = r124.inspect,
                   boot_reader: Callable[[],str] = boot_id_live,
                   marker_reader: Callable[[tuple[str,...]],tuple[int,bytes]] = r124.fixed_run) -> dict:
    need(type(head) is str and r124.GIT.fullmatch(head) is not None, 'HEAD_INVALID')
    before=clock()
    boot_before=boot_reader()
    snapshot=reader(head=head,now=datetime.now(timezone.utc).replace(microsecond=0))
    marker=None
    if snapshot['session_marker_consumed']:
        rc,raw=marker_reader((r124.SUDO,'-n','--','/usr/bin/cat',r124.MARKER))
        need(rc==0 and type(raw) is bytes,'ROOT_MARKER_READ_FAILED')
        marker=r124.marker_check(raw)
    boot_after=boot_reader()
    after=clock()
    need(boot_before==boot_after,'BOOT_CHANGED_DURING_READBACK')
    sample={'started_ns':before,'finished_ns':after,
            'boot_id':boot_after,'readback':snapshot,
            'marker_session':marker}
    validate_sample(head=head,data=sample)
    return sample


def watch(*, head: str, session: str, sample: Callable[[],dict],
          monotonic: Callable[[],int] = time.monotonic_ns,
          sleep: Callable[[float],Any] = time.sleep,
          max_seconds: int = 70, poll_seconds: int = 1) -> dict:
    """Observe existing timer; never start it, create traffic or kill worker."""
    need(type(session) is str and SESSION.fullmatch(session) is not None,'SESSION_INVALID')
    need(type(max_seconds) is int and 1<=max_seconds<=70 and
         type(poll_seconds) is int and 1<=poll_seconds<=5,
         'WATCH_BOUNDS_INVALID')
    need(callable(sample) and callable(monotonic) and callable(sleep),'WATCH_CALLBACK_INVALID')
    first=sample()
    state=validate_sample(head=head,data=first,session=session)
    need(state['marker_session']==session and state['timer']=='active' and
         state['stage']=='FIVE_ONE_DENY_MATCH','EXTERNAL_SESSION_NOT_ARMED_IN_FIVE_ONE')
    baseline=monotonic()
    observations=[first]
    finished=False
    while (monotonic()-baseline <= max_seconds*1_000_000_000 and
           len(observations)<MAX_SAMPLES):
        sleep(poll_seconds)
        next_sample=sample()
        observations.append(next_sample)
        view=validate_sample(head=head,data=next_sample,session=session)
        if view['timer']!='active':
            finished=True
            break
    dossier=assemble(head=head,records=observations,session=session)
    need(finished == dossier['session_timer_seen_inactive_after_active'],
         'WATCH_MONITOR_STATUS_DRIFT')
    # All successful observations are still UNSIGNED CANDIDATES.
    return dossier


def _private(parent: Path) -> None:
    st=parent.lstat()
    need(stat.S_ISDIR(st.st_mode) and st.st_uid==os.geteuid() and
         not parent.is_symlink() and not(st.st_mode & 0o022),
         'PRIVATE_PARENT_UNTRUSTED')


def _sync(directory: Path) -> None:
    fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:os.fsync(fd)
    finally:os.close(fd)


def persist(report: dict, *, root: Path | None = None) -> Path:
    """Persist in a private, dedicated evidence directory, never patch storage.

    The default location is under the current operator's fixed home. For
    caller-supplied test/audit directories, preserve the existing requirement
    that the location must already exist and be privately owned.
    """
    need(os.geteuid()!=0,'ROOT_SHELL_FORBIDDEN')
    verify(report)
    default_root = root is None
    if default_root:
        root=ROOT
    need(isinstance(root,Path) and root.is_absolute() and
         not root.is_symlink(), 'REVIEW_PATH_INVALID')
    if default_root:
        need(root.parent==HOME, 'DEFAULT_REVIEW_PARENT_MISMATCH')
        _private(HOME)
        if not root.exists():
            try:
                root.mkdir(mode=0o700)
            except FileExistsError:
                pass
            _sync(HOME)
    need(root.is_dir(), 'REVIEW_PATH_INVALID')
    _private(root)
    need(stat.S_IMODE(root.lstat().st_mode)==0o700,
         'REVIEW_ROOT_NOT_0700')
    folder=root/('r127-b6-observation-'+report['sha256'])
    need(not folder.is_symlink(),'REVIEW_DIRECTORY_SYMLINK')
    raw=f1.canonical(report)
    if folder.exists():
        _private(folder)
        need(stat.S_IMODE(folder.stat().st_mode)==0o700 and
             {x.name for x in folder.iterdir()}=={'observation.json'},
             'REVIEW_DIRECTORY_DRIFT')
        path=folder/'observation.json'
        need(not path.is_symlink() and path.is_file() and
             stat.S_IMODE(path.stat().st_mode)==0o600 and
             path.read_bytes()==raw,'REVIEW_OBSERVATION_TAMPERED')
        return folder
    folder.mkdir(mode=0o700)
    fd=os.open(folder/'observation.json',os.O_WRONLY|os.O_CREAT|os.O_EXCL|
               os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(raw);f.flush();os.fsync(f.fileno())
    _sync(folder);_sync(root)
    return folder


def verify_persisted(folder: Path) -> dict:
    need(isinstance(folder,Path) and folder.is_absolute() and
         folder.name.startswith('r127-b6-observation-'),
         'REVIEW_FOLDER_INVALID')
    _private(folder.parent)
    _private(folder)
    need(stat.S_IMODE(folder.stat().st_mode)==0o700 and
         {x.name for x in folder.iterdir()}=={'observation.json'},
         'REVIEW_FOLDER_CONTENTS')
    path=folder/'observation.json'
    st=path.lstat()
    need(stat.S_ISREG(st.st_mode) and st.st_uid==os.geteuid() and
         st.st_nlink==1 and stat.S_IMODE(st.st_mode)==0o600 and
         0<st.st_size<MAX_FILE,'REVIEW_FILE_MODE_OR_SIZE')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        fstat=os.fstat(fd)
        need((fstat.st_dev,fstat.st_ino,fstat.st_size,fstat.st_uid)==
             (st.st_dev,st.st_ino,st.st_size,st.st_uid),
             'REVIEW_FILE_CHANGED')
        raw=os.read(fd,MAX_FILE)
        need(len(raw)==st.st_size,'REVIEW_SHORT_READ')
    finally:os.close(fd)
    try:
        doc=f1.load(raw)
    except (f1.Rejected,ValueError,TypeError) as exc:
        raise Stop('REVIEW_JSON_CORRUPT') from exc
    need(f1.canonical(doc)==raw and
         folder.name=='r127-b6-observation-'+doc.get('sha256',''),
         'REVIEW_CANONICAL_OR_PATH_DRIFT')
    verify(doc)
    return doc


def capabilities() -> dict:
    return {'schema':SCHEMA+'-capabilities',
            'watches_root_installed_r116_via_r124':True,
            'current_boot_and_monotonic_chained':True,
            'timer_expiration_not_proof_of_restore':True,
            'persisted_private_audit_replay':True,
            'raises_if_session_not_arm_current':True,
            'bounded_max_observation_seconds':70,
            'requires_independent_crash_and_root_signature':True,
            'does_not_arm_start_kill_or_open_traffic':True,
            'physical_60s_accepted':False,
            'network_connections':0,'vm_starts':0,'nft_writes':0,
            'p8':'NO-GO','a6':'ND','a9':None}
