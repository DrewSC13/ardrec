"""R117-F3 current-HEAD signed admission; historical R116 boot engine is immutable.

This module is a *gate*, not a privileged boot dispatcher. Reuse R116 pure
physical predicates and current Ed25519 reviewer, never bypass R116 git_guard
through runtime monkeypatching. A separate versioned root release is required
before the first R117 authorized boot.
"""
from __future__ import annotations
from datetime import datetime
from pathlib import Path
import subprocess
from ardrec.coordination import r116_f12_controlled_boot as historical
from ardrec.coordination import r116_f2_current_pilot_gate as pilot
from ardrec.coordination import r115_dev_admission_contract as scope
from ardrec.coordination import r115_f6_signed_scope_and_activation as signer

ACTIVE_BRANCH='feat/p14-r117-piloto-real-a5-a10'
MERGED_R116='fdb6efa0c297ce18b28cddb9494514f51d88bdb4'
REPO=historical.REPO

class Stop(ValueError): pass

def need(ok,code):
    if not ok:raise Stop(code)

def git_guard(*,runner=subprocess.run):
    """Exact R117 branch, merged R116 ancestor, clean signed head (G)."""
    need(Path.cwd().resolve()==REPO,'R117_WRONG_REPOSITORY')
    def query(argv,label):
        return historical.ok(historical._run(argv,runner=runner),label)
    need(query(('git','rev-parse','--show-toplevel'),'GIT_ROOT')==str(REPO),
         'R117_GIT_ROOT_DRIFT')
    need(query(('git','branch','--show-current'),'GIT_BRANCH')==ACTIVE_BRANCH,
         'R117_GIT_BRANCH_DRIFT')
    head=query(('git','rev-parse','HEAD'),'GIT_HEAD')
    need(scope.GIT_SHA.fullmatch(head),'R117_HEAD_INVALID')
    need(historical._run(('git','merge-base','--is-ancestor',MERGED_R116,head),
                         runner=runner)['rc']==0,'R117_MERGE_NOT_ANCESTOR')
    need(query(('git','status','--porcelain=v1','--untracked-files=all'),'GIT_STATUS')=='',
         'R117_WORKTREE_DIRTY')
    need(query(('git','log','-1','--format=%G?'),'GIT_SIGNATURE')=='G',
         'R117_HEAD_NOT_VERIFIED_G')
    for name in ('src/ardrec/coordination/r117_f3_current_git_admission.py',
                 'src/ardrec/coordination/r116_f12_controlled_boot.py',
                 'src/ardrec/coordination/r116_f12_runner_ftp_boot.py'):
        need(historical._run(('git','ls-files','--error-unmatch',name),runner=runner)['rc']==0,
             'R117_UNTRACKED_BOOT_SOURCE')
        need(historical._run(('git','diff','--quiet','HEAD','--',name),runner=runner)['rc']==0,
             'R117_BOOT_SOURCE_CHANGED')
    return head

def signed_scope(contract_raw,authorization_raw,*,now:datetime,runner=subprocess.run):
    """Review independent scope with current head; no boot permit issued."""
    head=git_guard(runner=runner)
    contract=scope.load(contract_raw)
    need(contract['source_commit']==head,'R117_SCOPE_WRONG_HEAD')
    result=pilot.current_scope_review(contract_raw,authorization_raw,
        catalog_raw=signer.CATALOG.read_bytes(),now=now,head=head)
    need(result[0]=='VERDADERO','R117_SCOPE_NOT_SIGNED_CURRENT_'+result[0])
    return result

def role_preflight(capture,role):
    """Reuse R116 pure F5 5/1 transition predicate; no guest start or network."""
    need(role in historical.ORDER,'R117_ROLE_UNKNOWN')
    gate=historical.state_gate(capture,role)
    need(gate['all_deny']=='MATCH' and gate['p8']=='NO-GO','R117_DENY_NOT_PROVEN')
    return gate

def boundary():
    return {'schema':'ARDREC-R117-F3-CURRENT-BOOT-ADMISSION-v1',
            'r116_immutable':True,'r117_signed_head_required':True,
            'boot_dispatcher':'NOT_RELEASED_FOR_R117',
            'root_restage_required':True,
            'independent_authority_required':True,
            'vm_starts':0,'traffic_opened':False,
            'p7':'DRAFT','a6':'ND','p8':'NO-GO'}
