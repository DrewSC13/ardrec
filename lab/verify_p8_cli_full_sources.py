#!/usr/bin/env python3
"""P8-R14: source-only full-manpage entry anchors. Never a CLI authorization.

CI validates the pinned public anchor catalogue and R13 chain. Optional --private-full
reconciles every source byte and all 91 canonical entry headers with the private
operator report without printing the full manuals, executing guest binaries,
reading environment secrets, connecting to a service, or modifying any files.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import sys

import verify_p8_cli_grammar as r13

ROOT=Path(__file__).resolve().parents[1]
SOURCE='lab/p8-cli-full-source-v1/anchors.json'
SOURCE_SHA='6b22b5ae82a3af897516a3c7eb5f37c7bff71ad7a6f2d9382de10b2855fccfb4'
R12='lab/p8-cli-semantics-v1/semantics.json'
R12_SHA='9701bc65e9e62f18389da021c5ac9c1a7e930e30152403a87d81b094cf0dfab0'
R13='lab/p8-cli-grammar-v1/spec.json'
R13_SHA='df9fbfae39526a70f96972074357f0e4144bd3d39f7f771d291e95c23999f4e0'
BASE='67c55f1bb2165a1edac25ecaf86e8638ef705548'
FULL_SHA='2968e57fc65554735cef5ad349ec8a159dcc42fae3b0f05a653b2df0b20af365'
IMAGE_SHA='fc9244fe29917f9bbeab09604a5845506dc3ab222b5c53648b5b90b2b1bf2103'
SHA_RE=re.compile(r'^[0-9a-f]{64}$')
ROOT_FIELDS={'schema_version','roadmap_step','increment','base_commit','kind','private_report_sha256',
 'r12_semantics_sha256','r13_symbolic_spec_sha256','image_sha256','manual_count','term_count',
 'profile_count','source_manifests','term_anchors','anchor_class_totals','safety_boundaries',
 'profile_refs','complete_semantic_reviews','approved_cli_options','approved_argv_renderers',
 'approved_cli_grammars','authorized_cases','authorized_profiles','dispatch_allowed',
 'algorithms_started','guest_binaries_executed','physical_laboratory_contact',
 'full_original_manual_text_published'}
MANIFEST_FIELDS={'manual_path','uncompressed_sha256','uncompressed_bytes','compressed_sha256',
                 'compressed_bytes','lexical_candidates'}
ANCHOR_FIELDS={'term_id','manual_path','term','anchor_class','source_line_1based',
              'exact_roff_line_sha256','uncompressed_manual_sha256','annotation_status',
              'option_authorized','caller_supplied_values_approved'}
RISK_FIELDS={'risk_id','term_id','manual_path','evidence_line_1based','evidence_line_sha256',
             'documented_boundary','required_design_guard','guard_verified_operationally',
             'approved_for_execution'}
PROFILE_FIELDS={'profile_id','source_term_ids','symbolic_grammar_only','complete_semantic_review',
                'approved_for_execution'}
EXPECTED_MANUALS={
 '/usr/share/man/man1/ssh.1.gz': ('c19056cc2e6661b282963673bba0ada5b5a4ae30f4d49f91a1d168fef9e25766',48413,'78a8c50b4eecf26228707878018ca314aea3008c87caef6724030fc856e50481',15310,9),
 '/usr/share/man/man5/ssh_config.5.gz': ('10ea0a18bfd6b57d94037c5acd231ef3ab4d112c689039c4af9cbf6dc744a841',73459,'7860149efded4d0d863e3227c78780137ee78ce437cca61aad74bdd425498b37',20952,24),
 '/usr/share/man/man1/ssh-keyscan.1.gz': ('43e1ad81c1f1448bce4339e8d177ad55f290bb79149fc7097396073f57f6309a',4828,'9853bddce174b54203038fc07a8efe432cb52891e456d31eab6ff58984f3dadc',2296,4),
 '/usr/share/man/man1/sftp.1.gz': ('29301db4c4c016483fc4d3c42652f678cc99bcfaec16cbb2490151fc172a15f7',18055,'14866f5f918982483f7bfa5d4c53fcc2662ab0d86db6d7113309fbc5a5dc53e0',6331,4),
 '/usr/share/man/man1/curl.1.gz': ('4ed8ecde3cc54664c458d80a29addf867cac7b261ec51ceafba3fac87be6a7e0',255928,'c890fbab33db8ed67773ffa4d422ed78da17f16d827f6615d94111923d242c16',72618,27),
 '/usr/share/man/man1/smbclient.1.gz': ('902caa2613d93637dd47b112fdb573ae4fdfa4818d31960d3962acbe8d7833a5',47640,'aca2de052bb22fa7fb03451de4f7cd2c235af5a84372e623d9b49863262ef77b',13812,20),
 '/usr/share/man/man1/rpcclient.1.gz': ('4bc2690e466f70ce9d502feac76bcf8c28841feaa616b9baecfb6532ffa054cb',37432,'f264e9e8c4c1eece7688a1d1813974211f4969ec51e3e8a944d4ae40d26ba05a',10872,3),
}
class FullSourceError(ValueError): pass

def need(value,why):
    if not value:raise FullSourceError('P8_R14_FAIL_CLOSED:'+why)

def sha(raw):return hashlib.sha256(raw).hexdigest()

def exact(x,fields,label):need(type(x) is dict and set(x)==fields,'fields:'+label)

def parse(raw):
    need(type(raw) is bytes and 0<len(raw)<=1024*1024,'json_bytes')
    return r13.strict_json(raw)

def safe_read(root,name,expected):
    need(type(name) is str and not name.startswith('/') and '\\' not in name and
         all(part not in ('','.','..') for part in name.split('/')),'path')
    p=Path(root)
    for segment in name.split('/'):
        p=p/segment
        need(not p.is_symlink(),'symlink_source')
    need(p.is_file(),'source_missing:'+name)
    raw=p.read_bytes()
    need(sha(raw)==expected,'source_hash_drift:'+name)
    return parse(raw)

def check_catalog(a,r12,r13_spec):
    exact(a,ROOT_FIELDS,'root')
    need(a['schema_version']=='1.0' and type(a['roadmap_step']) is int and
         a['roadmap_step']==8 and a['increment']=='P8-R14' and a['base_commit']==BASE and
         a['kind']=='FULL_SOURCE_ANCHORED_LOCATION_AND_SAFETY_BOUNDARY_NOT_SEMANTIC_APPROVAL'
         and a['private_report_sha256']==FULL_SHA and
         a['r12_semantics_sha256']==R12_SHA and a['r13_symbolic_spec_sha256']==R13_SHA and
         a['image_sha256']==IMAGE_SHA,'source_identities')
    for k,n in [('manual_count',7),('term_count',91),('profile_count',29),
                ('complete_semantic_reviews',0),('approved_cli_options',0),
                ('approved_argv_renderers',0),('approved_cli_grammars',0),
                ('authorized_cases',0),('authorized_profiles',0)]:
        need(type(a[k]) is int and a[k]==n,'gate:'+k)
    need(a['dispatch_allowed'] is False and a['algorithms_started'] is False and
         a['guest_binaries_executed'] is False and
         a['full_original_manual_text_published'] is False and
         a['physical_laboratory_contact']=='NONE','no_execution')
    need(type(r12) is dict and len(r12.get('term_reviews',[]))==91 and
         type(r13_spec) is dict and len(r13_spec.get('profiles',[]))==29,'prior_contracts')
    manifests=a['source_manifests']
    need(type(manifests) is list and len(manifests)==7,'manifest_count')
    mpaths={}
    for m in manifests:
        exact(m,MANIFEST_FIELDS,'manifest')
        path=m['manual_path'];need(type(path) is str and path not in mpaths and
                                  path in EXPECTED_MANUALS,'manifest_path')
        h,n,ch,cn,c=EXPECTED_MANUALS[path]
        need(m['uncompressed_sha256']==h and type(m['uncompressed_bytes']) is int and
             m['uncompressed_bytes']==n and m['compressed_sha256']==ch and
             type(m['compressed_bytes']) is int and m['compressed_bytes']==cn and
             type(m['lexical_candidates']) is int and m['lexical_candidates']==c,
             'manifest_pin:'+path)
        mpaths[path]=m
    need(set(mpaths)==set(EXPECTED_MANUALS),'missing_manifests')
    termset=set();anchors=a['term_anchors'];need(type(anchors) is list and len(anchors)==91,'term_count')
    for curr,prev in zip(anchors,r12['term_reviews']):
        exact(curr,ANCHOR_FIELDS,'anchor')
        need(curr['term_id']==prev['id'] and curr['manual_path']==prev['manual_path'] and
             curr['term']==prev['term'] and curr['term_id'] not in termset,'term_identity')
        termset.add(curr['term_id'])
        need(curr['manual_path'] in mpaths and curr['uncompressed_manual_sha256']==
             mpaths[curr['manual_path']]['uncompressed_sha256'],'anchor_manual_pin')
        need(curr['anchor_class']=='EXACT_MANPAGE_ENTRY_LOCATED' and
             type(curr['source_line_1based']) is int and curr['source_line_1based']>0 and
             type(curr['exact_roff_line_sha256']) is str and
             SHA_RE.fullmatch(curr['exact_roff_line_sha256']) and
             curr['annotation_status']=='SOURCE_LOCATION_ONLY_SEMANTIC_REVIEW_NOT_COMPLETED' and
             curr['option_authorized'] is False and
             curr['caller_supplied_values_approved'] is False,'anchor_denial')
    need(a['anchor_class_totals']=={'EXACT_MANPAGE_ENTRY_LOCATED':91},'anchor_class')
    refs=a['profile_refs'];need(type(refs) is list and len(refs)==29,'profile_refs')
    for curr,prev in zip(refs,r13_spec['profiles']):
        exact(curr,PROFILE_FIELDS,'profile')
        need(curr['profile_id']==prev['profile_id'] and
             curr['source_term_ids']==prev['source_term_ids'] and
             type(curr['source_term_ids']) is list and
             len(curr['source_term_ids'])==len(set(curr['source_term_ids'])) and
             all(x in termset for x in curr['source_term_ids']) and
             curr['symbolic_grammar_only'] is True and
             curr['complete_semantic_review'] is False and
             curr['approved_for_execution'] is False,'profile_gate')
    risks=a['safety_boundaries'];need(type(risks) is list and len(risks)==25,'risk_count')
    names=set();byid={x['term_id']:x for x in anchors}
    for row in risks:
        exact(row,RISK_FIELDS,'risk')
        need(type(row['risk_id']) is str and row['risk_id'] not in names and
             re.fullmatch('[A-Z0-9_]{5,60}',row['risk_id']) and
             row['term_id'] in byid,'risk_identity')
        names.add(row['risk_id']);anchor=byid[row['term_id']]
        need(row['manual_path']==anchor['manual_path'] and
             row['evidence_line_1based']==anchor['source_line_1based'] and
             row['evidence_line_sha256']==anchor['exact_roff_line_sha256'] and
             type(row['documented_boundary']) is str and
             re.fullmatch('[A-Z0-9_]{8,100}',row['documented_boundary']) and
             type(row['required_design_guard']) is str and
             re.fullmatch('[A-Z0-9_]{8,100}',row['required_design_guard']) and
             row['guard_verified_operationally'] is False and
             row['approved_for_execution'] is False,'risk_authority')
    return {'status':'PASS_P8_R14_91_EXACT_FULL_SOURCE_ENTRY_ANCHORS_25_GUARDS_DENY_ALL',
            'manuals':7,'terms':91,'safety_boundaries':25,'profiles':29,
            'complete_semantic_reviews':0,'approved_cli_options':0,
            'authorized_profiles':0,'dispatch_allowed':False}

def normalized_match(line,term):
    text=line.replace('\\-','-').replace('\\&','')
    return re.search(r'(?<![\w-])'+re.escape(term)+r'(?![\w-])',text) is not None

def matches_entry(name,term,line):
    if name in ('ssh.1.gz','ssh-keyscan.1.gz','sftp.1.gz'):
        return bool(term.startswith('-') and
                    re.match(r'^\.It Fl\s+'+re.escape(term[1:])+r'(?:\s|$)',line))
    if name=='ssh_config.5.gz':
        return bool(re.match(r'^\.It Cm\s+'+re.escape(term)+r'(?:\s|$)',line))
    if name=='curl.1.gz':
        return line.startswith('.IP "') and normalized_match(line,term)
    if name in ('smbclient.1.gz','rpcclient.1.gz'):
        if term.startswith('--'):
            return line.startswith('\\-') and normalized_match(line,term)
        return bool(re.match(r'^'+re.escape(term)+r'(?:\s|$)',line))
    return False

def private_reconcile(raw,a):
    need(sha(raw)==FULL_SHA,'private_report_hash')
    full=parse(raw)
    need(type(full) is dict and full.get('repo_base_commit')==BASE and
         full.get('image_sha256')==IMAGE_SHA and
         full.get('complete_manual_source_captures')==7 and
         full.get('complete_semantic_reviews')==0 and
         full.get('approved_cli_options')==0 and
         full.get('authorized_profiles')==0 and
         full.get('dispatch_allowed') is False and
         full.get('guest_executables_run') is False,'private_report_authority')
    rawpages=full.get('manuals');need(type(rawpages) is list and len(rawpages)==7,'private_manual_count')
    bypath={}
    for row in rawpages:
        need(type(row) is dict and type(row.get('manual_path')) is str and
             row['manual_path'] not in bypath and row['manual_path'] in EXPECTED_MANUALS,
             'private_manual_identity')
        path=row['manual_path'];h,n,ch,cn,c=EXPECTED_MANUALS[path]
        need(row.get('source_encoding')=='base64_of_unmodified_roff_bytes' and
             row.get('uncompressed_sha256')==h and row.get('uncompressed_bytes')==n and
             row.get('compressed_sha256')==ch and row.get('compressed_bytes')==cn and
             row.get('cli_options_authorized')==0 and
             row.get('manual_review_status')=='COMPLETE_SOURCE_CAPTURED_REVIEW_NOT_DONE' and
             type(row.get('lexical_terms_from_r12')) is list and
             len(row['lexical_terms_from_r12'])==c,'private_manual_meta')
        try:rawsource=base64.b64decode(row['full_roff_source_b64'],validate=True)
        except (TypeError,ValueError,base64.binascii.Error) as exc:
            raise FullSourceError('P8_R14_FAIL_CLOSED:invalid_base64') from exc
        need(len(rawsource)==n and sha(rawsource)==h,'private_manual_sha')
        bypath[path]=rawsource
    need(set(bypath)==set(EXPECTED_MANUALS),'private_missing_manual')
    for rec in a['term_anchors']:
        lines=bypath[rec['manual_path']].splitlines(keepends=True)
        offset=rec['source_line_1based']-1
        need(0<=offset<len(lines),'line_bounds')
        line=lines[offset]
        need(sha(line)==rec['exact_roff_line_sha256'],'line_digest')
        need(matches_entry(Path(rec['manual_path']).name,rec['term'],line.decode('utf-8')),
             'not_exact_entry:'+rec['term_id'])
    return {'private_full_report':'MATCH_7_FULL_SOURCES_91_ENTRY_HEADINGS',
            'original_manuals_published':False,'full_report_sha256':FULL_SHA}

def verify_repository(root=ROOT,full_report=None):
    root=Path(root)
    if root==ROOT:r13.verify_repository()
    a=safe_read(root,SOURCE,SOURCE_SHA)
    r12doc=safe_read(root,R12,R12_SHA)
    r13doc=safe_read(root,R13,R13_SHA)
    outcome=check_catalog(a,r12doc,r13doc)
    if full_report is not None:
        p=Path(full_report)
        need(p.is_file() and not p.is_symlink(),'private_report_missing_or_symlink')
        outcome.update(private_reconcile(p.read_bytes(),a))
    return outcome

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--private-full',type=Path,default=None)
    args=parser.parse_args()
    try:print(json.dumps(verify_repository(full_report=args.private_full),sort_keys=True))
    except (FullSourceError,r13.GrammarError,r13.r12.R12Error,
            r13.r12.r11.EvidenceError,r13.r12.r11.r10.ContractError,
            r13.r12.r11.r10.r9.InventoryError,OSError,KeyError,TypeError,ValueError) as e:
        print('ARDREC_P8_R14=FAIL_CLOSED:'+str(e),file=sys.stderr)
        return 1
    return 0
if __name__=='__main__':raise SystemExit(main())
