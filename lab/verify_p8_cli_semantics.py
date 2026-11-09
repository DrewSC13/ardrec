#!/usr/bin/env python3
"""P8-R12: bounded manpage excerpt analysis; strictly non-operational.

Default: versioned source-only validation (safe in CI). Optional --probe: match
private operator report SHA and each bounded excerpt hash without printing it.
No subprocess, network, execution, sudo, guest access, command rendering or writes.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

import verify_p8_cli_sources as r11

ROOT=Path(__file__).resolve().parents[1]
BASE='82ed763b809f0ae0bc94c8dbfa5bc9fb1fd300f4'
SOURCE='lab/p8-cli-semantics-v1/semantics.json'
R11='lab/p8-cli-source-v1/evidence.json'
R10='lab/p8-profile-contract-v1/contracts.json'
PROBE_SHA='976d239af18d3a8abc51fbe74828cb27267f44918c1c27f280b3021627658559'
R11_SHA='6ce04b5faaf9e1847627d4552a6909d57f15c00f8bd35478118ab914eca01e86'
R10_SHA='f09e92f395928a52e3c826a11aeef8ed13acb07299b322d173cc03fcf55b4f41'
IMAGE_SHA=r11.IMAGE_SHA
SOURCE_SHA='9701bc65e9e62f18389da021c5ac9c1a7e930e30152403a87d81b094cf0dfab0'
CATEGORIES=frozenset({'DIRECT_DEFINITION_FRAGMENT','MENTION_OR_INCOMPLETE','AMBIGUOUS_SHORT_TOKEN'})
DISPOSITIONS=frozenset({'EXCLUDE_FREEFORM_OR_DOWNGRADE','WRITE_NEEDS_SEPARATE_CLEANUP',
                         'PRIVATE_MATERIAL_UNRESOLVED','NEEDS_COMPLETE_MANUAL','BOUNDED_FUTURE_CANDIDATE'})
COUNT_BY_CATEGORY={'DIRECT_DEFINITION_FRAGMENT':74,'MENTION_OR_INCOMPLETE':15,'AMBIGUOUS_SHORT_TOKEN':2}
DOC_FIELDS={'schema_version','roadmap_step','increment','base_commit','kind','probe_report_sha256',
 'r11_evidence_sha256','r10_contracts_sha256','image_sha256','manual_count','lexical_term_count',
 'snippet_class_totals','term_reviews','profile_count','profiles','complete_manual_semantic_reviews',
 'approved_cli_grammars','approved_cli_options','verified_tool_capabilities','authorized_cases',
 'authorized_profiles','dispatch_allowed','algorithms_started','physical_laboratory_contact',
 'guest_binaries_executed'}
TERM_FIELDS={'id','manual_path','term','lexical_matches','review_class','design_disposition',
 'evidence_anchors','bounded_excerpt_interpretation_es','complete_manual_semantics_verified',
 'cli_flag_approved','runtime_capability_verified'}
ANCHOR_FIELDS={'line_1based','context_sha256'}
PROFILE_FIELDS={'profile_id','semantic_operation_id','source_term_ids','cli_grammar','rendered_argv',
 'remote_command_ast','smb_command_ast','credential_ref','private_case_authorization',
 'approved_target_ref','budget_ref','capture_ref','cleanup_receipt_ref','effective_cli_option_tokens',
 'source_semantics_complete','profile_capability_verified','dispatch_allowed','status'}
SHA_RE=re.compile(r'^[a-f0-9]{64}$')

class R12Error(ValueError): pass

def need(condition,why):
    if not condition: raise R12Error('P8-R12_FAIL_CLOSED:'+why)

def exact(value,fields,why):
    need(type(value) is dict and set(value)==fields,'fields:'+why)

def sha(raw): return hashlib.sha256(raw).hexdigest()

def no_duplicate_pairs(pairs):
    out={}
    for k,v in pairs:
        need(k not in out,'duplicate_json_key')
        out[k]=v
    return out

def parse(raw):
    need(type(raw) is bytes and len(raw)<=1024*1024,'json_size')
    try:
        return json.loads(raw.decode('utf-8'),object_pairs_hook=no_duplicate_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(R12Error('nonfinite_number')))
    except (UnicodeError,json.JSONDecodeError,RecursionError) as e:
        raise R12Error('invalid_json') from e

def read_file(root,relative,digest=None):
    need(type(relative) is str and not relative.startswith('/') and '\\' not in relative and
         all(part not in ('','.','..') for part in relative.split('/')),'path')
    root=Path(root)
    p=root
    for part in relative.split('/'):
        p=p/part
        need(not p.is_symlink(),'symlink_path')
    need(p.is_file(),'missing_source:'+relative)
    raw=p.read_bytes()
    if digest is not None: need(sha(raw)==digest,'pinned_source_changed:'+relative)
    return parse(raw)

def validate(record,previous,contracts):
    exact(record,DOC_FIELDS,'root')
    need(record['schema_version']=='1.0' and type(record['roadmap_step']) is int and
         record['roadmap_step']==8 and record['increment']=='P8-R12' and
         record['base_commit']==BASE and record['probe_report_sha256']==PROBE_SHA and
         record['r11_evidence_sha256']==R11_SHA and record['r10_contracts_sha256']==R10_SHA and
         record['image_sha256']==IMAGE_SHA and
         record['kind']=='BOUNDED_EXCERPT_ANALYST_NOTES_NOT_FULL_MANUAL_ATTESTATION',
         'identity_drift')
    for name,count in [('manual_count',7),('lexical_term_count',91),('profile_count',29),
                       ('complete_manual_semantic_reviews',0),('approved_cli_grammars',0),
                       ('approved_cli_options',0),('verified_tool_capabilities',0),
                       ('authorized_cases',0),('authorized_profiles',0)]:
        need(type(record[name]) is int and record[name]==count,'bad_counter:'+name)
    need(record['dispatch_allowed'] is False and record['algorithms_started'] is False and
         record['guest_binaries_executed'] is False and
         record['physical_laboratory_contact']=='NONE','operational_claim')
    need(record['snippet_class_totals']==COUNT_BY_CATEGORY and
         type(record['term_reviews']) is list and len(record['term_reviews'])==91,'category_drift')
    need(type(previous) is dict and type(contracts) is dict and
         len(previous['manual_sources'])==7 and len(previous['profile_documentation_candidates'])==29 and
         len(contracts['profiles'])==29,'prior_sources_invalid')
    by_path={x['absolute_path']:x for x in previous['manual_sources']}
    need(len(by_path)==7,'manual_sources_duplicates')
    classes={k:0 for k in CATEGORIES}; ids=set(); available={}
    for row in record['term_reviews']:
        exact(row,TERM_FIELDS,'term')
        term_id=row['id'];term=row['term'];path=row['manual_path']
        need(type(term_id) is str and type(term) is str and type(path) is str and
             term_id==Path(path).name+':'+term and term_id not in ids,'term_id')
        ids.add(term_id);available[term_id]=path
        need(path in by_path,'unknown_document')
        need(row['review_class'] in CATEGORIES and row['design_disposition'] in DISPOSITIONS,
             'bad_review_class')
        classes[row['review_class']]+=1
        need(type(row['lexical_matches']) is int and row['lexical_matches']>0,
             'lexical_count')
        need(type(row['bounded_excerpt_interpretation_es']) is str and
             14<=len(row['bounded_excerpt_interpretation_es'])<=500,
             'missing_analyst_note')
        need(type(row['evidence_anchors']) is list and
             1<=len(row['evidence_anchors'])<=2,'anchors')
        for anchor in row['evidence_anchors']:
            exact(anchor,ANCHOR_FIELDS,'anchor')
            need(type(anchor['line_1based']) is int and anchor['line_1based']>0 and
                 type(anchor['context_sha256']) is str and SHA_RE.fullmatch(anchor['context_sha256']),
                 'bad_anchor')
        for field in ('complete_manual_semantics_verified','cli_flag_approved','runtime_capability_verified'):
            need(row[field] is False,'false_capability:'+term_id)
    need(classes==COUNT_BY_CATEGORY,'wrong_review_counts')
    need(type(record['profiles']) is list and len(record['profiles'])==29,'profiles')
    for row,old,prev in zip(record['profiles'],contracts['profiles'],previous['profile_documentation_candidates']):
        exact(row,PROFILE_FIELDS,'profile')
        pid=old['profile_id']
        need(row['profile_id']==pid==prev['profile_id'] and
             row['semantic_operation_id']==old['semantic_operation_id']==prev['operation_id'],
             'profile_identity')
        terms=row['source_term_ids']
        need(type(terms) is list and len(terms)>=2 and len(terms)==len(set(terms)) and
             all(type(t) is str and t in ids and available[t] in prev['documentation_candidates']
                 for t in terms), 'unauthorized_doc_mapping:'+pid)
        for f in ('cli_grammar','rendered_argv','remote_command_ast','smb_command_ast',
                  'credential_ref','private_case_authorization','approved_target_ref',
                  'budget_ref','capture_ref','cleanup_receipt_ref'):
            need(row[f] is None,'materialized_artifact:'+pid+':'+f)
        need(row['effective_cli_option_tokens']==[] and type(row['effective_cli_option_tokens']) is list,
             'options_materialized:'+pid)
        for f in ('source_semantics_complete','profile_capability_verified','dispatch_allowed'):
            need(row[f] is False,'profile_authority:'+pid)
        need(row['status']=='BLOCKED_SEMANTIC_EXCERPTS_ONLY_NO_EXECUTION' and
             old['contract_status']=='BLOCKED_UNBOUND_NO_EXECUTION' and
             prev['dispatch_allowed'] is False,'profile_status:'+pid)
    return {'status':'PASS_P8_R12_91_EXCERPT_NOTES_29_PROFILES_DENY_ALL',
            'manuals':7,'terms':91,'snippet_classes':classes,'profiles':29,
            'complete_manual_reviews':0,'approved_cli_options':0,'authorized_profiles':0,
            'approved_cases':0,'dispatch_allowed':False,'guest_executables_run':False}

def validate_private_probe(probe,record):
    need(type(probe) is dict and probe.get('repo_base')==BASE and
         probe.get('image_sha256')==IMAGE_SHA and
         probe.get('effective_cli_grammars')==0 and probe.get('authorized_profiles')==0 and
         probe.get('dispatch_allowed') is False and
         type(probe.get('manuals')) is list and len(probe['manuals'])==7,
         'private_probe_identity')
    expected=record['term_reviews'];index=0
    for manual in probe['manuals']:
        need(type(manual) is dict and type(manual.get('lexical_candidates')) is list,
             'invalid_probe_manual')
        for row in manual['lexical_candidates']:
            need(index<len(expected),'extra_probe_term')
            original=expected[index]
            need(manual['manual_path']==original['manual_path'] and
                 row['term']==original['term'] and
                 row['lexical_matches']==original['lexical_matches'],
                 'probe_term_drift')
            anchors=row['contexts']
            need(type(anchors) is list and len(anchors)==len(original['evidence_anchors']),
                 'probe_anchor_count')
            for source,ref in zip(anchors,original['evidence_anchors']):
                need(source['source_line_1based']==ref['line_1based'] and
                     sha(source['context'].encode('utf-8'))==ref['context_sha256'],
                     'probe_excerpt_changed')
            index+=1
    need(index==91,'missing_probe_terms')
    return {'private_probe':'MATCH_91_TERMS_0_AUTHORIZATION',
            'report_sha256':PROBE_SHA,'raw_contexts_published':False}

def verify_repository(root=ROOT,probe_path=None):
    root=Path(root)
    if root==ROOT:
        r11.verify_repository()
    report=read_file(root,SOURCE,SOURCE_SHA)
    previous=read_file(root,R11,R11_SHA)
    contracts=read_file(root,R10,R10_SHA)
    result=validate(report,previous,contracts)
    if probe_path is not None:
        p=Path(probe_path)
        need(p.is_file() and not p.is_symlink(),'missing_private_probe')
        raw=p.read_bytes()
        need(sha(raw)==PROBE_SHA,'private_probe_sha_mismatch')
        result.update(validate_private_probe(parse(raw),report))
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe',type=Path,default=None)
    args=parser.parse_args()
    try: print(json.dumps(verify_repository(probe_path=args.probe),sort_keys=True,ensure_ascii=False))
    except (R12Error,r11.EvidenceError,r11.r10.ContractError,
            r11.r10.r9.InventoryError,OSError,KeyError,TypeError) as err:
        print('ARDREC_P8_R12=FAIL_CLOSED:'+str(err),file=sys.stderr)
        return 1
    return 0

if __name__=='__main__': raise SystemExit(main())
