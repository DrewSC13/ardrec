#!/usr/bin/env python3
"""ARDREC P8-R21: strict offline DSO candidate reconciliation only.

No loader equivalence, argv generation, credentials, clients, runtime execution,
case authority or dispatch. The pure evaluator never accesses the guest image.
"""
from __future__ import annotations
from collections import Counter
import re

import p8_r19_graph as g
import p8_r20_samba_candidate as r20

R21_BASE = '363f5ca7b34419e5a1da270907f9b89c768e6a08'
R20_BASE = '4d0907a982183a33b18eb2decba20fc02f37b822'
R20_SHA = '0e3d4fb71dc8784d551cf2e028fa441e719d2c443baa14af5aebe7d76951f17d'
R19_SHA = '785a85192e42588042467017f4ec65bafed96f4711bb1d42c6f846ede0e1a1cf'
IMAGE_SHA = 'fc9244fe29917f9bbeab09604a5845506dc3ab222b5c53648b5b90b2b1bf2103'

SEARCH_DIRS = tuple(dict.fromkeys((*g.LIB_DIRS, r20.SAMBA_DIR)))
EXPECTED_MISSING = {
    'libdcerpc-binding.so.0': 2,
    'libjansson.so.4': 1,
    'libndr-krb5pac.so.0': 3,
    'libsamdb.so.0': 1,
    'libwbclient.so.0': 1,
}
MAX_NAMES_PER_LAYER = 96
MAX_LAYERS = 12
MAX_NEW_NODES = 60
MAX_NEW_EDGES = 640
SHA_RE = re.compile(r'[0-9a-f]{64}\Z')


def need(condition, reason):
    g.need(condition, 'r21_'+reason)


def candidate_paths(soname):
    soname = g.safe_soname(soname)
    return [g.safe_path(d+'/'+soname) for d in SEARCH_DIRS]


def canonical_guest_path(path):
    g.safe_path(path)
    need(any(path.startswith(d+'/') for d in SEARCH_DIRS), 'canonical_outside_candidate_dirs')
    return path


def assess_multidir_scan(names, answers, canonical):
    """Map 7-path probes to deduplicated, canonical alternatives per name.

    A collision in different canonical files is ambiguous, not first-match wins.
    """
    need(type(names) is list and 1 <= len(names) <= MAX_NAMES_PER_LAYER and
         len(names)==len(set(names)), 'scan_name_bound_or_duplicate')
    need(type(answers) is list and len(answers)==len(names)*len(SEARCH_DIRS),
         'scan_boolean_cardinality')
    need(type(canonical) is list, 'scan_realpath_type')
    options={};hits={};offset=0;idx=0
    for name in names:
        paths=candidate_paths(name)
        matches=[];raw_paths=[]
        for path in paths:
            found=answers[offset];offset+=1
            need(found in ('true','false'), 'scan_not_boolean')
            if found=='true':
                need(idx<len(canonical), 'scan_missing_realpath')
                resolved=canonical_guest_path(canonical[idx]);idx+=1
                raw_paths.append({'candidate_path':path, 'canonical_path':resolved})
                if resolved not in matches:
                    matches.append(resolved)
        options[name]=matches
        hits[name]=raw_paths
    need(idx==len(canonical), 'scan_excess_realpath')
    return options,hits


def validate_r20_receipts(r19_doc,r20_doc):
    """Reconstruct R20's reconciliation, not just its claimed counts."""
    oldmap,initial_missing=r20.validate_r19(r19_doc)
    need(type(r20_doc) is dict and
         r20_doc.get('scope')=='P8_R20_SAMBA_STATIC_CANDIDATES_NOT_LOADER_PROOF'
         and r20_doc.get('base_main_commit')==R20_BASE
         and r20_doc.get('image_sha256')==IMAGE_SHA
         and r20_doc.get('r19_private_receipt_sha256')==R19_SHA
         and r20_doc.get('r9_offline_status')=='PASS_P8_R9_OFFLINE_QCOW2_READ_ONLY_OBSERVATION'
         and r20_doc.get('operator_confirmed_image_idle') is True,
         'source_identity')
    for key in ('effective_loader_resolution_verified','runtime_dependency_closure_verified',
                'runtime_binary_identity_verified','dispatch_allowed','guest_binaries_executed'):
        need(r20_doc.get(key) is False,'r20_unsafe_promotion_'+key)
    need(r20_doc.get('authorized_profiles')==0 and r20_doc.get('authorized_cases')==0,
         'r20_authority')
    result=r20_doc.get('result')
    need(type(result) is dict and type(result.get('new_nodes')) is list and
         type(result.get('unresolved_new_dso_edges')) is list, 'r20_result_shape')
    counts=result.get('summary')
    need(type(counts) is dict, 'r20_summary_shape')
    expected_counts={
        'r19_initial_unresolved_edges':67,
        'r19_recovered_candidate_edges':67,
        'r19_remaining_unresolved_edges':0,
        'r20_new_library_nodes':64,
        'r20_new_dso_needed_edges':563,
        'r20_new_unresolved_edges':8,
        'r20_unique_names_probed':69,
        'r20_names_found_in_samba':64,
        'r20_custom_search_path_flags':53,
    }
    for k,v in expected_counts.items():need(counts.get(k)==v,'r20_count_'+k)
    need(counts.get('candidate_only') is True, 'r20_candidate_status')
    for key in ('loader_semantics_verified','runtime_identity_verified',
                'transitive_dependency_closure_verified','dispatch_allowed'):
        need(counts.get(key) is False,'r20_summary_promotion_'+key)
    need(counts.get('authorized_profiles')==0 and counts.get('authorized_cases')==0,
         'r20_summary_authority')
    need(result.get('candidate_dir')==r20.SAMBA_DIR, 'r20_candidate_dir')
    need(len(result['new_nodes'])==64 and len(result['unresolved_new_dso_edges'])==8,
         'r20_actual_count')
    visited={}
    for node in result['new_nodes']:
        name=g.safe_soname(node['origin_soname'])
        path=r20.validated_canonical(node['canonical_path'])
        meta=node['metadata']
        need(meta.get('elf_type')=='ET_DYN' and meta.get('soname') in (name,None) and
             meta.get('dispatch_allowed') is False and
             meta.get('loader_executed') is False and
             meta.get('static_candidate_only') is True and
             type(meta.get('sha256')) is str and SHA_RE.fullmatch(meta['sha256']) is not None,
             'r20_node_metadata')
        need(name not in visited, 'r20_duplicate_origin_name')
        visited[name]=path
    missing=Counter()
    for edge in result['unresolved_new_dso_edges']:
        name=g.safe_soname(edge['soname']);g.safe_path(edge['requested_by'])
        need(edge.get('reason')=='CANDIDATE_NOT_OBSERVED' and
             name not in visited and name not in oldmap, 'r20_unresolved_consistency')
        missing[name]+=1
    need(dict(missing)==EXPECTED_MISSING, 'r20_missing_exact_five_names')
    for name in missing:visited[name]=None
    need(set(initial_missing).issubset(visited), 'r20_incomplete_r19_seed')
    rebuilt=r20.evaluate(r19_doc['result'],result['new_nodes'],visited)
    for key in ('summary','recovered_r19_edges','remaining_r19_edges',
                'new_dso_edges','unresolved_new_dso_edges','candidate_dir'):
        need(result.get(key)==rebuilt.get(key), 'r20_recomputation_'+key)
    need(len(visited)==69, 'r20_visited_names')
    known=dict(oldmap)
    for name,path in visited.items():
        if path is not None:
            need(name not in known or known[name]==path,'source_conflicting_candidate')
            known[name]=path
    return known, sorted(missing)


def evaluate(r20_doc,known,scanned,new_nodes,raw_hits):
    """Reconcile all R20 unresolved references + observed new dependencies."""
    need(type(known) is dict and type(scanned) is dict and
         type(new_nodes) is list and type(raw_hits) is dict,'shapes')
    need(len(new_nodes)<=MAX_NEW_NODES,'new_node_bound')
    expected=set(EXPECTED_MISSING)
    need(expected.issubset(scanned),'seeds_not_scanned')
    paths=set();by_name={}
    for name,path in known.items():
        g.safe_soname(name);canonical_guest_path(path)
    for node in new_nodes:
        path=canonical_guest_path(node['canonical_path'])
        need(path not in paths,'duplicate_new_node');paths.add(path)
        meta=node['metadata']
        need(meta.get('elf_type')=='ET_DYN' and
             meta.get('static_candidate_only') is True and
             meta.get('dispatch_allowed') is False and
             meta.get('loader_executed') is False and
             type(meta.get('sha256')) is str and SHA_RE.fullmatch(meta['sha256']) is not None,
             'node_policy')
        origin=g.safe_soname(node['origin_soname'])
        need(meta.get('soname') in (None,origin),'soname_mismatch')
        need(origin not in known,'known_read_again')
        need(origin not in by_name or by_name[origin]==path,'new_name_conflict')
        by_name[origin]=path
    for name,opts in scanned.items():
        g.safe_soname(name)
        need(type(opts) is list and len(opts)<=len(SEARCH_DIRS) and
             len(set(opts))==len(opts),'probe_alternatives')
        for path in opts:canonical_guest_path(path)
        need(name not in known,'scanned_already_known')
        if len(opts)==1:need(opts[0] in paths,'singleton_not_observed')
    for name in raw_hits:
        need(name in scanned, 'extra_hit')
    need(set(raw_hits)==set(scanned),'missing_raw_hits')
    for name,hits in raw_hits.items():
        need(type(hits) is list and len(hits)<=len(SEARCH_DIRS),'hit_bound')
        for hit in hits:
            need(type(hit) is dict and set(hit)=={'candidate_path','canonical_path'},'hit_fields')
            need(hit['candidate_path'] in candidate_paths(name),'unapproved_raw_lookup')
            need(hit['canonical_path'] in scanned[name],'raw_hit_drift')
        need(set(x['canonical_path'] for x in hits)==set(scanned[name]),'hit_coverage')
    source_rows=r20_doc['result']['unresolved_new_dso_edges']
    original=[];unresolved=[];ambiguous=[]
    for row in source_rows:
        name=row['soname'];owner=row['requested_by'];opts=scanned[name]
        if len(opts)==1:
            original.append({'requested_by':owner,'soname':name,
                             'candidate_path':opts[0], 'candidate_only':True})
        elif not opts:
            unresolved.append({'requested_by':owner,'soname':name,
                               'reason':'NO_GUEST_CANDIDATE_IN_SEVEN_DIRS'})
        else:
            ambiguous.append({'requested_by':owner,'soname':name,
                              'candidate_paths':opts,'reason':'MULTIPLE_DISTINCT_CANONICAL_CANDIDATES'})
    added=[];new_missing=[];new_ambiguous=[]
    for node in new_nodes:
        for name in node['metadata']['dt_needed_direct']:
            g.safe_soname(name)
            opts=([known[name]] if name in known else scanned.get(name,[]))
            classification=('CANDIDATE' if len(opts)==1 else
                            'UNRESOLVED' if not opts else 'AMBIGUOUS')
            edge={'requested_by':node['canonical_path'],'soname':name,
                  'candidate_paths':opts,'classification':classification,
                  'runtime_selected':False}
            added.append(edge)
            if classification=='UNRESOLVED':new_missing.append(edge)
            elif classification=='AMBIGUOUS':new_ambiguous.append(edge)
    need(len(added)<=MAX_NEW_EDGES,'new_edge_bound')
    flags=[{'canonical_path':n['canonical_path'],'reason':'CUSTOM_SEARCH_PATH_NOT_EVALUATED'}
           for n in new_nodes if n['metadata'].get('dt_rpath') or n['metadata'].get('dt_runpath')]
    summary={
        'r20_initial_unresolved_edges':8,
        'r20_recovered_candidate_edges':len(original),
        'r20_remaining_unresolved_edges':len(unresolved),
        'r20_ambiguous_edges':len(ambiguous),
        'r21_unique_names_probed':len(scanned),
        'r21_new_library_nodes':len(new_nodes),
        'r21_new_dso_needed_edges':len(added),
        'r21_new_unresolved_edges':len(new_missing),
        'r21_new_ambiguous_edges':len(new_ambiguous),
        'r21_new_custom_search_path_flags':len(flags),
        'candidate_only':True,
        'loader_resolution_verified':False,
        'runtime_dependency_closure_verified':False,
        'effective_configuration_verified':False,
        'runtime_identity_verified':False,
        'authorized_profiles':0,'authorized_cases':0,
        'dispatch_allowed':False,'guest_binaries_executed':False,
    }
    need(sum(summary[k] for k in ('r20_recovered_candidate_edges',
          'r20_remaining_unresolved_edges','r20_ambiguous_edges'))==8,'r20_partition')
    return {'summary':summary,'recovered_r20_edges':original,
            'remaining_r20_edges':unresolved,'ambiguous_r20_edges':ambiguous,
            'new_nodes':new_nodes,'new_dso_edges':added,
            'unresolved_new_dso_edges':new_missing,'ambiguous_new_dso_edges':new_ambiguous,
            'custom_search_path_uncertainties':flags,
            'probed_candidates':{name:opts for name,opts in scanned.items()},
            'probe_hits':raw_hits,
            'candidate_search_dirs':list(SEARCH_DIRS)}
