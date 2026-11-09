#!/usr/bin/env python3
"""P8-R20: bounded, pure candidate resolution for Samba's Debian multiarch DSO directory.

No effective ld.so semantics, no process execution, no authority, no dispatch.
"""
from __future__ import annotations
from collections import Counter
import p8_r19_graph as g

SAMBA_DIR = '/usr/lib/x86_64-linux-gnu/samba'
MAX_PROBE_NAMES = 128
MAX_NEW_LIBRARIES = 92
MAX_ADDED_EDGES = 1000
MAX_LAYERS = 12
EXPECTED_R19_COUNTS = (68,292,67,0)


def need(ok, reason):
    g.need(ok, 'r20_'+reason)


def restricted_candidate(name):
    return g.safe_path(SAMBA_DIR+'/'+g.safe_soname(name))


def validated_canonical(path):
    g.safe_path(path)
    need(path.startswith(SAMBA_DIR+'/'), 'canonical_escaped_samba_directory')
    return path


def validate_r19(doc):
    need(type(doc) is dict and doc.get('scope')=='P8_R19_OFFLINE_STATIC_ELF_CANDIDATE_GRAPH_ONLY', 'receipt_scope')
    need(doc.get('base_main_commit')=='e1e43c621e28628d004775d888ef5b133debfb52', 'receipt_base')
    need(doc.get('operator_confirmed_image_idle') is True, 'r19_image_idle_declaration')
    for field in ('runtime_dependency_closure_verified', 'effective_loader_resolution_verified',
                  'case_authority_verified','dispatch_allowed','guest_binaries_executed'):
        need(doc.get(field) is False, 'r19_unsafe_promotion_'+field)
    need(doc.get('authorized_profiles')==0 and doc.get('authorized_cases')==0,'r19_authority')
    result = doc.get('result')
    need(type(result) is dict,'r19_result_shape')
    summary=result.get('summary')
    need(type(summary) is dict and summary.get('status')=='PASS_P8_R19_OFFLINE_CANDIDATE_GRAPH_NOT_LOADER_CLOSURE', 'r19_status')
    counts=(summary.get('observed_library_nodes'),summary.get('direct_and_transitive_candidate_edges'),
            summary.get('unresolved_edges'),summary.get('ambiguous_edges'))
    need(counts==EXPECTED_R19_COUNTS,'r19_summary_counts')
    for field in ('runtime_dependency_closure_verified','loader_search_semantics_verified','dispatch_allowed'):
        need(summary.get(field) is False,'r19_summary_promotion_'+field)
    nodes=result.get('nodes');edges=result.get('edges');missing=result.get('unresolved');ambiguous=result.get('ambiguous')
    need(type(nodes) is list and type(edges) is list and type(missing) is list and type(ambiguous) is list, 'r19_lists')
    need((len(nodes),len(edges),len(missing),len(ambiguous))==EXPECTED_R19_COUNTS,'r19_actual_counts')
    canon=set()
    for node in nodes:
        p=g.safe_path(node['canonical_path']);need(p not in canon,'r19_duplicate_node')
        canon.add(p)
        meta=node['metadata']
        need(meta['dispatch_allowed'] is False and meta['loader_executed'] is False
             and meta['static_candidate_only'] is True,'r19_node_promotion')
    path_by_name={}
    edge_counts=Counter()
    for edge in edges:
        n=g.safe_soname(edge['soname']);opts=edge['candidate_paths']
        g.safe_path(edge['requested_by']);need(type(opts) is list and len(opts)<=1,'r19_edge_ambiguous')
        need(edge['runtime_selected'] is False and edge['candidate_resolution_only'] is True,'r19_edge_promotion')
        edge_counts[(edge['requested_by'],n)] += 1
        if opts:
            p=g.safe_path(opts[0]);need(p in canon,'r19_candidate_not_observed')
            need(n not in path_by_name or path_by_name[n]==p,'r19_conflicting_names')
            path_by_name[n]=p
    missing_counts=Counter()
    for edge in missing:
        key=(g.safe_path(edge['requested_by']),g.safe_soname(edge['soname']))
        need(edge.get('status')=='NOT_FOUND_IN_RESTRICTED_CANDIDATE_DIRS', 'r19_missing_status')
        need(edge_counts[key]>0,'r19_missing_without_edge')
        missing_counts[key]+=1
        need(missing_counts[key]<=edge_counts[key],'r19_duplicate_missing')
        need(key[1] not in path_by_name,'r19_missing_already_resolved')
    need(sum(missing_counts.values())==67,'r19_missing_count')
    return path_by_name,sorted({name for _,name in missing_counts})


def assess_candidate_scan(names, exist, canonical):
    """Exact count, safe paths; only the pinned Samba directory is queried."""
    need(type(names) is list and len(names)<=MAX_PROBE_NAMES and len(names)==len(set(names)), 'scan_names_bound')
    need(type(exist) is list and len(exist)==len(names),'scan_exist_count')
    need(type(canonical) is list,'scan_canonical_type')
    answer={};i=0
    for name,found in zip(names,exist):
        restricted_candidate(name)
        need(found in ('true','false'),'scan_boolean')
        if found=='true':
            need(i<len(canonical),'scan_realpath_short')
            answer[name]=validated_canonical(canonical[i]);i+=1
        else:
            answer[name]=None
    need(i==len(canonical),'scan_realpath_extra')
    return answer


def evaluate(r19_result, new_nodes, probes):
    """Reconcile R19's missing references and new DSO edges, retaining uncertainty."""
    need(type(new_nodes) is list and type(probes) is dict,'r20_shapes')
    need(len(new_nodes)<=MAX_NEW_LIBRARIES,'new_node_bound')
    paths=set()
    for row in new_nodes:
        path=validated_canonical(row['canonical_path']);need(path not in paths,'duplicate_new_node')
        paths.add(path)
        meta=row['metadata']
        need(meta['elf_type']=='ET_DYN' and meta['loader_executed'] is False
             and meta['dispatch_allowed'] is False and meta['static_candidate_only'] is True,
             'new_node_promotion')
    for name,path in probes.items():
        restricted_candidate(name)
        if path is not None:
            validated_canonical(path)
            need(path in paths,'probed_file_not_observed')
    missed=r19_result['unresolved']
    recovered=[{'requested_by':row['requested_by'],'soname':row['soname'],
                'candidate_path':probes[row['soname']]}
               for row in missed if probes.get(row['soname']) is not None]
    pending=[{'requested_by':row['requested_by'],'soname':row['soname'],
              'reason':'NOT_FOUND_IN_SAMBA_CANDIDATE_DIR'}
             for row in missed if probes.get(row['soname']) is None]
    oldmap={}
    for row in r19_result['edges']:
        if row['candidate_paths']:
            n=row['soname'];p=row['candidate_paths'][0]
            need(n not in oldmap or oldmap[n]==p,'oldmap_conflict')
            oldmap[n]=p
    new_edges=[];missing_new=[]
    for row in new_nodes:
        for n in row['metadata']['dt_needed_direct']:
            g.safe_soname(n)
            p=oldmap.get(n) or probes.get(n)
            new_edges.append({'requested_by':row['canonical_path'],'soname':n,
                              'candidate_path':p,'runtime_selected':False})
            if p is None:missing_new.append({'requested_by':row['canonical_path'],'soname':n,
                                             'reason':'CANDIDATE_NOT_OBSERVED'})
    need(len(new_edges)<=MAX_ADDED_EDGES,'new_edges_bound')
    proof={'r19_initial_unresolved_edges':len(missed), 'r19_recovered_candidate_edges':len(recovered),
           'r19_remaining_unresolved_edges':len(pending), 'r20_new_library_nodes':len(new_nodes),
           'r20_new_dso_needed_edges':len(new_edges), 'r20_new_unresolved_edges':len(missing_new),
           'r20_unique_names_probed':len(probes), 'r20_names_found_in_samba':sum(x is not None for x in probes.values()),
           'r20_custom_search_path_flags':sum(bool(x['metadata'].get('dt_runpath') or x['metadata'].get('dt_rpath')) for x in new_nodes),
           'candidate_only':True,'loader_semantics_verified':False,'runtime_identity_verified':False,
           'transitive_dependency_closure_verified':False,'authorized_profiles':0,
           'authorized_cases':0,'dispatch_allowed':False}
    need(proof['r19_recovered_candidate_edges']+proof['r19_remaining_unresolved_edges']==67,'partition')
    return {'summary':proof,'recovered_r19_edges':recovered,'remaining_r19_edges':pending,
            'new_dso_edges':new_edges,'unresolved_new_dso_edges':missing_new,
            'new_nodes':new_nodes,
            'candidate_dir':SAMBA_DIR}
