#!/usr/bin/env python3
"""P8-R22: strict, static audit of ELF search strings and candidate graph.

Pure data processing. NOT an ld.so emulator. Never loads binaries, runs clients,
uses a VM, resolves effective environment, grants profile authority or dispatch.
"""
from __future__ import annotations
from collections import Counter
import re
import p8_r19_graph as graph
import p8_r21_multiarch_reconcile as r21

BASE = '0abec70380976b15a674580ab600f9bd933678c8'
R18_SHA = '90586b0fedd11fad28e9896f75f654fe3ff7558f2510940bd5e48d2171cbb806'
R19_SHA = r21.R19_SHA
R20_SHA = r21.R20_SHA
R21_SHA = '79a9d6512cb3fccaafb90240b44d29d9747df798c34d2b956008161d667cbeff'
IMAGE_SHA = r21.IMAGE_SHA
EXPECTED_NODES = (68,64,6)
EXPECTED_EDGES = (292,563,51)
EXPECTED_FLAGS = (9,53,4)
ROOTS = ('/usr/bin/ssh','/usr/bin/curl','/usr/bin/smbclient')
SONAME_HASH = re.compile(r'[0-9a-f]{64}\Z')
TOKEN = re.compile(r'\$(?:ORIGIN|LIB|PLATFORM)(?![A-Za-z0-9_])|\$\{(?:ORIGIN|LIB|PLATFORM)\}')
DOLLAR_TOKEN = re.compile(r'\$\{[^}]*\}|\$[A-Za-z_][A-Za-z_0-9]*')


def need(ok, why):
    graph.need(ok, 'r22_'+why)


def path_segments(raw):
    """Lexical audit, never expand or apply glibc precedence.

    Retain empty segments; possible cwd semantics are explicitly unsafe/unknown.
    """
    need(type(raw) is str and 1 <= len(raw) <= 255 and '\x00' not in raw and
         '\n' not in raw and '\r' not in raw and '\\' not in raw,
         'unsafe_search_value')
    segments=[]
    for segment in raw.split(':'):
        tokens=DOLLAR_TOKEN.findall(segment)
        approved=all(TOKEN.fullmatch(t) is not None for t in tokens)
        has_unknown='$' in DOLLAR_TOKEN.sub('',segment) or not approved
        has_parent='..' in segment.split('/')
        kind=('EMPTY_CWD_SENSITIVE' if not segment else
              'UNKNOWN_DYNAMIC_TOKEN' if has_unknown else
              'PARENT_TRAVERSAL_UNRESOLVED' if has_parent else
              'DYNAMIC_TOKEN_REQUIRES_RUNTIME_CONTEXT' if tokens else
              'ABSOLUTE_DIRECTORY_NOT_EFFECTIVE_PROOF' if segment.startswith('/') else
              'RELATIVE_CWD_SENSITIVE')
        segments.append({'segment':segment,'kind':kind,'tokens':tokens})
    return segments


def source_ledger(r18, r19, r20, r21doc):
    """Validate pinned provenance and replay both R20 and R21 reconciliation.

    This is source consistency only. The SHA anchors must be checked by the caller.
    """
    need(type(r18) is dict and type(r19) is dict and
         type(r20) is dict and type(r21doc) is dict,'source_shapes')
    need(r18.get('scope')=='P8_R18_OFFLINE_DIRECT_ELF_CANDIDATE_ONLY' and
         r18.get('image_sha256')==IMAGE_SHA and
         r18.get('authorized_profiles')==0 and r18.get('authorized_cases')==0 and
         r18.get('guest_binaries_executed') is False and
         r18.get('dispatch_allowed') is False,'r18_source')
    roots=r18.get('candidates')
    need(type(roots) is list and len(roots)==3 and
         [r.get('guest_path') for r in roots]==list(ROOTS),'roots_identity')
    for root in roots:
        metadata=root['metadata']
        need(metadata.get('dynamic_loader_executed') is False and
             metadata.get('runtime_identity_verified') is False and
             metadata.get('dispatch_allowed') is False and
             SONAME_HASH.fullmatch(metadata.get('sha256','')) is not None and
             type(metadata.get('dt_needed_direct')) is list,'root_policy')
    known, seeds=r21.validate_r20_receipts(r19,r20)
    need(seeds==sorted(r21.EXPECTED_MISSING),'r21_seed_drift')
    need(r21doc.get('scope')=='P8_R21_READ_ONLY_MULTIARCH_CANDIDATES_NO_LOADER_PROOF' and
         r21doc.get('base_main_commit')==r21.R21_BASE and
         r21doc.get('image_sha256')==IMAGE_SHA and
         r21doc.get('r19_private_receipt_sha256')==R19_SHA and
         r21doc.get('r20_private_receipt_sha256')==R20_SHA and
         r21doc.get('r9_offline_status')=='PASS_P8_R9_OFFLINE_QCOW2_READ_ONLY_OBSERVATION' and
         r21doc.get('operator_confirmed_image_idle') is True and
         r21doc.get('authorized_profiles')==0 and r21doc.get('authorized_cases')==0,
         'r21_source_identity')
    for f in ('runtime_dependency_closure_verified','loader_search_semantics_verified',
              'runtime_binary_identity_verified','effective_configuration_verified',
              'guest_binaries_executed','dispatch_allowed'):
        need(r21doc.get(f) is False,'r21_source_promotion_'+f)
    result=r21doc['result']
    replay=r21.evaluate(r20,known,result['probed_candidates'],
                        result['new_nodes'],result['probe_hits'])
    need(result==replay,'r21_replay_mismatch')
    counts=result['summary']
    need(counts['r20_recovered_candidate_edges']==8 and
         counts['r20_remaining_unresolved_edges']==0 and
         counts['r20_ambiguous_edges']==0 and
         counts['r21_new_unresolved_edges']==0 and
         counts['r21_new_ambiguous_edges']==0 and
         counts['r21_new_library_nodes']==6 and
         counts['r21_new_dso_needed_edges']==51 and
         counts['r21_new_custom_search_path_flags']==4,'r21_exact_counts')
    return roots,known


def analyze(roots,r19_result,r20_result,r21_result):
    """Exact independent data-accounting of all 906 candidate edges and 66 search flags.

    No path is selected by an emulated loader; candidate evidence is never authority.
    """
    need(type(roots) is list and type(r19_result) is dict and
         type(r20_result) is dict and type(r21_result) is dict,'input_shapes')
    groups=(r19_result['nodes'],r20_result['new_nodes'],r21_result['new_nodes'])
    need(tuple(map(len,groups))==EXPECTED_NODES,'node_count')
    sources={}
    def add(path,meta,origin):
        graph.safe_path(path)
        need(path not in sources,'duplicate_path')
        need(type(meta) is dict and meta.get('dispatch_allowed') is False and
             meta.get('loader_executed') is False and
             meta.get('static_candidate_only') is True and
             meta.get('elf_type')=='ET_DYN' and
             SONAME_HASH.fullmatch(meta.get('sha256','')) is not None and
             type(meta.get('dt_needed_direct')) is list,'node_policy')
        sources[path]={'metadata':meta,'origin':origin}
    for name,group in zip(('R19','R20','R21'),groups):
        for node in group:add(node['canonical_path'],node['metadata'],name)
    need(len(sources)==sum(EXPECTED_NODES),'node_total')
    owner_metadata={}
    for root in roots:
        path=graph.safe_path(root['guest_path'])
        need(path in ROOTS and path not in owner_metadata,'root_name')
        owner_metadata[path]={'metadata':root['metadata'],'origin':'R18'}
    need(len(owner_metadata)==3,'root_count')
    owner_metadata.update(sources)
    interpreter=r19_result['interpreter_candidate']
    need(interpreter['canonical_path'] in sources and
         all(r['metadata']['interpreter']==interpreter['declared'] for r in roots),
         'interp_candidate_only')
    edges=(r19_result['edges'],r20_result['new_dso_edges'],r21_result['new_dso_edges'])
    need(tuple(map(len,edges))==EXPECTED_EDGES,'edge_count')
    r20fix={(x['requested_by'],x['soname']):x['candidate_path']
            for x in r20_result['recovered_r19_edges']}
    r21fix={(x['requested_by'],x['soname']):x['candidate_path']
            for x in r21_result['recovered_r20_edges']}
    need(len(r20_result['recovered_r19_edges'])==67 and
         len(r20_result['remaining_r19_edges'])==0 and
         len(r20_result['unresolved_new_dso_edges'])==8 and
         len(r21_result['recovered_r20_edges'])==8 and
         len(r21_result['remaining_r20_edges'])==0,'recovery_provenance')
    candidate_edges=[]
    for kind,group in zip(('R19','R20','R21'),edges):
        for edge in group:
            owner=graph.safe_path(edge['requested_by'])
            soname=graph.safe_soname(edge['soname'])
            need(owner in owner_metadata,'unknown_edge_owner')
            key=(owner,soname)
            if kind=='R19':
                need(edge.get('candidate_resolution_only') is True and
                     edge.get('runtime_selected') is False,'r19_edge_promotion')
                choices=edge['candidate_paths'] or ([r20fix[key]] if key in r20fix else [])
            elif kind=='R20':
                need(edge.get('runtime_selected') is False,'r20_edge_promotion')
                choices=([edge['candidate_path']] if edge['candidate_path'] is not None
                         else [r21fix[key]] if key in r21fix else [])
            else:
                need(edge.get('runtime_selected') is False and
                     edge.get('classification')=='CANDIDATE','r21_edge_promotion')
                choices=edge['candidate_paths']
            need(type(choices) is list and len(choices)==1,'unresolved_or_ambiguous_edge')
            target=graph.safe_path(choices[0])
            need(target in sources,'edge_target_not_audited')
            candidate_edges.append({'owner':owner,'soname':soname,
                                    'candidate':target,'evidence_origin':kind})
    need(len(candidate_edges)==sum(EXPECTED_EDGES),'candidate_edge_count')
    flags=[]
    for owner,record in owner_metadata.items():
        meta=record['metadata']
        for tag,key in (('DT_RPATH','dt_rpath'),('DT_RUNPATH','dt_runpath')):
            raw=meta.get(key)
            if raw is None:
                continue
            flags.append({'owner':owner,'origin':record['origin'],'tag':tag,
                          'expression':raw,'segments':path_segments(raw),
                          'direct_needed':len(meta['dt_needed_direct'])})
    observed_flags=Counter(f['origin'] for f in flags)
    # Source counters count flagged objects (an object with both tags counts once).
    flagged_owners=Counter()
    for owner,rec in owner_metadata.items():
        if rec['metadata'].get('dt_rpath') or rec['metadata'].get('dt_runpath'):
            flagged_owners[rec['origin']]+=1
    need((flagged_owners['R18']+flagged_owners['R19'],
          flagged_owners['R20'],flagged_owners['R21'])==EXPECTED_FLAGS,
         'search_flag_provenance')
    need(len(r19_result['search_path_uncertainties'])==EXPECTED_FLAGS[0] and
         r20_result['summary']['r20_custom_search_path_flags']==EXPECTED_FLAGS[1] and
         len(r21_result['custom_search_path_uncertainties'])==EXPECTED_FLAGS[2],
         'search_source_flags')
    kinds=Counter(s['kind'] for f in flags for s in f['segments'])
    tags=Counter(f['tag'] for f in flags)
    summary={'candidate_dso_nodes':len(sources),
             'candidate_roots':3,'candidate_graph_edges':len(candidate_edges),
             'static_candidate_edges_without_candidate':0,
             'search_flagged_objects':sum(EXPECTED_FLAGS),
             'search_tag_occurrences':len(flags),
             'search_path_segments':sum(kinds.values()),
             'search_tag_counts':dict(sorted(tags.items())),
             'segment_risk_counts':dict(sorted(kinds.items())),
             'source_flagged_objects':{'R19_including_R18_roots':EXPECTED_FLAGS[0],
                                       'R20':EXPECTED_FLAGS[1],'R21':EXPECTED_FLAGS[2]},
             'loader_search_order_verified':False,
             'effective_loader_resolution_verified':False,
             'glibc_cache_verified':False,
             'glibc_hwcaps_verified':False,
             'environment_and_preload_verified':False,
             'runtime_binary_identity_verified':False,
             'effective_configuration_verified':False,
             'transitive_runtime_closure_verified':False,
             'authorized_profiles':0,'authorized_cases':0,'dispatch_allowed':False,
             'candidate_only':True}
    return {'summary':summary,'search_path_audit':flags,
            'candidate_edges':candidate_edges,
            'scope':'STATIC_METADATA_ONLY_NOT_LD_SO_SEMANTICS'}
