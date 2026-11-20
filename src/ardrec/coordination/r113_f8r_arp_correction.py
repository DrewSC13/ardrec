"""ARDREC R113-F8R: append-only correction of F8 nwfilter ARP attribute names.

Pure module: no host commands, file writes, firewall actions or traffic.
F8/F9 original plans and incident evidence remain unchanged and replayable.
"""
from __future__ import annotations
import json
from pathlib import Path
from xml.etree import ElementTree as ET

from ardrec.coordination import r113_f8_window_policy as old

SCHEMA = 'ARDREC-R113-F8R-CORRECTED-ARP-OFFLINE-v1'
DEST = Path('/home/cicada/ardrec-lab/r113-f8r-arp-xml-v1')
OLD_PLAN = Path('/home/cicada/ardrec-lab/r113-f8-admission-policy-v1/plan-r_wtdoqp')
F9_REPORT = Path('/home/cicada/ardrec-lab/r113-f9-policy-host-acceptance-v1/validation-xiu8v24h/report.json')
F9_REPORT_SHA = '5f492ab67002cd6d8ce4d898d09c3c59c3c9551e72c243f6ac41f0e2190ae03d'
PARENT = '0eb1d8dbb618de008d8b96c5c5b89c474c54b980'


def require(ok, reason):
    if not ok:
        raise old.PolicyError(reason)


def fixed_xml(role, old_bytes=None):
    original = old.filter_xml(role) if old_bytes is None else old_bytes
    old.validate_filter(original, role)
    root = ET.fromstring(original)
    require(len(root) == 5, 'OLD_XML_SCOPE_INVALID')
    for rule in root[:2]:
        require(rule[0].tag == 'arp', 'ARP_RULE_EXPECTED')
        attrs = rule[0].attrib
        require(set(attrs) == {'srcmacaddr', 'srcipaddr', 'dstipaddr'},
                'OLD_ARP_ATTRS_CHANGED')
        src = attrs.pop('srcipaddr')
        dst = attrs.pop('dstipaddr')
        attrs['arpsrcipaddr'] = src
        attrs['arpdstipaddr'] = dst
    corrected = ET.tostring(root, encoding='utf-8', xml_declaration=True) + b'\n'
    require(corrected.count(b'arpsrcipaddr=') == 2 and
            corrected.count(b'arpdstipaddr=') == 2, 'ARP_TRANSFORMATION_FAILED')
    check_fixed_xml(corrected, role)
    return corrected


def check_fixed_xml(raw, role):
    require(type(raw) is bytes and len(raw) < 12000 and b'<!DOCTYPE' not in raw,
            'CORRECTED_XML_BYTES_INVALID')
    expected = _expected(role)
    require(raw == expected, 'CORRECTED_XML_NOT_CANONICAL')
    return True


def _expected(role):
    # Independent canonical rendering; avoids a recursive fixed_xml call.
    raw = old.filter_xml(role)
    tree = ET.fromstring(raw)
    for rule in tree[:2]:
        attrs = rule[0].attrib
        src = attrs.pop('srcipaddr')
        dst = attrs.pop('dstipaddr')
        attrs['arpsrcipaddr'] = src
        attrs['arpdstipaddr'] = dst
    return ET.tostring(tree, encoding='utf-8', xml_declaration=True) + b'\n'


def validate_f9_report(raw, original_policy):
    require(old.sha(raw) == F9_REPORT_SHA, 'F9_SOURCE_SHA256_CHANGED')
    report = json.loads(raw)
    require(report.get('schema') == 'ARDREC-R113-F9-HOST-CHECK-v1'
            and report.get('outcome') == 'BLOCKED_FIX_POLICY'
            and report.get('nft_check_only') is True
            and report.get('libvirt_schema_only') is True
            and report.get('network_probes') == 0
            and report.get('protocol_connections') == 0
            and report.get('p8') == 'NO-GO', 'F9_SOURCE_REPORT_INVALID')
    require(report.get('f8_manifest_sha256') == old.sha(original_policy['manifest.json']),
            'F9_F8_MANIFEST_LINK_CHANGED')
    expected_hashes = {name:old.sha(raw) for name,raw in original_policy.items()
                       if name != 'manifest.json'}
    require(report.get('candidate_files_sha256') == expected_hashes,
            'F9_SOURCE_POLICY_LINK_CHANGED')
    queries = report.get('queries', {})
    require(all(queries.get('xml_'+r.replace('-','_'),{}).get('rc') != 0
                for r in ('runner-ssh','ssh','runner-ftp','ftp','runner-smb','smb')),
            'F9_SOURCE_XML_ERRORS_CHANGED')
    require(queries.get('nft_check',{}).get('rc') == 0 and
            queries.get('f6_before',{}).get('rc') == 0 and
            queries.get('f6_after',{}).get('rc') == 0,
            'F9_SOURCE_DENY_OR_NFT_CHANGED')
    return True


def prepare(original_policy, f9_report):
    require(isinstance(original_policy,dict) and len(original_policy)==8,
            'F8_ORIGINAL_FILES_INVALID')
    meta = json.loads(original_policy['manifest.json'])
    require(meta.get('schema') == old.SCHEMA and meta.get('policy_not_deployed') is True
            and meta.get('window_not_opened') is True and meta.get('p8') == 'NO-GO',
            'F8_ORIGINAL_MANIFEST_INVALID')
    expected = set(meta['sha256']) | {'manifest.json'}
    require(set(original_policy) == expected, 'F8_ORIGINAL_SCOPE_INVALID')
    for name,digest in meta['sha256'].items():
        require(old.sha(original_policy[name]) == digest,
                'F8_ORIGINAL_FILE_CHANGED_'+name)
    validate_f9_report(f9_report, original_policy)
    result = {}
    for key in old.f6.ROLES:
        name = old.filter_name(key)+'.xml'
        result[name] = fixed_xml(key,original_policy[name])
    nft_name = 'r34-window-CANDIDATE.nft'
    require(original_policy[nft_name] == old.nft_script(), 'NFT_ORIGINAL_NOT_CANONICAL')
    result[nft_name] = original_policy[nft_name]
    manifest = {
        'schema': SCHEMA,
        'original_f8_manifest_sha256': old.sha(original_policy['manifest.json']),
        'rejected_f9_report_sha256': F9_REPORT_SHA,
        'f5_manifest_sha256': meta['f5_manifest_sha256'],
        'f7e_manifest_sha256': meta['f7e_manifest_sha256'],
        'correction': 'arp.srcipaddr/dstipaddr -> arpsrcipaddr/arpdstipaddr in 12 ARP rules',
        'safety': {'policy_installed':False,'traffic_admitted':False,'p8':'NO-GO'},
        'sha256': {k:old.sha(v) for k,v in sorted(result.items())},
    }
    result['manifest.json'] = old.canonical(manifest)
    return result
