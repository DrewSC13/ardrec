#!/usr/bin/env python3
"""R58-A FTP: deterministic, in-memory NIC candidate; NEVER apply or start anything.

Reads only the pre-existing, exact pinned host preflight and libvirt read-only XML.
No virsh define, net-start, VM start, nft write, systemd action, or disk output.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import sys
from xml.etree import ElementTree as ET

REPO = Path('/home/cicada/Development/GitHub/ardrec')
SOURCE_HEAD = 'be7bc497bbbb45b585ac308066d6ff08b07775bd'
PRIOR_REL = 'scripts/ardrec_p14_r58a_ftp_nic_preflight.py'
PRIOR_SHA256 = '9b778d8414241d2f69dd53c8a90b944441d82b17b365378edc38ca53a3adad6d'
DOMAIN = 'ardrec-r33-dev-runner'
NET = 'ardrec-r33-dev-net-ftp'
MAC = '52:54:00:ad:31:01'
TAP = 'a33d31r'
FILTER = 'ardrec-r33-block-until-containment'
CLOSING = re.compile(r'(?m)^([ \t]*)</interface>[ \t]*$')

class GateError(ValueError):
    """No candidate if exact, safe source identity cannot be shown."""


def need(value: bool, reason: str):
    if not value:
        raise GateError(reason)


def sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def xml_root(body: bytes) -> ET.Element:
    need(type(body) is bytes and 0 < len(body) <= 300_000 and
         b'<!DOCTYPE' not in body and b'<!ENTITY' not in body and
         b'<!--' not in body and b'-->' not in body, 'UNSAFE_XML')
    try:
        return ET.fromstring(body)
    except ET.ParseError as exc:
        raise GateError('INVALID_XML') from exc


def safe_nic(root: ET.Element) -> ET.Element:
    need(root.tag == 'domain' and root.findtext('name') == DOMAIN,
         'WRONG_RUNNER_DOMAIN')
    dev = root.find('devices')
    need(dev is not None, 'MISSING_DEVICES')
    interfaces = dev.findall('interface')
    need(len(interfaces) == 1, 'RUNNER_NOT_SSH_ONLY')
    iface = interfaces[0]
    need(iface.attrib == {'type':'network'} and
         len(iface.findall('mac')) == len(iface.findall('source')) ==
         len(iface.findall('target')) == len(iface.findall('filterref')) == 1,
         'SSH_NIC_STRUCTURE_DRIFT')
    need(iface.find('mac').attrib == {'address':'52:54:00:ad:30:01'} and
         iface.find('source').attrib == {'network':'ardrec-r33-dev-net-ssh'} and
         iface.find('target').attrib == {'dev':'a33d30r'} and
         iface.find('filterref').attrib == {'filter':FILTER},
         'SSH_NIC_IDENTITY_OR_DENY_DRIFT')
    need(not root.findall('devices/hostdev') and not root.findall('devices/graphics'),
         'RUNNER_UNEXPECTED_HOST_DEVICE_OR_GRAPHICS')
    return iface


def strict_new_ftp_nic(node: ET.Element):
    need(node.attrib == {'type':'network'} and
         len(node) == 5 and [c.tag for c in node] ==
         ['mac', 'source', 'target', 'model', 'filterref'] and
         node[0].attrib == {'address':MAC} and
         node[1].attrib == {'network':NET} and
         node[2].attrib == {'dev':TAP} and
         node[3].attrib == {'type':'virtio'} and
         node[4].attrib == {'filter':FILTER},
         'CANDIDATE_FTP_NIC_NOT_EXACT')


def build_candidate(raw: bytes) -> tuple[bytes, dict]:
    """Inject one guarded FTP interface WITHOUT rewriting existing XML bytes."""
    before_root = xml_root(raw)
    original = safe_nic(before_root)
    try:
        source = raw.decode('utf-8', errors='strict')
    except UnicodeError as exc:
        raise GateError('RUNNER_XML_NOT_UTF8') from exc
    matches = list(CLOSING.finditer(source))
    need(len(matches) == 1, 'RUNNER_INTERFACE_ANCHOR_NOT_EXACT')
    indent = matches[0].group(1)
    need(2 <= len(indent) <= 20 and indent.isspace(), 'XML_INDENT_NOT_SAFE')
    child = indent + '  '
    injected = ("\n" + indent + "<interface type='network'>\n" +
                child + "<mac address='" + MAC + "'/>\n" +
                child + "<source network='" + NET + "'/>\n" +
                child + "<target dev='" + TAP + "'/>\n" +
                child + "<model type='virtio'/>\n" +
                child + "<filterref filter='" + FILTER + "'/>\n" +
                indent + '</interface>')
    candidate = (source[:matches[0].end()] + injected +
                 source[matches[0].end():]).encode('utf-8')
    after_root = xml_root(candidate)
    dev_before = before_root.find('devices')
    dev_after = after_root.find('devices')
    need(dev_after is not None and len(dev_after) == len(dev_before) + 1,
         'CANDIDATE_UNEXPECTED_DEVICE_CHANGE')
    a_nics = dev_after.findall('interface')
    need(len(a_nics) == 2 and a_nics[0].attrib == original.attrib,
         'CANDIDATE_ORIGINAL_NIC_CHANGED')
    strict_new_ftp_nic(a_nics[1])
    # The existing source bytes must be an exact contiguous subsequence around the insertion.
    need(candidate.replace(injected.encode('utf-8'),b'',1) == raw,
         'CANDIDATE_NONADDITIVE_CHANGE')
    # Prove each old device child is unchanged at the XML level too.
    before_children = list(dev_before)
    after_children = list(dev_after)
    insertion = next(i for i,e in enumerate(after_children) if e is a_nics[1])
    after_children.pop(insertion)
    need(len(after_children)==len(before_children) and
         all(ET.tostring(a) == ET.tostring(b) for a,b in zip(before_children, after_children)),
         'CANDIDATE_EXISTING_DEVICE_MUTATION')
    return candidate, {
        'original_xml_sha256':sha(raw),
        'candidate_xml_sha256':sha(candidate),
        'candidate_bytes':len(candidate),
        'inserted_xml_bytes':len(injected.encode('utf-8')),
        'added_nic':{'network':NET,'mac':MAC,'tap':TAP,'model':'virtio','filter':FILTER},
        'existing_nics_preserved':True,
        'existing_xml_bytes_preserved':True,
    }


def load_prior(root: Path):
    need(root.resolve()==REPO and Path.cwd().resolve()==REPO,
         'MUST_RUN_FROM_MAIN_REPOSITORY')
    path = root/PRIOR_REL
    need(path.is_file() and not path.is_symlink() and sha(path.read_bytes())==PRIOR_SHA256,
         'PRIOR_PREFLIGHT_SHA256_DRIFT')
    spec=importlib.util.spec_from_file_location('ardrec_r58a_ftp_preflight_pinned',path)
    need(spec is not None and spec.loader is not None, 'PRIOR_IMPORT_FAILED')
    module=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    need(module.SOURCE_COMMIT == SOURCE_HEAD,'SOURCE_HEAD_MISMATCH')
    return module


def plan_from_host(prior, *, get_runner=None) -> dict:
    """All host access goes through prior allowlisted READONLY commands."""
    report_before=prior.read_host()
    need(report_before.get('result')=='BLOCKED_FTP_RUNNER_NIC_MISSING' and
         report_before.get('four_dev_domains_off') is True and
         report_before.get('ftp_network_inactive') is True and
         report_before.get('nft_r34') == 'DENY_STRUCTURE_MATCHED_FOUR_SCOPED_DROPS' and
         report_before.get('nwfilter_r34') == 'DROP_ALL_DEFINITION_MATCHED',
         'FIRST_READONLY_GATE_NOT_MATCHED')
    cmd=['/usr/bin/virsh','--readonly','-c','qemu:///system',
         'dumpxml', DOMAIN,'--inactive']
    getter=get_runner if get_runner is not None else prior.run_readonly
    raw_first=getter(cmd)
    candidate,meta = build_candidate(raw_first)
    report_after=prior.read_host()
    raw_second=getter(cmd)
    need(raw_first == raw_second,'RUNNER_XML_CHANGED_BETWEEN_READS')
    need(report_after.get('result')==report_before['result'] and
         report_after.get('ftp_nic')==report_before['ftp_nic'] and
         report_after.get('four_dev_domains_off') is True and
         report_after.get('ftp_network_inactive') is True,
         'READONLY_GATE_CHANGED_DURING_PLAN')
    need(report_after.get('source_git_head')==SOURCE_HEAD and
         report_before.get('source_git_head')==SOURCE_HEAD and
         isinstance(report_before.get('observed_git_head'),str) and
         report_before['observed_git_head']==report_after.get('observed_git_head'),
         'REPOSITORY_HEAD_CHANGED_DURING_PLAN')
    # The XML is deliberately never written or printed; its digest is a reproducible plan.
    return {
        'schema':'ardrec-r58a-ftp-runner-one-nic-candidate-v1',
        'result':'FTP_RUNNER_XML_CANDIDATE_VERIFIED_IN_MEMORY_ONLY',
        'baseline_commit':SOURCE_HEAD,
        'observed_git_head':report_before['observed_git_head'],
        **meta,
        'runner_nics_before':['a33d30r'],
        'runner_nics_candidate':['a33d30r','a33d31r'],
        'nft_r34':'DENY_STRUCTURE_MATCHED_FOUR_SCOPED_DROPS',
        'nwfilter_r34':'DROP_ALL_DEFINITION_MATCHED',
        'runner_off':True,
        'ftp_target_off':True,
        'ftp_network_inactive':True,
        'manual_vm_boot_block_attested':False,
        'f11_guard_first_execution_attested':False,
        'independent_watchdog_verified':False,
        'libvirt_definition_modified':False,
        'physical_mutations':0,
        'candidate_xml_written':False,
        'traffic_generated':False,
        'p8':'NO-GO',
        'next_step':'SEPARATE_F11_RECOVERY_AND_PHYSICAL_RECONCILIATION_AUTHORIZATION_REQUIRED',
    }


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host-plan-readonly',action='store_true',required=True)
    parser.parse_args()
    try:
        prior=load_prior(REPO)
        report=plan_from_host(prior)
    except (GateError,ValueError,TypeError,KeyError,OSError,UnicodeError) as exc:
        print('R58A_FTP_CANDIDATE=BLOCKED:'+str(exc)[:160])
        print('R58A_FTP_CANDIDATE_PHYSICAL_MUTATIONS=0')
        print('R58A_FTP_CANDIDATE_P8=NO-GO')
        return 23
    print(json.dumps(report,ensure_ascii=True,indent=2,sort_keys=True))
    return 22


if __name__ == '__main__':
    sys.exit(main())
