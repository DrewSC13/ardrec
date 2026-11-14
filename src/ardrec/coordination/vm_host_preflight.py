"""R29: consulta local de metadatos libvirt en modo estrictamente lectura.

No arranca dominios, no crea redes, no consulta un servicio invitado y no
acredita identidad/autoridad operacional. El inventario histórico no es
una observación actual ni una autorización de pentesting.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Callable
import uuid
import xml.etree.ElementTree as ET

SCHEMA = 'ardrec-p14-r29-libvirt-readonly-preflight-v1'
HISTORY = 'ardrec-p14-r29-historical-vm-roles-v1'
MAX_JSON_BYTES = 65536
MAX_XML_BYTES = 65536
ROLES = ('ssh', 'ftp', 'smb', 'runner')
EXPECTED_NETWORKS = ('ardrec-dev-ssh', 'ardrec-dev-ftp', 'ardrec-dev-smb')
HEX_MAC = re.compile(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\Z', re.ASCII)
SAFE_DOMAIN = re.compile(r'ardrec-dev-(?:ssh|ftp|smb|runner)\Z', re.ASCII)


class VMPreflightError(ValueError):
    pass


def _need(ok: bool, reason: str) -> None:
    if not ok:
        raise VMPreflightError(reason)


def canonical(doc: Any) -> bytes:
    try:
        return json.dumps(doc, sort_keys=True, separators=(',', ':'),
                          ensure_ascii=True, allow_nan=False).encode('ascii')
    except (ValueError, TypeError, OverflowError, RecursionError) as error:
        raise VMPreflightError('canonical_json_invalid') from error


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        _need(key not in result, 'duplicate_json_key')
        result[key] = value
    return result


def _read_json(path: Path, *, limit: int = MAX_JSON_BYTES) -> tuple[dict, bytes]:
    _need(type(path) is Path or isinstance(path, Path), 'path_type_invalid')
    _need(path.is_file() and not path.is_symlink(), 'file_missing_or_symlink')
    _need(0 < path.stat().st_size <= limit, 'file_size_invalid')
    raw = path.read_bytes()
    _need(0 < len(raw) <= limit, 'file_size_invalid')
    try:
        doc = json.loads(raw, object_pairs_hook=_unique,
                         parse_constant=lambda _: _need(False, 'non_json_constant'))
    except (ValueError, UnicodeError, RecursionError) as error:
        raise VMPreflightError('json_invalid') from error
    _need(type(doc) is dict, 'json_root_invalid')
    return doc, raw


def read_profile(path: Path) -> tuple[dict[str, Any], str]:
    p, raw = _read_json(path)
    _need(set(p) == {'schema','source','provenance','host','libvirt_uri',
                     'roles','historic_cleanup','operational_authority'}, 'profile_keys_invalid')
    _need(p['schema'] == HISTORY and p['source'] == 'lab/services-v1/evidence.json',
          'profile_source_invalid')
    _need(p['host'] == 'Prometheus' and p['libvirt_uri'] == 'qemu:///system',
          'profile_scope_invalid')
    _need(p['operational_authority'] is False and
          p['historic_cleanup'] == 'ALL_TEMPORARY_DOMAINS_STOPPED_AND_NETWORKS_REMOVED',
          'profile_authority_invalid')
    roles = p['roles']
    _need(type(roles) is list and len(roles) == 4 and
          tuple(x.get('role') for x in roles if type(x) is dict) == ROLES,
          'roles_invalid')
    networks = set(EXPECTED_NETWORKS)
    for r in roles:
        _need(set(r) == {'role','domain','ip','port','interfaces'}, 'role_keys_invalid')
        _need(type(r['domain']) is str and SAFE_DOMAIN.fullmatch(r['domain']) and
              r['domain'] == 'ardrec-dev-' + r['role'], 'domain_invalid')
        if r['role'] == 'runner':
            _need(r['ip'] is None and r['port'] is None, 'runner_endpoint_forbidden')
        else:
            expected_port = {'ssh':22,'ftp':21,'smb':445}[r['role']]
            expected_ip = {'ssh':'10.203.30.2','ftp':'10.203.31.2',
                           'smb':'10.203.32.2'}[r['role']]
            _need(r['port'] == expected_port and type(r['port']) is int and
                  r['ip'] == expected_ip and type(r['ip']) is str, 'endpoint_invalid')
            ipaddress.IPv4Address(r['ip'])
        nics = r['interfaces']
        _need(type(nics) is list and len(nics) == (3 if r['role']=='runner' else 1),
              'interfaces_invalid')
        _need(len({x['network'] for x in nics if type(x) is dict}) == len(nics),
              'duplicate_network')
        for nic in nics:
            _need(type(nic) is dict and set(nic) == {'network','mac'} and
                  nic['network'] in networks and type(nic['mac']) is str and
                  HEX_MAC.fullmatch(nic['mac']) is not None, 'interface_invalid')
            _need(nic['network'] == ('ardrec-dev-'+r['role']) if r['role'] != 'runner'
                  else nic['network'] in networks, 'network_role_mismatch')
    return p, hashlib.sha256(raw).hexdigest()


def read_historical_evidence(path: Path) -> dict[str, Any]:
    source, raw = _read_json(path, limit=262144)
    guest = source.get('guest_checks')
    cleanup = source.get('cleanup')
    _need(source.get('status') == 'RECORDED_HOST_SERVICE_SMOKE_PASS'
          and type(guest) is dict and type(cleanup) is dict, 'history_not_expected')
    _need(cleanup.get('all_created_domains_stopped') is True and
          cleanup.get('created_networks_removed') is True and
          cleanup.get('dedicated_firewall_removed') is True, 'history_cleanup_not_verified')
    for role, ip in (('ssh','10.203.30.2'),('ftp','10.203.31.2'),
                     ('smb','10.203.32.2')):
        _need(type(guest.get(role)) is dict and guest[role].get('addresses') == [ip] and
              guest[role].get('default_routes') == 'ABSENT' and
              guest[role].get('forwarding') == 'DISABLED', 'history_guest_scope_invalid')
    _need(type(guest.get('runner')) is dict and
          guest['runner'].get('addresses') ==
          ['10.203.30.1','10.203.31.1','10.203.32.1'], 'history_runner_invalid')
    return {'source_sha256':hashlib.sha256(raw).hexdigest(),
            'historical_activation':source['status'],
            'historical_cleanup':'RECORDED_PASS_NOT_CURRENT',
            'historical_guest_checks':'RECORDED_PASS_NOT_CURRENT'}


def _safe_names(raw: str) -> set[str]:
    names = [x.strip() for x in raw.splitlines() if x.strip()]
    _need(len(names) <= 256 and len(names) == len(set(names)) and
          all(0 < len(n) <= 128 and not any(ch.isspace() for ch in n) for n in names),
          'libvirt_names_invalid')
    return set(names)


def _virsh(runner: Callable[..., Any], args: list[str]) -> str:
    _need(type(args) is list and args and args[0] in
          ('list','net-list','domuuid','domstate','dumpxml'), 'virsh_command_forbidden')
    argv = ['virsh','--readonly','--connect','qemu:///system',*args]
    try:
        done = runner(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                      stdin=subprocess.DEVNULL, timeout=5, check=False,
                      close_fds=True,
                      env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C','LANG':'C'})
    except (OSError, subprocess.TimeoutExpired) as error:
        raise VMPreflightError('virsh_unavailable_or_timeout') from error
    _need(type(done.returncode) is int and done.returncode == 0,
          'virsh_readonly_query_failed')
    raw = done.stdout
    _need(type(raw) is bytes and len(raw) <= MAX_XML_BYTES, 'virsh_output_excessive')
    try:
        return raw.decode('utf-8')
    except UnicodeError as error:
        raise VMPreflightError('virsh_output_not_utf8') from error


def _domain_xml(source: str, domain: str, expected: list[dict[str, str]],
                queried_uuid: str) -> tuple[bool, list[dict[str, str]]]:
    _need(len(source.encode('utf-8')) <= MAX_XML_BYTES and
          '<!DOCTYPE' not in source.upper() and '<!ENTITY' not in source.upper(),
          'domain_xml_unsafe')
    try:
        doc = ET.fromstring(source)
    except ET.ParseError as error:
        raise VMPreflightError('domain_xml_invalid') from error
    _need(doc.tag == 'domain' and doc.findtext('name') == domain and
          doc.findtext('uuid') == queried_uuid, 'domain_identity_mismatch')
    nics = []
    for iface in doc.findall('./devices/interface'):
        source = iface.find('source')
        mac = iface.find('mac')
        nics.append({'network':source.get('network','') if source is not None else '',
                     'mac':mac.get('address','') if mac is not None else '',
                     'type':iface.get('type','')})
    observed = sorted(nics, key=lambda x:(x['network'],x['mac']))
    expected_nics = sorted([{'network':x['network'],'mac':x['mac'],'type':'network'}
                            for x in expected], key=lambda x:(x['network'],x['mac']))
    return observed == expected_nics, observed


def collect(profile_path: Path, evidence_path: Path, *, observe: bool,
            runner: Callable[..., Any] = subprocess.run) -> dict[str, Any]:
    profile, profile_sha = read_profile(profile_path)
    history = read_historical_evidence(evidence_path)
    rows=[]
    names=set()
    nets=set()
    if observe:
        names=_safe_names(_virsh(runner,['list','--all','--name']))
        nets=_safe_names(_virsh(runner,['net-list','--all','--name']))
    for role in profile['roles']:
        entry={'role':role['role'],'domain':role['domain'],
               'historical_ipv4':role['ip'],'historical_port':role['port'],
               'state':'NOT_OBSERVED','layout_matches_historical':None,
               'uuid':None,'interfaces':[]}
        if observe:
            if role['domain'] not in names:
                entry['state']='ABSENT_FROM_LIBVIRT_LIST'
            else:
                id_raw=_virsh(runner,['domuuid',role['domain']]).strip()
                try:
                    parsed_uuid = str(uuid.UUID(id_raw))
                except (ValueError, AttributeError) as error:
                    raise VMPreflightError('domuuid_invalid') from error
                _need(parsed_uuid == id_raw.lower(), 'domuuid_not_canonical')
                state=_virsh(runner,['domstate',role['domain']]).strip()
                _need(state in ('running','shut off','paused','pmsuspended','in shutdown',
                                'crashed','blocked'), 'domstate_invalid')
                xml=_virsh(runner,['dumpxml','--inactive',role['domain']])
                matches, nics = _domain_xml(xml,role['domain'],role['interfaces'],parsed_uuid)
                entry.update(state='PRESENT_'+state.upper().replace(' ','_'),
                             layout_matches_historical=matches,
                             uuid=parsed_uuid,interfaces=nics)
        rows.append(entry)
    residuals=sorted(n for n in names if n.startswith('ardrec-') and
                     n not in {x['domain'] for x in profile['roles']})
    residual_networks=sorted(n for n in nets if n.startswith('ardrec-'))
    if not observe:
        summary='HISTORICAL_ONLY_NOT_CURRENT'
    elif any(r['state'].startswith('PRESENT_') for r in rows) or residuals or residual_networks:
        summary='ARDREC_DOMAINS_OR_NETWORKS_PRESENT_REVIEW_REQUIRED'
    else:
        summary='NO_NAMED_ARDREC_DOMAINS_OR_NETWORKS_IN_LIBVIRT_LIST'
    report={
       'schema':SCHEMA,'host':profile['host'],'profile_sha256':profile_sha,
       'historical':history,'libvirt_uri':profile['libvirt_uri'],
       'mode':'READONLY_LIBVIRT' if observe else 'HISTORICAL_ONLY',
       'host_metadata_observed':observe,'summary':summary,
       'roles':rows,'unrecognized_ardrec_domains':residuals,
       'ardrec_networks_listed':residual_networks,
       'guest_checks_executed':False,'vm_network_probes':False,
       'identity_accredited':False,'technical_truth_accredited':False,
       'operational_dispatch':False,'p8_operational':'NO-GO',
       'published_generation':None,'final_risk':None,
       'external_freshness_custody_verified':False,
    }
    report['sha256']=hashlib.sha256(canonical(report)).hexdigest()
    verify_report(report)
    return report


def verify_report(report: dict[str, Any]) -> bool:
    _need(type(report) is dict and type(report.get('sha256')) is str,
          'report_invalid')
    body={k:v for k,v in report.items() if k!='sha256'}
    _need(hashlib.sha256(canonical(body)).hexdigest()==report['sha256'],
          'report_digest_mismatch')
    _need(report.get('schema')==SCHEMA and report.get('p8_operational')=='NO-GO'
          and report.get('operational_dispatch') is False and
          report.get('guest_checks_executed') is False and
          report.get('vm_network_probes') is False and
          report.get('identity_accredited') is False and
          report.get('technical_truth_accredited') is False and
          report.get('external_freshness_custody_verified') is False and
          report.get('published_generation') is None and
          report.get('final_risk') is None, 'false_operational_claim')
    _need({x['role'] for x in report['roles']} == set(ROLES) and
          len(report['roles'])==4, 'report_roles_invalid')
    return True
