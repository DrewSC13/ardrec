"""R116-F3: strict one-shot FTP-T01 pilot session budget and interlock.

No host operations. Physical execution requires a separately staged, audited,
root-owned dispatcher, independent Ed25519 authorization and an armed DENY
watchdog. This module never grants ordinary P8 access or accepts A6 evidence.
"""
from __future__ import annotations
from datetime import datetime, timezone
import re

SCHEMA='ARDREC-R116-F3-FTP-T01-ROOT-SESSION-v1'
TARGET={'ip':'10.203.31.2','port':21}
SRC='10.203.31.1'
MAX_WINDOW=60
MIN_MARGIN=25
MAX_RECV=256
MAX_ATTEMPTS=1
ALLOWED_BINDINGS=('ftp','runner_ftp','runner_smb','runner_ssh','ssh')

class Stop(ValueError):pass

def need(condition,code):
    if not condition:raise Stop(code)

def timestamp(now):
    need(isinstance(now,datetime) and now.tzinfo is not None and
         now.utcoffset() is not None,'AWARE_CLOCK_REQUIRED')
    return now.astimezone(timezone.utc)

def session_id(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{16}',value) is not None,
         'SESSION_ID_NOT_16_HEX')
    return value

def signed_grant(review, *, head, catalog_sha, now, permit_expiry):
    """Document verification is mandatory, but not sufficient alone."""
    timestamp(now)
    need(type(review) is dict and review.get('document_status')=='DOCUMENT_SIGNED',
         'INDEPENDENT_PILOT_NOT_SIGNED')
    need(review.get('head')==head and review.get('catalog_sha256')==catalog_sha and
         review.get('family_id')=='FTP-T01','SIGNED_SCOPE_NOT_CURRENT')
    need(review.get('physical_pilot_session_attested') is False and
         review.get('authorized_to_connect_by_module') is False and
         review.get('p8')=='NO-GO' and review.get('a6')=='ND',
         'DOCUMENT_MISREPRESENTS_OPERATIONAL_GO')
    b=review.get('budget')
    need(type(b) is dict and all(type(x) is int for x in b.values()),
         'BUDGET_NOT_INTEGER')
    required={'max_connections','ordinary_attempts','additional_attempts',
              'timeout_seconds','max_recv_bytes','max_recv_calls','max_lines',
              'read_size','max_output_bytes','memory_mib'}
    need(required<=set(b),'BUDGET_FIELDS_MISSING')
    need(b['max_connections']==1 and b['ordinary_attempts']==1 and
         b['additional_attempts']==0 and 0<b['timeout_seconds']<=10 and 0<b['max_recv_bytes']<=4096 and
         0<b['max_recv_calls']<=16 and 0<b['read_size']<=512 and
         0<b['max_lines']<=16 and 0<b['max_output_bytes']<=8192 and
         0<b['memory_mib']<=512 and b['read_size']<=b['max_recv_bytes'] and
         b['max_recv_calls']*b['read_size']>=b['max_recv_bytes'],
         'BUDGET_EXCEEDS_PILOT')
    need(type(permit_expiry) is datetime and timestamp(now)<timestamp(permit_expiry),
         'PILOT_EXPIRED')
    return {'schema':SCHEMA+'-signed-review',
            'head':head,'pilot_sha256':review['pilot_sha256'],
            'scope_sha256':review['scope_authorization_sha256'],
            'budget':b,'p8':'NO-GO','a6':'ND'}

def five_one(readback):
    need(type(readback) is dict and readback.get('deny')=='MATCH' and
         readback.get('p8')=='NO-GO' and readback.get('host_writes')==0,
         'ROOT_DENY_READBACK_NOT_VALID')
    states={'ssh':'RUNNING','runner':'RUNNING','ftp':'RUNNING','smb':'OFF'}
    p=readback.get('policy')
    need(readback.get('states')==states and type(p) is dict and
         p.get('active')==list(ALLOWED_BINDINGS) and p.get('absent')==['smb'] and
         p.get('active_count')==5 and p.get('absent_count')==1 and
         p.get('allow_traffic') is False and p.get('p8')=='NO-GO',
         'LIVE_FIVE_ONE_DENY_MISMATCH')
    return True

def timer_remaining(properties, *, monotonic_seconds, expected_unit):
    """systemd's monotonic deadline must be sufficiently in the future."""
    need(type(properties) is dict and properties.get('LoadState')=='loaded' and
         properties.get('ActiveState')=='active' and
         properties.get('Unit')==expected_unit+'.service',
         'AUTONOMOUS_DENY_TIMER_NOT_ACTIVE')
    token=properties.get('NextElapseUSecMonotonic')
    need(type(token) is str and re.fullmatch('[1-9][0-9]{0,19}',token) is not None,
         'DENY_TIMER_DEADLINE_UNKNOWN')
    need(type(monotonic_seconds) in (int,float) and monotonic_seconds>=0,
         'MONOTONIC_CLOCK_INVALID')
    # Leave a generous margin for guest probe, external watchdog, and restoration.
    delta=int(token)/1_000_000-float(monotonic_seconds)
    need(MIN_MARGIN<=delta<=MAX_WINDOW+3, 'DENY_TIMER_MARGIN_UNSAFE')
    return delta

def permit_margin(*, now, permit_expiry, timer_seconds):
    remain=(timestamp(permit_expiry)-timestamp(now)).total_seconds()
    need(type(timer_seconds) in (int,float) and timer_seconds>=MIN_MARGIN,
         'TIMER_NOT_ENOUGH_TIME')
    need(remain>=MIN_MARGIN,'SIGNED_WINDOW_NOT_ENOUGH_TIME')
    return min(remain,timer_seconds)

def candidate_rules(raw):
    """Narrow prior R114 policy syntax; never accepts a global allow."""
    need(type(raw) is bytes and len(raw)<4096,'NFT_CANDIDATE_SIZE')
    lines=raw.splitlines(keepends=True)
    need(len(lines)==9 and lines[0]==b'flush table bridge ardrec_r34_guard\n',
         'NFT_CANDIDATE_STRUCTURE')
    accepts=lines[1:5];drops=lines[5:]
    need(all(x.startswith(b'add rule bridge ardrec_r34_guard forward ') and
             b' counter accept\n' in x and b'a33d31' in x and
             (b'a33d31r' in x and b'a33d31t' in x) and
             b'a33d30' not in x and b'a33d32' not in x and
             b'10.203.31.1' in x and b'10.203.31.2' in x
             for x in accepts),'NFT_FTP_ONLY_ACCEPT_RULES')
    need(sum(b'ether type arp ' in x for x in accepts)==2 and
         sum(b'ip protocol tcp ' in x for x in accepts)==2 and
         all(b'tcp dport 21 ' in x or b'tcp sport 21 ' in x or b'ether type arp ' in x
             for x in accepts), 'NFT_FTP_PROTOCOL_OR_PORT')
    need(all(x.startswith(b'add rule bridge ardrec_r34_guard ') and
             b' counter drop\n' in x and b'accept' not in x
             for x in drops),'NFT_DEFAULT_DROP_CHANGED')
    return True

def capabilities():
    return {'schema':SCHEMA+'-capabilities','family_id':'FTP-T01',
            'root_source_staging_required':True,'independent_ed25519_required':True,
            'root_five_one_deny_required':True,'one_attempt':True,
            'autonomous_recovery_60s':True,'ordinary_p8':'NO-GO',
            'a6':'ND','installs_or_arms_automatically':False}
