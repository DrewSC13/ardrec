#!/usr/bin/env python3
"""Ephemeral-key synthetic Ed25519 witness demo; no real provenance or VM calls."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

REPO=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(REPO/'src'))
sys.path.insert(0,str(REPO))
from ardrec.analytics.exact_preview import canonical
from ardrec.coordination.r58f_signed_bridge import build_signed_bridge,verify_signed_bridge
from ardrec.evidence.r58f_signed_witness import SCHEMA,signing_bytes
from scripts.ardrec_p14_r58e_unit_bridge import synthetic_units

OPENSSL='/usr/bin/openssl'
AS_OF='2026-11-16T12:00:00Z'

def _run(args):
    cp=subprocess.run([OPENSSL,*args],stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
                      stderr=subprocess.PIPE,timeout=6,check=False)
    if cp.returncode: raise ValueError('SYNTHETIC_KEY_OPERATION_FAILED')

def build_demo():
    units=synthetic_units()
    ssh=next(u for u in units if u['service_id']=='SSH_DEV')
    support=b'ARDREC R58-F synthetic observational support only\n'
    stmt={'schema':SCHEMA,'record_id':'R58F_SYNTH_001',
          'session_id':'DEV_TUTOR_001','service_id':'SSH_DEV',
          'case_id':ssh['case_id'],'assessment_index':ssh['assessment_index'],
          'configuration_sha256':'a'*64,
          'captured_at_utc':'2026-11-16T11:59:00Z',
          'method_id':'SSH_EFFECTIVE_CONFIG_READONLY',
          'observed_claim':'INCONCLUSIVE','support_sha256':hashlib.sha256(support).hexdigest(),
          'support_bytes':len(support)}
    signatures={};trust={}
    with tempfile.TemporaryDirectory(prefix='ardrec-r58f-demo-') as folder:
        root=Path(folder)
        msg=root/'message.bin';msg.write_bytes(signing_bytes(stmt))
        for role in ('observer','reviewer'):
            private=root/(role+'.private.pem');public=root/(role+'.public.pem')
            signature=root/(role+'.sig')
            _run(['genpkey','-algorithm','ED25519','-out',str(private)])
            private.chmod(0o600)
            _run(['pkey','-in',str(private),'-pubout','-out',str(public)])
            _run(['pkeyutl','-sign','-inkey',str(private),'-rawin',
                  '-in',str(msg),'-out',str(signature)])
            keyid='SYNTH_'+role.upper()
            trust[role]={'key_id':keyid,'public_key_pem':public.read_bytes()}
            signatures[role]={'key_id':keyid,
                              'signature_b64':base64.b64encode(signature.read_bytes()).decode('ascii')}
        bindings={(u['service_id'],u['case_id'],u['assessment_index']):'a'*64 for u in units}
        bundle={'statement':stmt,'signatures':signatures,'support':support}
        report=build_signed_bridge(units,[bundle],configuration_hashes=bindings,
                                   trusted_authorities=trust,as_of_utc=AS_OF)
        assert verify_signed_bridge(report,units,[bundle],configuration_hashes=bindings,
                                    trusted_authorities=trust,as_of_utc=AS_OF)
    return report

def main()->int:
    parser=argparse.ArgumentParser()
    parser.add_argument('--synthetic-offline',action='store_true',required=True)
    args=parser.parse_args()
    if not args.synthetic_offline:return 23
    report=build_demo()
    print(json.dumps(report,indent=2,sort_keys=True))
    return 0

if __name__=='__main__':raise SystemExit(main())
