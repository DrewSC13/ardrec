import base64
import json
import unittest
from copy import deepcopy

from ardrec.coordination import r114_f1_real_receipt as c

SSH='5353482d322e302d4f70656e5353485f31302e3070322044656269616e2d372b646562313375340d0a'
FTP='323230202876734654506420332e302e35290d0a'


def fixture():
    rows=[]
    for role,src,dst,port in c.ROLES:
        value=SSH if role=='ssh' else FTP if role=='ftp' else ''
        rows.append({'role':role,'src':src,'dst':dst,'port':port,
                     'tcp':'CONNECTED','response_hex':value,
                     'protocol':'BANNER_RECEIVED' if role!='smb' else 'UNVERIFIED_RESPONSE'})
    payload=c.canonical({'schema':'ARDREC-R113-F10-THREE-BOUNDED-PROBES-v1','results':rows})
    qga=c.canonical({'return':{'exited':True,'exitcode':0,'out-data':base64.b64encode(payload).decode(),'err-data':''}})
    nft=c.canonical({'nftables':[{'rule':{'expr':[{'accept':None}]}} for _ in range(12)]+[{'rule':{'expr':[{'drop':None}]}} for _ in range(4)]})
    raw={
        'runner-probe-stdout.json':payload,
        'qga_status_1.stdout':qga,
        'f6_restore_final.stdout':c.canonical({'result':'SIX_BINDING_DENY_RESTORED','nft_deny_verified':True,'traffic_allowed':False,'bindings':6,'p8':'NO-GO'}),
        'f6_attest_final.stdout':c.canonical({'result':'SIX_BINDING_DENY_ATTESTED','bindings':6,'host_writes':0,'p8':'NO-GO'}),
        'timer_active.stdout':b'LoadState=loaded\nActiveState=active\n',
        'nft_live_check.stdout':nft,
    }
    raw['receipt.json']=c.canonical({'schema':'ARDREC-R113-F10R-ROOT-EVENT-v1',
        'status':'CLOSED_DENY_WITH_REAL_PROBES','traffic_scope':'THREE_FIXED_PRIVATE_TCP_PORTS',
        'p8':'NO-GO','files':{name:c.digest(value) for name,value in raw.items()}})
    return raw

def review(raw):
    return c.analyze(raw,expected_receipt_sha=c.digest(raw['receipt.json']))

class RealReceiptContract(unittest.TestCase):
    def test_real_receipt_reference_is_pinned(self):
        self.assertEqual(len(c.F10R_RECEIPT_SHA),64)
        self.assertEqual(c.F10R_RECEIPT_SHA,'8aecaaccafca822da5204aedd781bc64af44c79afa38e8ca1e091eadd6ea5363')

    def test_valid_fixture_only_for_unit_tests(self):
        r=review(fixture())
        self.assertEqual(r['counts'],{'tcp_connections':3,'verified_banners':2,'verified_smb2':0,'a5_case_bound':0,'a6_conditions_admitted':0})
        self.assertFalse(r['risk_recalculation_performed'])
        self.assertIsNone(r['confirmed_final_risk'])

    def test_ssh_is_verified_as_banner_only(self):
        r=review(fixture())
        self.assertEqual(r['observations'][0]['protocol_observation'],'SSH_IDENTIFICATION_BANNER_OBSERVED')
        self.assertFalse(r['observations'][0]['verified_vulnerability'])

    def test_ftp_is_verified_as_220_greeting_only(self):
        r=review(fixture())
        self.assertEqual(r['observations'][1]['protocol_observation'],'FTP_220_CONTROL_GREETING_OBSERVED')

    def test_smb_tcp_not_smb2(self):
        r=review(fixture())
        self.assertEqual(r['observations'][2]['protocol_observation'],'SMB_TCP_CONNECTED_NO_SMB2_RESPONSE_VERIFIED')
        self.assertEqual(r['observations'][2]['response_length'],0)

    def test_wrong_receipt_hash(self):
        with self.assertRaisesRegex(c.EvidenceError,'ROOT_RECEIPT_HASH_CHANGED'):
            c.analyze(fixture())

    def test_missing_raw_file(self):
        x=fixture();del x['qga_status_1.stdout']
        with self.assertRaisesRegex(c.EvidenceError,'SOURCE_SCOPE_INVALID'):review(x)

    def test_unlisted_raw_file(self):
        x=fixture();x['intruder']=b'x'
        with self.assertRaisesRegex(c.EvidenceError,'SOURCE_SCOPE_INVALID'):review(x)

    def test_source_byte_tamper(self):
        x=fixture();x['runner-probe-stdout.json']+=b' '
        with self.assertRaisesRegex(c.EvidenceError,'ROOT_SOURCE_HASH_CHANGED'):review(x)

    def test_qga_mismatch_not_a_valid_observation(self):
        x=fixture();x['qga_status_1.stdout']=c.canonical({'return':{'exited':True,'exitcode':0,'out-data':base64.b64encode(b'{}').decode()}})
        self._resign(x)
        with self.assertRaisesRegex(c.EvidenceError,'QGA_OUT_OF_SYNC'):review(x)

    def test_qga_nonzero_rejected(self):
        x=fixture(); q=json.loads(x['qga_status_1.stdout']);q['return']['exitcode']=3
        x['qga_status_1.stdout']=c.canonical(q);self._resign(x)
        with self.assertRaisesRegex(c.EvidenceError,'QGA_NOT_SUCCESSFUL'):review(x)

    def test_qga_stderr_rejected(self):
        x=fixture();q=json.loads(x['qga_status_1.stdout']);q['return']['err-data']=base64.b64encode(b'error').decode()
        x['qga_status_1.stdout']=c.canonical(q);self._resign(x)
        with self.assertRaisesRegex(c.EvidenceError,'QGA_OUT_OF_SYNC'):review(x)

    def test_target_changed_rejected(self):
        x=fixture();guest=json.loads(x['runner-probe-stdout.json']);guest['results'][2]['dst']='192.168.1.1'
        self._replace_probe(x,guest)
        with self.assertRaisesRegex(c.EvidenceError,'RUNNER_TARGET_IDENTITY_INVALID'):review(x)

    def test_bad_ssh_banner_rejected(self):
        x=fixture();guest=json.loads(x['runner-probe-stdout.json']);guest['results'][0]['response_hex']='48656c6c6f0d0a'
        self._replace_probe(x,guest)
        with self.assertRaisesRegex(c.EvidenceError,'SSH_BANNER_NOT_VERIFIED'):review(x)

    def test_bad_ftp_greeting_rejected(self):
        x=fixture();guest=json.loads(x['runner-probe-stdout.json']);guest['results'][1]['response_hex']='353030204552524f520d0a'
        self._replace_probe(x,guest)
        with self.assertRaisesRegex(c.EvidenceError,'FTP_CONTROL_GREETING_NOT_VERIFIED'):review(x)

    def test_smb_must_remain_unverified(self):
        x=fixture();guest=json.loads(x['runner-probe-stdout.json']);guest['results'][2]['protocol']='SMB2_REPLY'
        self._replace_probe(x,guest)
        with self.assertRaisesRegex(c.EvidenceError,'SMB_RESULT_NOT_AS_RECORDED'):review(x)

    def test_smb_bytes_must_remain_empty(self):
        x=fixture();guest=json.loads(x['runner-probe-stdout.json']);guest['results'][2]['response_hex']='fe534d42'
        self._replace_probe(x,guest)
        with self.assertRaisesRegex(c.EvidenceError,'SMB_RESULT_NOT_AS_RECORDED'):review(x)

    def test_f6_restore_fail_closed(self):
        x=fixture();val=json.loads(x['f6_restore_final.stdout']);val['traffic_allowed']=True
        x['f6_restore_final.stdout']=c.canonical(val);self._resign(x)
        with self.assertRaisesRegex(c.EvidenceError,'F6_RESTORE_INVALID'):review(x)

    def test_f6_attest_fail_closed(self):
        x=fixture();val=json.loads(x['f6_attest_final.stdout']);val['bindings']=5
        x['f6_attest_final.stdout']=c.canonical(val);self._resign(x)
        with self.assertRaisesRegex(c.EvidenceError,'F6_FINAL_DENY_INVALID'):review(x)

    def test_watchdog_must_have_been_armed(self):
        x=fixture();x['timer_active.stdout']=b'ActiveState=inactive\n';self._resign(x)
        with self.assertRaisesRegex(c.EvidenceError,'TIMER_WAS_NOT_ARMED'):review(x)

    def test_nft_rule_counts(self):
        x=fixture();n=json.loads(x['nft_live_check.stdout']);n['nftables'].pop()
        x['nft_live_check.stdout']=c.canonical(n);self._resign(x)
        with self.assertRaisesRegex(c.EvidenceError,'NFT_SCOPED_WINDOW_NOT_PROVEN'):review(x)

    def test_evidence_not_a6(self):
        self.assertTrue(all(x['a6_condition']=='ND_NO_DECLARED_FAMILY_CONDITION' for x in review(fixture())['observations']))

    def test_reproducible_report(self):
        x=fixture();r=review(x)
        c.verified_report(r,x,expected_receipt_sha=c.digest(x['receipt.json']))

    def test_tampered_report_is_rejected(self):
        x=fixture();r=review(x);r['counts']['verified_smb2']=1
        with self.assertRaisesRegex(c.EvidenceError,'REPORT_NOT_REPRODUCIBLE'):
            c.verified_report(r,x,expected_receipt_sha=c.digest(x['receipt.json']))

    @staticmethod
    def _resign(raw):
        r=json.loads(raw['receipt.json'])
        r['files']={name:c.digest(data) for name,data in raw.items() if name!='receipt.json'}
        raw['receipt.json']=c.canonical(r)
    @classmethod
    def _replace_probe(cls,raw,guest):
        payload=c.canonical(guest)
        raw['runner-probe-stdout.json']=payload
        q=json.loads(raw['qga_status_1.stdout'])
        q['return']['out-data']=base64.b64encode(payload).decode()
        raw['qga_status_1.stdout']=c.canonical(q)
        cls._resign(raw)

if __name__=='__main__':unittest.main()
