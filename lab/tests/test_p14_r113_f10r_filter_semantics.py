import unittest
from pathlib import Path
from ardrec.coordination.r113_f10r_filter_semantics import semantically_identical as same, FilterMismatch

N = 'ardrec-r113-runner-ssh-tcp-v1'
BASE = "<filter name='"+N+"'><rule action='accept' direction='out' priority='1'><arp arpsrcipaddr='10.203.30.1' arpdstipaddr='10.203.30.2'/></rule><rule action='drop' direction='inout' priority='999'><all/></rule></filter>"
LIVE = BASE.replace("<filter name='"+N+"'>", "<filter name='"+N+"' chain='root'><uuid>27d80da7-ea0c-4d3a-b7fa-6ad75d4e721a</uuid>")

def eq(a=BASE,b=LIVE,n=N):
    return same(a.encode(),b.encode(),expected_name=n)

class F10RSemantics(unittest.TestCase):
    def test_01_expected_lived_root_default(self): self.assertTrue(eq())
    def test_02_identical_no_insertions(self): self.assertTrue(eq(BASE,BASE))
    def test_03_uuid_only(self): self.assertTrue(eq(BASE, LIVE.replace(" chain='root'",'')))
    def test_04_root_chain_only(self): self.assertTrue(eq(BASE,LIVE.replace('<uuid>27d80da7-ea0c-4d3a-b7fa-6ad75d4e721a</uuid>','')))
    def test_05_attribute_order_irrelevant(self): self.assertTrue(eq(BASE,LIVE.replace("action='accept' direction='out'", "direction='out' action='accept'")))
    def test_06_xml_layout_whitespace_irrelevant(self): self.assertTrue(eq(BASE.replace('><','>\n<'),LIVE.replace('><','>  \n<')))
    def test_07_real_filter_name_required(self):
        with self.assertRaisesRegex(FilterMismatch,'FILTER_IDENTITY_CHANGED'): eq(n='some-other-filter')
    def test_08_changed_rule_action_rejected(self): self.assertFalse(eq(BASE,LIVE.replace("action='accept'", "action='drop'")))
    def test_09_changed_rule_direction_rejected(self): self.assertFalse(eq(BASE,LIVE.replace("direction='out'","direction='in'")))
    def test_10_changed_rule_priority_rejected(self): self.assertFalse(eq(BASE,LIVE.replace("priority='1'","priority='2'")))
    def test_11_changed_arp_source_rejected(self): self.assertFalse(eq(BASE,LIVE.replace('10.203.30.1','10.203.30.9')))
    def test_12_changed_arp_destination_rejected(self): self.assertFalse(eq(BASE,LIVE.replace('10.203.30.2','10.203.30.3')))
    def test_13_root_chain_nonroot_rejected(self): self.assertFalse(eq(BASE,LIVE.replace("chain='root'","chain='ipv4'")))
    def test_14_other_root_attribute_rejected(self): self.assertFalse(eq(BASE,LIVE.replace("chain='root'", "chain='root' priority='3'")))
    def test_15_insert_rule_rejected(self): self.assertFalse(eq(BASE,LIVE.replace('</filter>',"<rule action='accept'><all/></rule></filter>")))
    def test_16_remove_rule_rejected(self): self.assertFalse(eq(BASE,LIVE.replace("<rule action='drop' direction='inout' priority='999'><all/></rule>",'')))
    def test_17_swap_rule_order_rejected(self):
        x="<rule action='accept' direction='out' priority='1'><arp arpsrcipaddr='10.203.30.1' arpdstipaddr='10.203.30.2'/></rule>"
        y="<rule action='drop' direction='inout' priority='999'><all/></rule>"
        self.assertFalse(eq(BASE,LIVE.replace(x+y,y+x)))
    def test_18_change_protocol_rejected(self): self.assertFalse(eq(BASE,LIVE.replace('<arp ','<tcp ')))
    def test_19_added_child_rejected(self): self.assertFalse(eq(BASE,LIVE.replace('</filter>','<filterref filter="other"/></filter>')))
    def test_20_added_child_text_rejected(self): self.assertFalse(eq(BASE,LIVE.replace('<all/>','<all>text</all>')))
    def test_21_added_rule_tail_rejected(self): self.assertFalse(eq(BASE,LIVE.replace('</rule>','</rule>BAD',1)))
    def test_22_duplicate_uuid_rejected(self):
        with self.assertRaisesRegex(FilterMismatch,'MULTIPLE_UUIDS'): eq(BASE,LIVE.replace('</uuid>','</uuid><uuid>other</uuid>'))
    def test_23_candidate_uuid_forbidden(self):
        with self.assertRaisesRegex(FilterMismatch,'CANDIDATE_UUID_FORBIDDEN'): eq(BASE.replace('<rule','<uuid>hi</uuid><rule',1), LIVE)
    def test_24_invalid_live_xml_rejected(self):
        with self.assertRaisesRegex(FilterMismatch,'XML_NOT_PARSEABLE'): eq(BASE,'<filter')
    def test_25_non_filter_root_rejected(self):
        with self.assertRaisesRegex(FilterMismatch,'ROOT_NOT_FILTER'): eq(BASE,'<other/>')
    def test_26_empty_expected_rejected(self):
        with self.assertRaisesRegex(FilterMismatch,'XML_SIZE_INVALID'): same(b'',LIVE.encode(),expected_name=N)
    def test_27_empty_live_rejected(self):
        with self.assertRaisesRegex(FilterMismatch,'XML_SIZE_INVALID'): same(BASE.encode(),b'',expected_name=N)
    def test_28_non_bytes_rejected(self):
        with self.assertRaisesRegex(FilterMismatch,'XML_MUST_BE_BYTES'): same(BASE,LIVE.encode(),expected_name=N)
    def test_29_authentic_default_chain_if_explicit(self):
        a=BASE.replace("<filter name='"+N+"'>", "<filter name='"+N+"' chain='root'>")
        self.assertTrue(eq(a,LIVE))
    def test_30_mismatch_explicit_chain_rejected(self):
        a=BASE.replace("<filter name='"+N+"'>", "<filter name='"+N+"' chain='ipv4'>")
        self.assertFalse(eq(a,LIVE))

if __name__=='__main__': unittest.main()
