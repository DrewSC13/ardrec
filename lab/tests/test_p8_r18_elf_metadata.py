#!/usr/bin/env python3
"""P8-R18 synthetic ELF fixtures and fail-closed negative coverage; no VM."""
from __future__ import annotations
import copy
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

LAB=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(LAB))
import p8_r18_elf_metadata as m
import p8_r18_offline_collect as coll


def fixture(needed=('libcrypto.so.3','libc.so.6'),interp=b'/lib64/ld-linux-x86-64.so.2\x00'):
    b=bytearray(2048)
    b[:16]=b'\x7fELF\x02\x01\x01'+b'\0'*9
    struct.pack_into('<HHIQQQIHHHHHH',b,16,3,62,1,0,64,0,0,64,56,3,0,0,0)
    struct.pack_into('<IIQQQQQQ',b,64,1,5,0,0x400000,0,2048,2048,4096)
    struct.pack_into('<IIQQQQQQ',b,120,3,4,0x200,0x400200,0,len(interp),len(interp),1)
    b[0x200:0x200+len(interp)]=interp
    dyn=[];strtab=b'\x00';offs=[]
    for name in needed:
        offs.append(len(strtab));strtab+=name.encode()+b'\x00'
    for off in offs:dyn.append((1,off))
    dyn.extend(((5,0x400400),(10,len(strtab)),(0,0)))
    size=len(dyn)*16
    struct.pack_into('<IIQQQQQQ',b,176,2,4,0x300,0x400300,0,size,size,8)
    for i,(tag,val) in enumerate(dyn):struct.pack_into('<QQ',b,0x300+i*16,tag,val)
    b[0x400:0x400+len(strtab)]=strtab
    return bytes(b)


class TestElf(unittest.TestCase):
    def test_valid_metadata(self):
        z=fixture();e=m.inspect_elf(z)
        self.assertEqual(e['sha256'],hashlib.sha256(z).hexdigest())
        self.assertEqual(e['dt_needed_direct'],['libcrypto.so.3','libc.so.6'])
        self.assertEqual(e['interpreter'],'/lib64/ld-linux-x86-64.so.2')
        self.assertFalse(e['transitive_dependencies_resolved'])
        self.assertFalse(e['dynamic_loader_executed'])
        self.assertFalse(e['dispatch_allowed'])
    def test_determinism(self):
        self.assertEqual(m.inspect_elf(fixture()),m.inspect_elf(fixture()))
    def test_collect_safe_path_guard(self):
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(m.ElfEvidenceError):
                coll.private_destination(Path(t)/'receipt.json')
    def test_collect_guest_path_allowlist(self):
        with self.assertRaises(m.ElfEvidenceError):
            coll.virt_cat_read('/etc/shadow')
    def test_source_prohibits_guest_execution(self):
        p=(LAB/'p8_r18_offline_collect.py').read_text()
        self.assertNotIn('shell=True',p)
        self.assertNotIn('ssh -',p)
        self.assertNotIn('qemu-system-',p)
        self.assertNotIn('virsh start',p)


NEGATIVES=[
 ('wrong_magic',lambda x: x.__setitem__(0,0)),
 ('not_elf64',lambda x: x.__setitem__(4,1)),
 ('not_little',lambda x: x.__setitem__(5,2)),
 ('invalid_osabi',lambda x:x.__setitem__(7,255)),
 ('wrong_type',lambda x:struct.pack_into('<H',x,16,1)),
 ('wrong_machine',lambda x:struct.pack_into('<H',x,18,40)),
 ('bad_phnum',lambda x:struct.pack_into('<H',x,56,250)),
 ('bad_phentsize',lambda x:struct.pack_into('<H',x,54,48)),
 ('bad_phoff',lambda x:struct.pack_into('<Q',x,32,0xffffffffffffffff)),
 ('load_filesz_gt_memsz',lambda x:struct.pack_into('<Q',x,64+40,1)),
 ('no_interpreter',lambda x:struct.pack_into('<I',x,120,4)),
 ('bad_interpreter_termination',lambda x:x.__setitem__(0x200+len(b'/lib64/ld-linux-x86-64.so.2'),ord('x'))),
 ('relative_interpreter',lambda x:x.__setitem__(0x200,ord('a'))),
 ('duplicate_dynamic',lambda x:struct.pack_into('<I',x,120,2)),
 ('dynamic_size',lambda x:struct.pack_into('<Q',x,176+32,17)),
 ('strtab_unmapped',lambda x:struct.pack_into('<Q',x,0x300+32+8,0xffffffffffffffff)),
 ('no_needed',lambda x:(struct.pack_into('<Q',x,0x300,4), struct.pack_into('<Q',x,0x300+16,4))),
 ('strtab_too_large',lambda x:struct.pack_into('<Q',x,0x300+48+8,m.MAX_STRTAB+1)),
 ('bad_needed_offset',lambda x:struct.pack_into('<Q',x,0x300+8,10**6)),
 ('duplicate_needed',lambda x:struct.pack_into('<Q',x,0x300+16+8,1)),
]

def testcase(name, mutation):
    def test(self):
        data=bytearray(fixture())
        mutation(data)
        with self.assertRaises(m.ElfEvidenceError,msg=name):m.inspect_elf(bytes(data))
    return test

for i,(name,mutation) in enumerate(NEGATIVES):
    setattr(TestElf,f'test_negative_{i:02d}_{name}',testcase(name,mutation))


class TestUnsupported(unittest.TestCase):
    def test_not_bytes(self):
        with self.assertRaises(m.ElfEvidenceError):m.inspect_elf('not binary')
    def test_too_large(self):
        with self.assertRaises(m.ElfEvidenceError):m.inspect_elf(b'0'*(m.MAX_ELF_BYTES+1))
    def test_no_slashes_in_needed(self):
        with self.assertRaises(m.ElfEvidenceError):m.inspect_elf(fixture(needed=('../evil.so',)))
    def test_no_nonascii_needed(self):
        b=bytearray(fixture());b[0x401]=255
        with self.assertRaises(m.ElfEvidenceError):m.inspect_elf(bytes(b))
    def test_no_unterminated_name(self):
        b=bytearray(fixture());struct.pack_into('<Q',b,0x300+48+8,2)
        with self.assertRaises(m.ElfEvidenceError):m.inspect_elf(bytes(b))

if __name__=='__main__':unittest.main(verbosity=2)
