#!/usr/bin/env python3
"""ARDREC P8-R18: bounded offline ELF64 metadata inspection, no execution.

The ELF parser reads bytes, NEVER loads, executes, links or invokes a guest file.
DT_NEEDED strings are direct declarations, not resolved dependency closure.
"""
from __future__ import annotations

import hashlib
import re
import struct

MAX_ELF_BYTES = 8 * 1024 * 1024
MAX_PHDRS = 128
MAX_NEEDED = 96
MAX_STRTAB = 1024 * 1024
EXPECTED_SONAMES = {'ssh', 'curl', 'smbclient'}


class ElfEvidenceError(ValueError):
    pass


def need(ok, why):
    if not ok:
        raise ElfEvidenceError('P8_R18_FAIL_CLOSED:' + why)


def span(data, off, length, where):
    need(type(off) is int and type(length) is int and off >= 0 and
         length >= 0 and off <= len(data) and length <= len(data) - off,
         'bounds:' + where)
    return data[off:off + length]


def inspect_elf(data: bytes):
    """Extract PT_INTERP, direct DT_NEEDED, DT_RPATH/RUNPATH from x86_64 ELF64."""
    need(type(data) is bytes and 64 <= len(data) <= MAX_ELF_BYTES, 'elf_size')
    need(data[:4] == b'\x7fELF' and data[4:7] == b'\x02\x01\x01', 'elf_magic_class_endian_version')
    need(data[7] in (0, 3) and data[8:16] == b'\x00' * 8, 'elf_ident')
    header = struct.unpack_from('<HHIQQQIHHHHHH', data, 16)
    kind, machine, version, _, phoff, _, _, ehsize, phentsize, phnum, _, _, _ = header
    need(kind in (2, 3) and machine == 62 and version == 1 and ehsize == 64,
         'elf_architecture_type')
    need(phentsize == 56 and 1 <= phnum <= MAX_PHDRS, 'elf_phdr_shape')
    span(data, phoff, phentsize * phnum, 'program_headers')
    loads, dynamics, interps = [], [], []
    for idx in range(phnum):
        typ, flags, off, addr, _, size, memsize, align = struct.unpack_from(
            '<IIQQQQQQ', data, phoff + idx * phentsize)
        span(data, off, size, 'segment')
        if typ == 1:
            need(memsize >= size, 'load_filesz_exceeds_memsz')
            loads.append((addr, size, off))
        if typ == 2:
            dynamics.append((off, size))
        if typ == 3:
            interps.append((off, size))
    need(len(loads) >= 1 and len(dynamics) == 1 and len(interps) == 1,
         'required_program_headers')
    interp_off, interp_len = interps[0]
    need(2 <= interp_len <= 256, 'interpreter_size')
    rawinterp = span(data, interp_off, interp_len, 'interpreter')
    need(rawinterp.endswith(b'\x00') and b'\x00' not in rawinterp[:-1],
         'interpreter_termination')
    try:
        interp = rawinterp[:-1].decode('ascii')
    except UnicodeError as exc:
        raise ElfEvidenceError('P8_R18_FAIL_CLOSED:interpreter_encoding') from exc
    need(interp.startswith('/') and re.fullmatch(r'/[A-Za-z0-9._+/\-]+', interp)
         and '..' not in interp.split('/'), 'interpreter_path')
    dyn_off, dyn_len = dynamics[0]
    need(16 <= dyn_len <= 65536 and dyn_len % 16 == 0,
         'dynamic_table_shape')
    entries = [struct.unpack_from('<QQ', data, dyn_off + i * 16)
               for i in range(dyn_len // 16)]
    ends = [i for i, (tag, _) in enumerate(entries) if tag == 0]
    need(len(ends) > 0, 'dynamic_null_terminator')
    entries = entries[:ends[0]]
    tags = {}
    for tag, val in entries:
        tags.setdefault(tag, []).append(val)
    need(len(tags.get(5, [])) == 1 and len(tags.get(10, [])) == 1,
         'strtab_pointer_and_size')
    straddr, strsz = tags[5][0], tags[10][0]
    need(1 <= strsz <= MAX_STRTAB, 'strtab_size')
    strfile = None
    for vaddr, filesz, fileoff in loads:
        if vaddr <= straddr and straddr - vaddr <= filesz and strsz <= filesz - (straddr - vaddr):
            need(strfile is None, 'ambiguous_strtab_load')
            strfile = fileoff + straddr - vaddr
    need(strfile is not None, 'strtab_unmapped')
    strtab = span(data, strfile, strsz, 'string_table')

    def dynstr(offset, label, slashes=False):
        need(type(offset) is int and offset < len(strtab), 'strtab_index:' + label)
        end = strtab.find(b'\x00', offset)
        need(end > offset and 0 < end - offset <= 255, 'strtab_string:' + label)
        try:
            value = strtab[offset:end].decode('ascii')
        except UnicodeError as exc:
            raise ElfEvidenceError('P8_R18_FAIL_CLOSED:encoding:' + label) from exc
        pattern = r'[A-Za-z0-9_+.@\-/:$]+' if slashes else r'[A-Za-z0-9_+.@\-]+'
        need(re.fullmatch(pattern, value) is not None, 'symbols:' + label)
        return value

    offsets = tags.get(1, [])
    need(1 <= len(offsets) <= MAX_NEEDED, 'needed_count')
    needed = [dynstr(v, 'needed') for v in offsets]
    need(len(set(needed)) == len(needed), 'duplicate_needed')
    for key, label in ((15, 'rpath'), (29, 'runpath')):
        need(len(tags.get(key, [])) <= 1, 'duplicate_' + label)
    rpath = dynstr(tags[15][0], 'rpath', True) if 15 in tags else None
    runpath = dynstr(tags[29][0], 'runpath', True) if 29 in tags else None
    return {'elf_class': 'ELF64', 'machine': 'EM_X86_64', 'endian': 'LITTLE',
            'elf_type': 'ET_DYN' if kind == 3 else 'ET_EXEC',
            'interpreter': interp, 'dt_needed_direct': needed,
            'dt_rpath': rpath, 'dt_runpath': runpath,
            'file_bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'transitive_dependencies_resolved': False,
            'dynamic_loader_executed': False,
            'runtime_identity_verified': False, 'dispatch_allowed': False}
