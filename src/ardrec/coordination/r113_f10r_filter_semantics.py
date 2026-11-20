"""Semantic comparison for the exact six ARDREC F10 libvirt nwfilters.

Only the libvirt-generated root UUID and the default root chain attribute
may be ignored. All filter rules, attributes, child order and text remain pinned.
"""
from __future__ import annotations
import xml.etree.ElementTree as ET


class FilterMismatch(ValueError):
    pass


def semantically_identical(expected: bytes, live: bytes, *, expected_name: str) -> bool:
    if not isinstance(expected, bytes) or not isinstance(live, bytes):
        raise FilterMismatch('XML_MUST_BE_BYTES')
    if not 0 < len(expected) < 250_000 or not 0 < len(live) < 250_000:
        raise FilterMismatch('XML_SIZE_INVALID')
    try:
        a = ET.fromstring(expected)
        b = ET.fromstring(live)
    except ET.ParseError as exc:
        raise FilterMismatch('XML_NOT_PARSEABLE') from exc
    if a.tag != 'filter' or b.tag != 'filter':
        raise FilterMismatch('ROOT_NOT_FILTER')
    if a.get('name') != expected_name or b.get('name') != expected_name:
        raise FilterMismatch('FILTER_IDENTITY_CHANGED')
    if a.find('./uuid') is not None:
        raise FilterMismatch('CANDIDATE_UUID_FORBIDDEN')
    live_uuids = [item for item in b if item.tag == 'uuid']
    if len(live_uuids) > 1:
        raise FilterMismatch('MULTIPLE_UUIDS')
    for item in live_uuids:
        b.remove(item)
    # Libvirt inserts chain="root" for filters whose XML omits the default.
    # Reject any other addition/change at this position.
    if 'chain' not in a.attrib and b.get('chain') == 'root':
        del b.attrib['chain']

    def canonical(node: ET.Element):
        return (node.tag, tuple(sorted(node.attrib.items())),
                (node.text or '').strip(), (node.tail or '').strip(),
                tuple(canonical(child) for child in node))

    return canonical(a) == canonical(b)
