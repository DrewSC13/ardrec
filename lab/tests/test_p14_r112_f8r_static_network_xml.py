"""R112-F8R: regresiones unitarias del XML estático, no pruebas físicas."""
import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "src/ardrec/coordination/r112_f8_ssh_positive_boot.py"

def normalizer():
    module = ast.parse(SOURCE.read_text())
    nodes = [
        node for node in module.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_r112_f8_static_network_xml"
    ]
    if len(nodes) != 1:
        raise AssertionError("NORMALIZER_NOT_FOUND")
    code = compile(
        ast.Module(body=nodes, type_ignores=[]),
        str(SOURCE), "exec"
    )
    namespace = {}
    exec(code, namespace)
    return namespace["_r112_f8_static_network_xml"]

class StaticXMLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.norm = staticmethod(normalizer())

    def setUp(self):
        self.base = (
            '<network><name>net</name><uuid>uuid-1</uuid>'
            '<bridge name="br1"/><mac address="52:54:00:00:00:01"/>'
            '<dns enable="no"/></network>'
        )

    def test_runtime_connections_equivalent(self):
        dynamic = self.base.replace(
            "<network>", '<network connections="1">'
        )
        self.assertEqual(self.norm(self.base), self.norm(dynamic))

    def test_runtime_connections_zero_equivalent(self):
        dynamic = self.base.replace(
            "<network>", '<network connections="0">'
        )
        self.assertEqual(self.norm(self.base), self.norm(dynamic))

    def test_bridge_change_rejected(self):
        changed = self.base.replace('name="br1"', 'name="br2"')
        self.assertNotEqual(self.norm(self.base), self.norm(changed))

    def test_uuid_change_rejected(self):
        changed = self.base.replace("uuid-1", "uuid-2")
        self.assertNotEqual(self.norm(self.base), self.norm(changed))

    def test_mac_change_rejected(self):
        changed = self.base.replace(
            "52:54:00:00:00:01", "52:54:00:00:00:02"
        )
        self.assertNotEqual(self.norm(self.base), self.norm(changed))

    def test_forwarding_change_rejected(self):
        changed = self.base.replace(
            "</network>", '<forward mode="nat"/></network>'
        )
        self.assertNotEqual(self.norm(self.base), self.norm(changed))

    def test_other_root_attribute_not_ignored(self):
        changed = self.base.replace(
            "<network>", '<network altered="yes">'
        )
        self.assertNotEqual(self.norm(self.base), self.norm(changed))

    def test_nested_connections_not_ignored(self):
        changed = self.base.replace(
            '<bridge name="br1"/>',
            '<bridge name="br1" connections="1"/>'
        )
        self.assertNotEqual(self.norm(self.base), self.norm(changed))

    def test_invalid_connections_rejected(self):
        changed = self.base.replace(
            "<network>", '<network connections="invalid">'
        )
        with self.assertRaises(ValueError):
            self.norm(changed)

    def test_malformed_xml_rejected(self):
        with self.assertRaises(ValueError):
            self.norm("<network><broken></network>")

    def test_wrong_root_rejected(self):
        with self.assertRaises(ValueError):
            self.norm("<domain/>")

if __name__ == "__main__":
    unittest.main()
