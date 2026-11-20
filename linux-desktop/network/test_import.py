"""Node import regressions. Filesystem cases run as root on a disposable Linux guest."""
from contextlib import ExitStack
from io import BytesIO
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch
from uuid import uuid4

import gateway


class ImportTests(unittest.TestCase):
    def setUp(self):
        self.a, self.b, self.node = (str(uuid4()) for _ in range(3))
        self.record = {"node_id": self.node, "endpoint_ip": "203.0.113.12", "endpoint_port": 443,
                       "tls_server_name": "gateway.example", "authorization": "local-persistent",
                       "uuid": str(uuid4()), "password": "fixture-secret"}

    def test_validates_flat_binding_and_every_field(self):
        for change in ({"node_id": self.b}, {"bindings": {}}, {"insecure": True},
                       {"endpoint_port": True}, {"endpoint_ip": 7}, {"uuid": "bad"}, {"uuid": 17},
                       {"tls_server_name": "bad..name"},
                       {"password": ""}, {"probe": None}, {"certificate_pem": "bad"},
                       {"authorization": "unknown"}, {"ttl_seconds": 30},
                       {"probe": {"ipv4": "127.0.0.1", "tls_name": "probe.example", "path": "/ready"}}):
            with self.subTest(change=change), self.assertRaises((ValueError, TypeError)):
                gateway.scoped_record({**self.record, **change}, self.a, self.node)
        internal = gateway.scoped_record(self.record, self.a, self.node)
        self.assertEqual(set(internal["bindings"]), {self.a})
        self.assertNotIn("node_id", internal)

    @unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "root-only guest storage")
    def test_private_storage_atomicity_and_precedence(self):
        with ExitStack() as stack:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory()))
            instances, templates = root / "instances", root / "templates"
            instances.mkdir(mode=0o700)
            templates.mkdir(mode=0o700)
            stack.enter_context(patch.object(gateway, "INSTANCES", instances))
            stack.enter_context(patch.object(gateway, "NODES", templates))
            for sandbox in (self.a, self.b):
                (instances / sandbox).mkdir(mode=0o700)

            template = templates / (self.node + ".json")
            common = gateway.scoped_record(self.record, self.a, self.node)
            template.write_text(json.dumps(common))
            template.chmod(0o600)
            self.assertEqual(gateway.read_node(self.a, self.node)[1], "template")

            def store(sandbox, record):
                gateway.configure(sandbox, self.node, BytesIO(json.dumps(record).encode()))

            store(self.a, self.record)
            store(self.b, {**self.record, "password": "B-only"})
            a_file = instances / self.a / "nodes" / template.name
            b_file = instances / self.b / "nodes" / template.name
            stable_a = a_file.read_bytes()
            stable_b = b_file.read_bytes()
            self.assertEqual((stat.S_IMODE(a_file.stat().st_mode), a_file.stat().st_uid), (0o600, 0))
            for payload in (b'{"node_id":"wrong"}', b'{"node_id":1,"node_id":2}', b" " * 65537):
                with self.assertRaises((ValueError, KeyError, TypeError)):
                    gateway.configure(self.a, self.node, BytesIO(payload))
                self.assertEqual(a_file.read_bytes(), stable_a)
            store(self.a, {**self.record, "password": "rotated-A"})
            record, source = gateway.read_node(self.a, self.node)
            self.assertEqual(source, "instance")
            self.assertEqual(record["bindings"][self.a]["password"], "rotated-A")
            self.assertEqual(b_file.read_bytes(), stable_b)
            self.assertEqual(json.loads(template.read_text()), common)
            a_file.chmod(0o644)
            with self.assertRaises(ValueError):
                gateway.read_node(self.a, self.node)
            a_file.unlink()
            a_file.symlink_to(b_file)
            with self.assertRaises(OSError):
                gateway.read_node(self.a, self.node)
            a_file.unlink()
            self.assertEqual(gateway.read_node(self.a, self.node)[1], "template")


if __name__ == "__main__":
    unittest.main()
