"""Node lease handling. Runs on Linux (CLOCK_BOOTTIME); storage cases need root."""
from io import BytesIO
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

import gateway


def boottime():
    return time.clock_gettime(time.CLOCK_BOOTTIME)


@unittest.skipUnless(sys.platform == "linux", "CLOCK_BOOTTIME is Linux-only")
class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.a, self.b, self.node = (str(uuid4()) for _ in range(3))
        self.tunnel = str(uuid4())
        self.lease = {"node_id": self.node, "endpoint_ip": "203.0.113.12", "endpoint_port": 20000,
                      "tls_server_name": "gateway.example", "uuid": str(uuid4()), "password": "fixture-secret",
                      "tunnel_id": self.tunnel, "remaining_ms": 20000}
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.object(gateway, "LEASES", self.root))

    def store(self, sandbox, change=None, node=None):
        payload = json.dumps({**self.lease, **(change or {})}).encode()
        gateway.store_lease(sandbox, node or self.node, BytesIO(payload))

    def test_rejects_every_invalid_field_and_budget(self):
        for change in ({"remaining_ms": 500}, {"remaining_ms": 30001}, {"remaining_ms": 2.5},
                       {"remaining_ms": None}, {"tunnel_id": "bad"}, {"deadline": 1.0},
                       {"node_id": self.b}, {"insecure": True}, {"authorization": "local-persistent"},
                       {"ttl_seconds": 30}, {"endpoint_port": True}, {"endpoint_ip": 7},
                       {"endpoint_ip": "127.0.0.1"}, {"uuid": "bad"}, {"password": ""},
                       {"tls_server_name": "bad..name"}, {"certificate_pem": "bad"}, {"probe": None},
                       {"probe": {"ipv4": "127.0.0.1", "tls_name": "probe.example", "path": "/ready"}}):
            with self.subTest(change=change), self.assertRaises((ValueError, TypeError)):
                self.store(self.a, change)
        with self.assertRaises(ValueError):
            gateway.store_lease(self.a, self.node, BytesIO(b" " * 65537))
        with self.assertRaises(ValueError):
            gateway.store_lease(self.a, self.node, BytesIO(b'{"node_id":"x","node_id":"y"}'))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_lease_is_bound_to_its_node_and_budget(self):
        self.store(self.a)
        stored = json.loads((self.root / (self.a + ".json")).read_text())
        self.assertNotIn("remaining_ms", stored)
        self.assertTrue(19 < stored["deadline"] - boottime() <= 19.5)
        with patch.object(gateway, "read_record", side_effect=lambda path: json.loads(path.read_text())):
            lease, outbound, ttl, probe = gateway.read_lease(self.a, self.node)
            self.assertEqual((outbound["server"], outbound["server_port"], outbound["password"]),
                             ("203.0.113.12", 20000, "fixture-secret"))
            self.assertIsNone(probe)
            # The lease names one node: it never authorizes another one.
            with self.assertRaises(ValueError):
                gateway.read_lease(self.a, self.b)
            # Another sandbox has no lease at all.
            with self.assertRaises(ValueError):
                gateway.read_lease(self.b, self.node)
        expired = {**stored, "deadline": boottime() - 1}
        with self.assertRaises(ValueError):
            gateway.lease_policy(expired, self.node)

    @unittest.skipUnless(os.geteuid() == 0, "root-owned lease storage")
    def test_storage_is_private_and_renewal_needs_the_current_tunnel(self):
        self.store(self.a)
        self.store(self.b, {"password": "B-only"})
        path = self.root / (self.a + ".json")
        self.assertEqual((stat.S_IMODE(path.stat().st_mode), path.stat().st_uid), (0o600, 0))
        before = json.loads(path.read_text())["deadline"]
        gateway.Gateway(self.a).renew(self.tunnel, 25000)
        self.assertGreater(json.loads(path.read_text())["deadline"], before)
        for tunnel, budget in ((str(uuid4()), 25000), (self.tunnel, 500), (self.tunnel, 30001)):
            with self.subTest(tunnel=tunnel, budget=budget), self.assertRaises(ValueError):
                gateway.Gateway(self.a).renew(tunnel, budget)
        with self.assertRaises(ValueError):
            gateway.Gateway(str(uuid4())).renew(self.tunnel, 25000)
        # B's lease is untouched by A's renewals.
        self.assertEqual(gateway.read_lease(self.b, self.node)[0]["password"], "B-only")
        path.chmod(0o644)
        with self.assertRaises(ValueError):
            gateway.read_lease(self.a, self.node)
        path.unlink()
        path.symlink_to(self.root / (self.b + ".json"))
        with self.assertRaises(OSError):
            gateway.read_lease(self.a, self.node)


@unittest.skipUnless(sys.platform == "linux", "CLOCK_BOOTTIME is Linux-only")
class TunStartTests(unittest.TestCase):
    """The desktop's routes go through the tunnel interface only once it is up."""

    LO = {"ifname": "lo", "flags": ["LOOPBACK", "UP", "LOWER_UP"]}
    DOWN = {"ifname": "ostun0", "flags": ["POINTOPOINT", "MULTICAST", "NOARP"]}
    UP = {"ifname": "ostun0", "flags": ["POINTOPOINT", "MULTICAST", "NOARP", "UP", "LOWER_UP"]}

    def connect(self, listings):
        state = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.enterContext(patch.object(gateway, "STATE", state))
        self.enterContext(patch.object(gateway, "TUN_START_SECONDS", 0.5))
        self.enterContext(patch.object(gateway, "service_property", return_value="active"))
        self.enterContext(patch.object(gateway.shutil, "which", side_effect=lambda name: "/usr/bin/" + name))
        self.enterContext(patch.object(gateway.Gateway, "ready", return_value=True))
        calls, shown = [], []
        remaining = iter(listings)

        def run(*args, stdin=None):
            calls.append(args)
            if args[-3:] == ("-j", "link", "show"):
                shown.append(len(calls) - 1)
                return json.dumps(next(remaining, listings[-1]))
            return ""

        self.enterContext(patch.object(gateway, "run", side_effect=run))
        g = gateway.Gateway(str(uuid4()))
        data = {"slot": 1, "node": str(uuid4()), "tunnel": str(uuid4()), "endpoint": "203.0.113.12",
                "port": 20000, "probe": None, "ready_until": 0}
        outbound = {"type": "tuic", "tag": "bound-node", "server": "203.0.113.12", "server_port": 20000}
        return g, calls, shown, lambda: g.connect(data, outbound, 20)

    def test_routes_wait_until_the_interface_is_up(self):
        g, calls, shown, connect = self.connect([[self.LO], [self.LO, self.DOWN], [self.LO, self.DOWN],
                                                 [self.LO, self.UP]])
        connect()
        route = calls.index(("ip", "-n", g.ns, "route", "add", "default", "dev", "ostun0",
                             "metric", "10", "table", "100"))
        self.assertEqual(len(shown), 4)
        self.assertGreater(route, shown[-1])

    def test_an_interface_that_never_comes_up_fails_the_start(self):
        g, calls, shown, connect = self.connect([[self.LO, self.DOWN]])
        with self.assertRaisesRegex(gateway.GatewayError, "did not start"):
            connect()
        self.assertFalse(any("ostun0" in c and "route" in c for c in calls))


if __name__ == "__main__":
    unittest.main()
