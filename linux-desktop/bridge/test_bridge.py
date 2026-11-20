import concurrent.futures
import json
import os
from pathlib import Path
import socket
import struct
import tempfile
import threading
import unittest
import uuid

from guest import Agent, authority
from host import Hub
from wire import (Channel, DATA, HEADER, MAX_PAYLOAD, SocketEndpoint, authenticate,
                  background, read_exact)


def new_id():
    return str(uuid.uuid4())


class Lifecycle(Agent):
    def command(self, op, user, sandbox, node=None, settings=None):
        if op == "configure":
            return {"configured": json.loads(settings)["node_id"] == node, "desktop": "stopped"}
        running = op == "start" or (op == "status" and sandbox in self.displays)
        return {"user_id": user, "sandbox_id": sandbox, "node_id": node,
                "desktop": "running" if running else "stopped",
                "network": "offline"}


class BridgeTest(unittest.TestCase):
    def test_authenticated_channel(self):
        a, b = socket.socketpair()
        try:
            key = os.urandom(32)
            with a.makefile("rwb", 0) as host, b.makefile("rwb", 0) as guest:
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    result = pool.submit(authenticate, guest, key, host=False)
                    authenticate(host, key, host=True)
                    result.result(2)
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    result = pool.submit(authenticate, guest, key, host=False)
                    with self.assertRaises(ValueError):
                        authenticate(host, os.urandom(32), host=True)
                    a.shutdown(socket.SHUT_RDWR)
                    with self.assertRaises(EOFError):
                        result.result(2)
        finally:
            a.close()
            b.close()

    def test_bounded_frames(self):
        a, b = socket.socketpair()
        with a, b, b.makefile("rb", 0) as file:
            a.sendall(HEADER.pack(DATA, 1, MAX_PAYLOAD + 1))
            with self.assertRaises(ValueError):
                Channel(file).receive()

    def test_private_cookie_record(self):
        cookie = os.urandom(16)
        raw = authority(cookie)
        self.assertEqual(raw[:2], b"\xff\xff")
        self.assertTrue(raw.endswith(struct.pack("!H", 16) + cookie))

    def test_interleaved_displays_and_independent_stop(self):
        a, b = socket.socketpair()
        clients = {}
        def relay(_path, display):
            tx, rx = socket.socketpair()
            rx.settimeout(4)
            clients[display] = rx
            return SocketEndpoint(tx)
        user = new_id()
        with tempfile.TemporaryDirectory(prefix="os-", dir="/tmp") as temp:
            hostfile, guestfile = a.makefile("rwb", 0), b.makefile("rwb", 0)
            hub = Hub(Channel(hostfile), relay)
            agent = Lifecycle(Channel(guestfile), Path(temp), "/unused", os.getgid())
            def run_guest():
                try:
                    agent.run()
                except EOFError:
                    pass
            threads = [background(hub.run), background(run_guest)]
            def request(display):
                return {"user": user, "sandbox": new_id(), "node": new_id(), "op": "start",
                        "relay": "/relay", "display": display, "cookie": os.urandom(16).hex()}
            one, two = request(40), request(41)
            try:
                config = dict(one, op="configure", settings=json.dumps({"node_id": one["node"]}))
                self.assertTrue(hub.command(config)["configured"])
                with concurrent.futures.ThreadPoolExecutor(2) as pool:
                    results = list(pool.map(hub.command, [one, two]))
                self.assertTrue(all(r.get("desktop") == "running" for r in results), results)
                with socket.socket(socket.AF_UNIX) as x, socket.socket(socket.AF_UNIX) as y:
                    for sock, spec in ((x, one), (y, two)):
                        sock.settimeout(4)
                        sock.connect(str(Path(temp) / spec["sandbox"] / "X0"))
                        sock.sendall(b"request " + str(spec["display"]).encode())
                    # Wait for guest OPEN to create X server endpoint.
                    import time
                    until = time.monotonic() + 3
                    while len(clients) < 2 and time.monotonic() < until:
                        time.sleep(.005)
                    self.assertEqual(clients[40].recv(10), b"request 40")
                    self.assertEqual(clients[41].recv(10), b"request 41")
                    with self.assertRaises(ValueError):
                        hub.command(dict(one, user=new_id()))
                    with self.assertRaises(ValueError):
                        hub.command(dict(one, node=new_id()))
                    with self.assertRaises(ValueError):
                        hub.command(config)
                    with self.assertRaises(ValueError):
                        hub.command(dict(two, sandbox=new_id()))
                    bulk = os.urandom(3 * 1024 * 1024)
                    with concurrent.futures.ThreadPoolExecutor() as pool:
                        sending = pool.submit(x.sendall, bulk)
                        clients[41].sendall(b"interactive")
                        self.assertEqual(y.recv(11), b"interactive")
                        with clients[40].makefile("rb", 0) as stream:
                            self.assertEqual(read_exact(stream, len(bulk)), bulk)
                        sending.result(5)
                    self.assertEqual(hub.command(dict(one, op="stop"))["desktop"], "stopped")
                    self.assertFalse((Path(temp) / one["sandbox"] / "X0").exists())
                    clients[41].sendall(b"still B")
                    self.assertEqual(y.recv(7), b"still B")
                    self.assertEqual(hub.command(dict(two, op="stop"))["desktop"], "stopped")
            finally:
                a.shutdown(socket.SHUT_RDWR)
                for thread in threads:
                    thread.join(3)
                for sock in clients.values():
                    sock.close()
                hostfile.close()
                guestfile.close()
                a.close()
                b.close()


if __name__ == "__main__":
    unittest.main()
