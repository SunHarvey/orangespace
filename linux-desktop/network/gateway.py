"""Private, root-only IPv4 gateway for an OrangeSpace desktop in a dedicated Linux VM."""
import argparse
import contextlib
import fcntl
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import sys
import time
from uuid import UUID

STATE = Path("/run/orangespace-network")
NODES = Path("/etc/orangespace/nodes")
INSTANCES = Path("/var/lib/orangespace/desktop/instances")
# Node leases live on tmpfs only: their credentials never reach a disk.
LEASES = Path("/run/orangespace/leases")
LEASE_MARGIN_MS = 500
MAX_LEASE_MS = 30000
NETNS = Path("/run/netns")
POOL = ipaddress.IPv4Address("10.243.0.0")
DESKTOP_PEER = "192.168.254.1"
DESKTOP_IP = "192.168.254.2"
WINDOW = 15
CHECK_INTERVAL = 3
TUN_START_SECONDS = 15
BLOCKED = ("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
           "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4")


class GatewayError(ValueError):
    """Validation and lifecycle failures with fixed, safe operator messages."""


def uuid_text(value):
    if not isinstance(value, str):
        raise GatewayError("expected a UUID string")
    canonical = str(UUID(value))
    if canonical != value:
        raise GatewayError("expected canonical lowercase UUID")
    return canonical


def valid_tls_name(name):
    label = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    return (isinstance(name, str) and 1 <= len(name) <= 253 and
            all(re.fullmatch(label, part) for part in name.split(".")))


def node_policy(record, sandbox_id):
    allowed = {"endpoint_ip", "endpoint_port", "tls_server_name", "bindings",
               "ttl_seconds", "authorization", "certificate_pem", "probe", "tunnel_id", "deadline"}
    if not isinstance(record, dict) or record.keys() - allowed:
        raise GatewayError("invalid node file fields")
    if not isinstance(record["endpoint_ip"], str):
        raise GatewayError("a literal IPv4 address is required")
    ip = ipaddress.IPv4Address(record["endpoint_ip"])
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local or ip.is_reserved:
        raise GatewayError("invalid node IPv4 endpoint")
    port = record["endpoint_port"]
    ttl = record.get("ttl_seconds")
    if type(port) is not int or not 1 <= port <= 65535:
        raise GatewayError("invalid node port")
    lease = record.get("authorization") == "lease"
    if lease:
        # A node lease: the permit lasts exactly as long as the lease the client
        # last renewed (minus a margin), then the kernel withdraws it.
        if "ttl_seconds" in record or type(record.get("deadline")) is not float:
            raise GatewayError("invalid node lease")
        uuid_text(record.get("tunnel_id"))
        ttl = record["deadline"] - time.clock_gettime(time.CLOCK_BOOTTIME)
        if not 0.001 <= ttl <= MAX_LEASE_MS / 1000:
            raise GatewayError("node lease expired")
    elif "tunnel_id" in record or "deadline" in record:
        raise GatewayError("lease fields without a node lease")
    elif "authorization" in record:
        if record["authorization"] != "local-persistent" or "ttl_seconds" in record:
            raise GatewayError("ambiguous or unknown local node authorization")
    elif type(ttl) is not int or not 1 <= ttl <= 3600:
        raise GatewayError("test node ttl_seconds must be 1..3600")
    name = record["tls_server_name"]
    if not valid_tls_name(name):
        raise GatewayError("invalid node TLS name")
    binding = record["bindings"][sandbox_id]
    if set(binding) != {"uuid", "password"}:
        raise GatewayError("invalid binding fields")
    uid = uuid_text(binding["uuid"])
    password = binding["password"]
    if not isinstance(password, str) or not password or len(password) > 4096:
        raise GatewayError("invalid binding credentials")
    tls = {"enabled": True, "server_name": name}
    if "certificate_pem" in record:
        certificate = record["certificate_pem"]
        if not isinstance(certificate, str) or not certificate.startswith("-----BEGIN CERTIFICATE-----"):
            raise GatewayError("invalid certificate_pem")
        ssl.create_default_context(cadata=certificate)
        tls["certificate"] = certificate
    outbound = {"type": "tuic", "tag": "bound-node", "server": str(ip), "server_port": port,
                "uuid": uid, "password": password, "tls": tls, "bind_interface": "wan0",
                "udp_relay_mode": "native", "zero_rtt_handshake": False}
    return outbound, ttl


def unique_fields(pairs):
    record = {}
    for key, value in pairs:
        if key in record:
            raise GatewayError("duplicate node configuration field")
        record[key] = value
    return record


def read_record(path, directory=None):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags, dir_fd=directory), "r") as secret:
        st = os.fstat(secret.fileno())
        if st.st_uid != 0 or st.st_mode & 0o077 or not stat.S_ISREG(st.st_mode):
            raise GatewayError("node record must be a private root-owned regular file")
        return json.load(secret, object_pairs_hook=unique_fields)


@contextlib.contextmanager
def instance_nodes(sandbox_id, create=False):
    with contextlib.ExitStack() as stack:
        parent = None
        for name in (INSTANCES, uuid_text(sandbox_id), "nodes"):
            if name == "nodes" and create:
                try:
                    os.mkdir(name, 0o700, dir_fd=parent)
                    os.fsync(parent)
                except FileExistsError:
                    pass
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY, dir_fd=parent)
            stack.callback(os.close, fd)
            st = os.fstat(fd)
            if st.st_uid != 0 or st.st_mode & 0o022:
                raise GatewayError("untrusted node configuration directory")
            parent = fd
        yield parent


def scoped_record(flat, sandbox_id, node_id):
    if not isinstance(flat, dict) or flat.get("node_id") != node_id or "bindings" in flat:
        raise GatewayError("node import does not match its selected binding")
    record = dict(flat)
    del record["node_id"]
    record["bindings"] = {sandbox_id: {"uuid": record.pop("uuid"), "password": record.pop("password")}}
    node_policy(record, sandbox_id)
    probe_spec(record)
    return record


def lease_path(sandbox_id):
    return LEASES / (uuid_text(sandbox_id) + ".json")


def write_private(path, value):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temp = path.with_name(".import-" + secrets.token_hex(16))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w") as out:
            json.dump(value, out)
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def store_lease(sandbox_id, node_id, stream):
    """Keep one sandbox's current node lease (from the client) in /run."""
    raw = stream.read(65537)
    if len(raw) > 65536:
        raise GatewayError("node lease exceeds 64 KiB")
    flat = json.loads(raw, object_pairs_hook=unique_fields)
    if not isinstance(flat, dict) or "deadline" in flat or "authorization" in flat:
        raise GatewayError("invalid node lease")
    remaining = flat.pop("remaining_ms", None)
    if type(remaining) is not int or not LEASE_MARGIN_MS < remaining <= MAX_LEASE_MS:
        raise GatewayError("invalid node lease budget")
    flat.update(authorization="lease",
                deadline=time.clock_gettime(time.CLOCK_BOOTTIME) + (remaining - LEASE_MARGIN_MS) / 1000)
    scoped_record(flat, sandbox_id, uuid_text(node_id))
    write_private(lease_path(sandbox_id), flat)


def read_node(sandbox_id, node_id):
    filename = uuid_text(node_id) + ".json"
    try:
        flat = read_record(lease_path(sandbox_id))
    except FileNotFoundError:
        flat = None
    if flat is not None and flat.get("node_id") == node_id:
        return scoped_record(flat, sandbox_id, node_id), "lease"
    try:
        with instance_nodes(sandbox_id) as directory:
            private = read_record(filename, directory)
    except FileNotFoundError:
        return read_record(NODES / filename), "template"
    return scoped_record(private, sandbox_id, node_id), "instance"


def configure(sandbox_id, node_id, stream):
    filename = uuid_text(node_id) + ".json"
    raw = stream.read(65537)
    if len(raw) > 65536:
        raise GatewayError("node import exceeds 64 KiB")
    flat = json.loads(raw, object_pairs_hook=unique_fields)
    scoped_record(flat, sandbox_id, node_id)
    with instance_nodes(sandbox_id, create=True) as directory:
        temp = ".import-" + secrets.token_hex(16)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        fd = os.open(temp, flags, 0o600, dir_fd=directory)
        try:
            with os.fdopen(fd, "w") as out:
                json.dump(flat, out)
                out.flush()
                os.fsync(out.fileno())
            os.replace(temp, filename, src_dir_fd=directory, dst_dir_fd=directory)
            os.fsync(directory)
        finally:
            try:
                os.unlink(temp, dir_fd=directory)
            except FileNotFoundError:
                pass


def probe_spec(record):
    spec = record.get("probe")
    if "probe" not in record:
        return None
    if not isinstance(spec, dict) or set(spec) - {"ipv4", "port", "tls_name", "path", "certificate_pem"}:
        raise GatewayError("invalid probe fields")
    if not isinstance(spec["ipv4"], str):
        raise GatewayError("probe must specify a literal IPv4 address")
    ip = ipaddress.IPv4Address(spec["ipv4"])
    if any(ip in ipaddress.IPv4Network(net) for net in BLOCKED):
        raise GatewayError("probe IP must be reachable through the sandbox")
    if not valid_tls_name(spec["tls_name"]):
        raise GatewayError("invalid probe TLS name")
    if not re.fullmatch(r"/[!-~]{0,1023}", spec["path"]):
        raise GatewayError("invalid probe path")
    port = spec.get("port", 443)
    if type(port) is not int or not 1 <= port <= 65535:
        raise GatewayError("invalid probe port")
    if "certificate_pem" in spec:
        certificate = spec["certificate_pem"]
        if not isinstance(certificate, str) or not certificate.startswith("-----BEGIN CERTIFICATE-----"):
            raise GatewayError("invalid probe certificate_pem")
        ssl.create_default_context(cadata=certificate)
    return spec


def https_probe(spec):
    tls = ssl.create_default_context(cadata=spec.get("certificate_pem"))
    with socket.create_connection((spec["ipv4"], spec.get("port", 443)), timeout=1.5) as raw:
        with tls.wrap_socket(raw, server_hostname=spec["tls_name"]) as stream:
            request = f'GET {spec["path"]} HTTP/1.0\r\nHost: {spec["tls_name"]}\r\n\r\n'
            stream.sendall(request.encode("ascii"))
            with http.client.HTTPResponse(stream) as reply:
                reply.begin()
                return 200 <= reply.status < 300


def helper_config(outbound):
    return {"log": {"disabled": True},
            "inbounds": [{"type": "tun", "interface_name": "ostun0", "stack": "gvisor",
                          "address": ["172.31.255.1/30"], "mtu": 1280, "auto_route": False}],
            "outbounds": [outbound], "route": {"final": "bound-node"}}


def root_policy(table, wan, gw_ip, node, port, ttl):
    ttl_ms = max(1, int(ttl * 1000))
    # Per-interface rules also cover established packets and automatically expire.
    return f"""table inet {table} {{
 set endpoints {{
  type ipv4_addr . inet_service
  flags timeout
  elements = {{ {node} . {port} timeout {ttl_ms}ms }}
 }}
 chain input {{
  type filter hook input priority -20; policy accept;
  iifname "{wan}" drop
 }}
 chain forward {{
  type filter hook forward priority -20; policy accept;
  iifname "{wan}" ip saddr {gw_ip} ip daddr . udp dport @endpoints accept
  iifname "{wan}" drop
  oifname "{wan}" ip daddr {gw_ip} ip saddr . udp sport @endpoints ct state established accept
  oifname "{wan}" drop
 }}
 chain nat {{
  type nat hook postrouting priority srcnat; policy accept;
  iifname "{wan}" ip saddr {gw_ip} ip daddr . udp dport @endpoints masquerade
 }}
}}
"""


def gateway_policy(node, port):
    return f"""table inet orangespace {{
 chain forward {{
  type filter hook forward priority filter; policy drop;
  iifname "desk0" ip daddr {{ {", ".join(BLOCKED)} }} drop
  iifname "desk0" oifname "ostun0" ip saddr {DESKTOP_IP} meta l4proto {{ tcp, udp }} accept
  iifname "ostun0" oifname "desk0" ip daddr {DESKTOP_IP} meta l4proto {{ tcp, udp }} accept
 }}
 chain input {{
  type filter hook input priority filter; policy drop;
  iifname "lo" accept
  iifname "wan0" ip saddr {node} udp sport {port} ct state established accept
 }}
 chain output {{
  type filter hook output priority filter; policy drop;
  oifname "lo" accept
  oifname "wan0" ip daddr {node} udp dport {port} accept
 }}
}}
"""


def run(*args, stdin=None):
    return subprocess.run(args, input=stdin, text=True, capture_output=True, check=True,
                          timeout=25).stdout.strip()


def service_property(unit, prop):
    result = subprocess.run(["systemctl", "show", "--property=" + prop, "--value", unit],
                            text=True, capture_output=True, timeout=15)
    value = result.stdout.strip()
    if result.returncode and not (result.returncode == 4 and value == "not-found"):
        result.check_returncode()
    return value


def docker_forward(data, enable):
    """Integrate with Docker's default FORWARD DROP without changing global policy."""
    if not shutil.which("iptables"):
        return
    prefix = ["iptables", "-w", "5"]
    table = subprocess.run([*prefix, "-S", "DOCKER-USER"], capture_output=True, timeout=10)
    if table.returncode:
        if table.returncode != 1:
            table.check_returncode()
        return
    iface = f"osw{data['slot']:x}"
    local = str(POOL + 4 * data["slot"] + 2)
    node, port = data["endpoint"], str(data["port"])
    for args in (["-i", iface, "-s", local, "-d", node, "-p", "udp", "--dport", port],
                 ["-o", iface, "-s", node, "-d", local, "-p", "udp", "--sport", port,
                  "-m", "conntrack", "--ctstate", "ESTABLISHED"]):
        rule = [*args, "-m", "comment", "--comment", "OrangeSpace-" + iface, "-j", "ACCEPT"]
        check = subprocess.run([*prefix, "-C", "DOCKER-USER", *rule], capture_output=True, timeout=10)
        if check.returncode not in (0, 1):
            check.check_returncode()
        if enable and check.returncode == 1:
            run(*prefix, "-I", "DOCKER-USER", *rule)
        elif not enable and check.returncode == 0:
            run(*prefix, "-D", "DOCKER-USER", *rule)


@contextlib.contextmanager
def lock(name):
    with (STATE / (name + ".lock")).open("a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield


def save(path, value):
    temp = path.with_suffix(".new")
    temp.write_text(json.dumps(value), encoding="utf-8")
    temp.replace(path)


class Gateway:
    def __init__(self, sandbox_id):
        self.id = uuid_text(sandbox_id)
        tag = self.id.replace("-", "")
        self.ns = "osgw-" + tag
        self.desk = "osdesk-" + tag
        self.unit = "orangespace-gw-" + tag + ".service"
        self.table = "osg_" + tag
        self.state = STATE / (self.id + ".state")
        self.config = STATE / (self.id + ".conf")

    def reserve(self, node_id, source, outbound, probe):
        with lock("allocation"):
            used = {json.loads(p.read_text())["slot"] for p in STATE.glob("*.state")}
            for slot in range(1, 16384):
                if slot not in used and not Path("/sys/class/net", f"osw{slot:x}").exists():
                    data = {"slot": slot, "node": node_id, "source": source, "endpoint": outbound["server"],
                            "port": outbound["server_port"], "probe": probe, "ready_until": 0}
                    save(self.state, data)
                    return data
        raise GatewayError("gateway address pool is full")

    def inside(self, *args, stdin=None):
        return run("ip", "netns", "exec", self.ns, *args, stdin=stdin)

    def down(self):
        if not self.state.exists():
            return
        data = json.loads(self.state.read_text())
        wan = f"osw{data['slot']:x}"
        # Sever the only physical path before removing any filtering resource.
        if Path("/sys/class/net", wan).exists():
            run("ip", "link", "delete", wan)
        docker_forward(data, False)
        if service_property(self.unit, "LoadState") != "not-found":
            run("systemctl", "stop", self.unit)
        for name in (self.ns, self.desk):
            if (NETNS / name).exists():
                run("ip", "netns", "delete", name)
        tables = json.loads(run("nft", "-j", "list", "tables"))["nftables"]
        if any(t.get("table", {}).get("name") == self.table and
               t["table"]["family"] == "inet" for t in tables):
            run("nft", "delete", "table", "inet", self.table)
        self.config.unlink(missing_ok=True)
        with lock("allocation"):
            self.state.unlink()

    def up(self, pid, node_id):
        self.down()
        uuid_text(node_id)
        if pid < 1:
            raise GatewayError("invalid desktop PID")
        if Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() != "1":
            raise GatewayError("enable IPv4 forwarding on the dedicated guest")
        record, source = read_node(self.id, node_id)
        outbound, ttl = node_policy(record, self.id)
        probe = probe_spec(record)
        # Keep the actual namespace inode pinned across attachment and PID reuse.
        fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
        try:
            inode = os.fstat(fd)
            if os.path.samestat(inode, os.stat("/proc/self/ns/net")):
                raise GatewayError("desktop must have a private network namespace")
            data = self.reserve(node_id, source, outbound, probe)
            data["tunnel"] = record.get("tunnel_id")
            try:
                run("ip", "netns", "attach", self.desk, str(pid))
                if not os.path.samestat(inode, (NETNS / self.desk).stat()):
                    raise GatewayError("desktop PID changed")
                links = json.loads(run("ip", "-n", self.desk, "-j", "link", "show"))
                if {link["ifname"] for link in links} != {"lo"}:
                    raise GatewayError("desktop must start with only loopback")
                self.connect(data, outbound, ttl)
            except BaseException:
                self.down()
                raise
        finally:
            os.close(fd)

    def connect(self, data, outbound, ttl):
        slot = data["slot"]
        wan = f"osw{slot:x}"
        root_ip, gw_ip = (str(POOL + slot * 4 + offset) for offset in (1, 2))
        node, port = outbound["server"], outbound["server_port"]
        run("ip", "netns", "add", self.ns)
        self.inside("nft", "-f", "-", stdin=gateway_policy(node, port))
        expires = time.clock_gettime(time.CLOCK_BOOTTIME) + ttl if ttl else None
        run("nft", "-f", "-", stdin=root_policy(self.table, wan, gw_ip, node, port, ttl or WINDOW))
        docker_forward(data, True)
        run("ip", "link", "add", wan, "type", "veth", "peer", "name", "wan0", "netns", self.ns)
        run("ip", "addr", "add", root_ip + "/30", "dev", wan)
        run("ip", "link", "set", wan, "up")
        gw = ("ip", "-n", self.ns)
        desk = ("ip", "-n", self.desk)
        run(*gw, "link", "set", "lo", "up")
        run(*gw, "addr", "add", gw_ip + "/30", "dev", "wan0")
        run(*gw, "link", "set", "wan0", "up")
        run(*gw, "route", "add", node + "/32", "via", root_ip, "dev", "wan0")
        run(*gw, "link", "add", "desk0", "type", "veth", "peer", "name", "eth0", "netns", self.desk)
        self.inside("sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=0",
                    "net.ipv4.conf.default.rp_filter=0")
        run(*gw, "addr", "add", DESKTOP_PEER + "/30", "dev", "desk0")
        run(*gw, "link", "set", "desk0", "up")
        save(self.config, helper_config(outbound))
        binary = shutil.which("sing-box")
        if not binary:
            raise GatewayError("sing-box is missing")
        command = [shutil.which("ip"), "netns", "exec", self.ns, binary, "run", "-c", str(self.config)]
        if ttl is None:
            command = [sys.executable, str(Path(__file__).resolve()), "supervise", self.id]
        run("systemd-run", "--quiet", "--collect", "--unit=" + self.unit,
            "--property=Type=exec", "--property=Restart=no",
            "--property=StandardOutput=null", "--property=StandardError=null",
            "--", *command)
        # Bounded by time, not by iterations: on a loaded machine each check
        # itself can take a large share of the budget.
        deadline = time.monotonic() + TUN_START_SECONDS
        while True:
            links = json.loads(run(*gw, "-j", "link", "show"))
            if any(link["ifname"] == "ostun0" for link in links):
                break
            if service_property(self.unit, "ActiveState") != "active":
                raise GatewayError("tunnel process stopped during startup")
            if time.monotonic() >= deadline:
                raise GatewayError("tunnel interface did not start")
            time.sleep(0.05)
        # If removal of the TUN deletes its route, desktop traffic must not fall
        # through to the gateway's own node endpoint route in the main table.
        run(*gw, "route", "add", "unreachable", "default", "metric", "32767", "table", "100")
        run(*gw, "route", "add", "default", "dev", "ostun0", "metric", "10", "table", "100")
        run(*gw, "rule", "add", "iif", "desk0", "lookup", "100", "priority", "100")
        # The only point at which the desktop becomes routable.
        run(*desk, "addr", "add", DESKTOP_IP + "/30", "dev", "eth0")
        run(*desk, "link", "set", "eth0", "mtu", "1280", "up")
        run(*desk, "route", "add", "default", "via", DESKTOP_PEER, "dev", "eth0")
        data["ready_until"] = expires
        save(self.state, data)
        if not self.ready():
            raise GatewayError("gateway authorization expired before publication")

    def renew(self, tunnel_id, remaining_ms):
        """Extend the kernel permit to the lease the client just renewed."""
        uuid_text(tunnel_id)
        if type(remaining_ms) is not int or not LEASE_MARGIN_MS < remaining_ms <= MAX_LEASE_MS:
            raise GatewayError("invalid node lease budget")
        path = lease_path(self.id)
        flat = read_record(path)
        if flat.get("authorization") != "lease" or flat.get("tunnel_id") != tunnel_id:
            raise GatewayError("not the sandbox's current tunnel")
        now = time.clock_gettime(time.CLOCK_BOOTTIME)
        flat["deadline"] = now + (remaining_ms - LEASE_MARGIN_MS) / 1000
        write_private(path, flat)
        if not self.state.exists():
            return
        data = json.loads(self.state.read_text())
        if data.get("source") != "lease" or data.get("tunnel") != tunnel_id:
            return
        # One nft transaction: the permit is replaced, never briefly absent.
        timeout = remaining_ms - LEASE_MARGIN_MS
        run("nft", "-f", "-", stdin=(f"flush set inet {self.table} endpoints\n"
                                     f"add element inet {self.table} endpoints "
                                     f"{{ {data['endpoint']} . {data['port']} timeout {timeout}ms }}\n"))
        data["ready_until"] = flat["deadline"]
        save(self.state, data)

    def ready(self):
        if not self.state.exists():
            return False
        data = json.loads(self.state.read_text())
        return ((data["ready_until"] is None or time.clock_gettime(time.CLOCK_BOOTTIME) < data["ready_until"]) and
                Path("/sys/class/net", f"osw{data['slot']:x}").exists() and
                service_property(self.unit, "ActiveState") == "active" and
                bool(json.loads(run("nft", "-j", "list", "set", "inet", self.table, "endpoints"))
                     ["nftables"][-1]["set"].get("elem")))

    def supervise(self):
        data = json.loads(self.state.read_text())
        config = json.loads(self.config.read_text())
        process = subprocess.Popen(["ip", "netns", "exec", self.ns, "sing-box", "run",
                                    "-c", str(self.config)])
        try:
            while process.poll() is None:
                record, source = read_node(self.id, data["node"])
                current, ttl = node_policy(record, self.id)
                if (source != data["source"] or ttl is not None or helper_config(current) != config
                        or probe_spec(record) != data["probe"]):
                    break
                rules = (f"flush set inet {self.table} endpoints\n"
                         f"add element inet {self.table} endpoints "
                         f"{{ {current['server']} . {current['server_port']} timeout {WINDOW}s }}\n")
                run("nft", "-f", "-", stdin=rules)
                try:
                    process.wait(CHECK_INTERVAL)
                except subprocess.TimeoutExpired:
                    pass
        finally:
            try:
                run("nft", "flush", "set", "inet", self.table, "endpoints")
            finally:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()

    def probe(self):
        if not self.ready():
            return 2
        data = json.loads(self.state.read_text())
        if not data["probe"]:
            return 2
        now = time.clock_gettime(time.CLOCK_BOOTTIME)
        if "probed_at" in data and now - data["probed_at"] < CHECK_INTERVAL:
            return data["probe_result"]
        try:
            child = subprocess.run(["ip", "netns", "exec", self.desk, sys.executable,
                                    str(Path(__file__).resolve()), "probe-once", self.id],
                                   timeout=3, capture_output=True)
            result = int(child.returncode != 0)
        except subprocess.TimeoutExpired:
            result = 1
        data.update(probed_at=now, probe_result=result)
        save(self.state, data)
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    up = commands.add_parser("up")
    up.add_argument("sandbox_id")
    up.add_argument("container_pid", type=int)
    up.add_argument("node_id")
    config = commands.add_parser("configure")
    config.add_argument("sandbox_id")
    config.add_argument("node_id")
    lease = commands.add_parser("lease")
    lease.add_argument("sandbox_id")
    lease.add_argument("node_id")
    renew = commands.add_parser("renew")
    renew.add_argument("sandbox_id")
    renew.add_argument("tunnel_id")
    renew.add_argument("remaining_ms", type=int)
    for name in ("down", "status", "probe", "probe-once", "supervise"):
        commands.add_parser(name).add_argument("sandbox_id")
    args = parser.parse_args(argv)
    os.umask(0o077)
    os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    if sys.platform != "linux" or os.geteuid() != 0:
        parser.error("run as root inside the dedicated Linux guest")
    try:
        gateway = Gateway(args.sandbox_id)
        if args.operation == "supervise":
            gateway.supervise()
            return 0
        if args.operation == "probe-once":
            return int(not https_probe(json.loads(gateway.state.read_text())["probe"]))
        STATE.mkdir(mode=0o700, exist_ok=True)
        with lock(gateway.id):
            if args.operation == "up":
                gateway.up(args.container_pid, args.node_id)
            elif args.operation == "down":
                gateway.down()
            elif args.operation == "configure":
                if gateway.state.exists():
                    raise GatewayError("stop the sandbox gateway before configuring a node")
                configure(gateway.id, args.node_id, sys.stdin.buffer)
            elif args.operation == "lease":
                store_lease(gateway.id, args.node_id, sys.stdin.buffer)
            elif args.operation == "renew":
                gateway.renew(args.tunnel_id, args.remaining_ms)
            elif args.operation == "probe":
                return gateway.probe()
            elif not gateway.ready():
                return 1
        return 0
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError) as exc:
        # Avoid JSON values or command arguments containing node credentials in logs.
        if isinstance(exc, GatewayError):
            print(f"gateway operation failed: {exc}", file=sys.stderr)
        elif isinstance(exc, subprocess.CalledProcessError):
            print(f"gateway operation failed: {exc.cmd[0]} exited {exc.returncode}", file=sys.stderr)
        else:
            print(f"gateway operation failed ({type(exc).__name__})", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
