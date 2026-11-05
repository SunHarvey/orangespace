#!/usr/bin/env python3
"""Generate an explicit sing-box 1.14.4 Linux node config, without emitting secrets."""
import argparse
import json
import os
from pathlib import Path
from uuid import UUID


def node_config(users: list[dict], certificate: str, key: str, port: int = 443) -> dict:
    if not users or not 1 <= port <= 65535:
        raise ValueError("at least one user and a valid port are required")
    seen = set()
    normalized = []
    for user in users:
        uid = str(UUID(user["uuid"]))
        if uid in seen or len(user["password"]) < 24:
            raise ValueError("duplicate UUID or TUIC password shorter than 24 characters")
        seen.add(uid)
        normalized.append({"uuid": uid, "password": user["password"], "name": uid})
    return {
        "log": {"level": "warn", "timestamp": True},
        "dns": {
            "servers": [{"type": "udp", "tag": "node-resolver", "server": "127.0.0.1", "server_port": 5353}],
            "final": "node-resolver",
        },
        "inbounds": [{
            "type": "tuic", "tag": "orangespace-tuic", "listen": "0.0.0.0", "listen_port": port,
            "users": normalized, "congestion_control": "cubic", "zero_rtt_handshake": False,
            "tls": {"enabled": True, "certificate_path": certificate, "key_path": key},
        }],
        "outbounds": [{"type": "direct", "tag": "node-egress"}],
        "route": {
            "rules": [
                {"port": 53, "action": "hijack-dns"},
                {"action": "resolve"},
                {"ip_is_private": True, "action": "reject"},
                {"ip_cidr": ["0.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "224.0.0.0/4", "::/128", "ff00::/8"], "action": "reject"},
            ],
            "default_domain_resolver": "node-resolver",
            "final": "node-egress",
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--users", type=Path, required=True, help="private JSON array of uuid/password entries")
    parser.add_argument("--certificate", required=True, help="certificate path as seen by sing-box")
    parser.add_argument("--key", required=True, help="key path as seen by sing-box")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    config = node_config(json.loads(args.users.read_text()), args.certificate, args.key, args.port)
    # Deliberately refuse overwrites/symlinks. Rotate a reviewed new file explicitly.
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(config, stream, indent=2)
        stream.write("\n")
    print(f"Created {args.output}; secrets were not printed. Run sing-box check before deployment.")


if __name__ == "__main__":
    main()
