#!/usr/bin/env python3
"""Release only this product's labeled desktops when the guest bridge exits."""
import json
import subprocess
import sys
from uuid import UUID

DOCKER = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]
PREFIX = "io.orangespace.desktop."


def cleanup():
    output = subprocess.check_output([*DOCKER, "ps", "-aq", "--no-trunc", "--filter",
                                      "label=" + PREFIX + "sandbox"], text=True, timeout=15)
    failed = False
    for cid in output.split():
        try:
            raw = subprocess.check_output([*DOCKER, "inspect", "--type", "container", cid], timeout=10)
            item, = json.loads(raw)
            labels = item["Config"]["Labels"]
            sid, user = labels[PREFIX + "sandbox"], labels[PREFIX + "user"]
            if (sid != str(UUID(sid)) or user != str(UUID(user))
                    or item["Name"] != "/osdesk-" + sid):
                continue
            proc = subprocess.run(["/opt/orangespace/guest/desktop", "stop", user, sid],
                                  stdout=subprocess.DEVNULL, timeout=90)
            failed |= bool(proc.returncode)
        except (KeyError, ValueError, OSError, subprocess.SubprocessError):
            failed = True
    return int(failed)


if __name__ == "__main__":
    sys.exit(cleanup())
