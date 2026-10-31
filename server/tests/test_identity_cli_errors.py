"""Offline fault injection; not database or deployment acceptance."""
import json
from types import SimpleNamespace

import pytest

from orangespace_node import cli, control_identity


@pytest.mark.parametrize("failure", ["settings", "construct", "initialize", "machine", "binding", "submit", "close", "submit_and_close", None])
def test_inventory_error_boundary(monkeypatch, capsys, failure):
    sentinel = "synthetic-private-detail-do-not-echo"
    events = []
    public = dict(schema=1, evidence_digest="d" * 64, expires_at=1999999999)

    def fail(stage):
        if failure == stage or (failure == "submit_and_close" and stage in ("submit", "close")):
            raise RuntimeError(sentinel)

    def settings():
        events.append("settings")
        fail("settings")
        return SimpleNamespace(database_url="offline", node_id="local-node")

    class Database:
        def __init__(self, url):
            events.append("construct")
            fail("construct")
            self.engine = object()

        def initialize(self):
            events.append("initialize")
            fail("initialize")

        def close(self):
            events.append("close")
            fail("close")

    def machine(path):
        fail("machine")
        return {"node_id": sentinel if failure == "binding" else "local-node"}

    async def submit(*args):
        events.append("submit")
        fail("submit")
        return dict(public, private_detail=sentinel)

    monkeypatch.setattr(cli.Settings, "from_env", staticmethod(settings))
    monkeypatch.setattr(cli, "Database", Database)
    monkeypatch.setattr(control_identity, "load_machine_config", machine)
    monkeypatch.setattr(control_identity, "submit_inventory", submit)
    monkeypatch.setattr("sys.argv", ["orangespace-node", "publish-identity-evidence", "--machine-config", "offline", "--legacy-user-id", "legacy", "--request-id", "request"])
    # Convert unexpected exceptions to a fixed assertion, keeping synthetic detail
    # out of RED logs even when the original boundary is missing.
    unexpected = False
    exit_code = None
    try:
        cli.main()
    except SystemExit as error:
        exit_code = error.code
    except Exception:
        unexpected = True
    output = capsys.readouterr()
    assert not unexpected, "ordinary exception escaped inventory boundary"
    assert events.count("close") == (0 if failure in ("settings", "construct") else 1)
    assert sentinel not in output.out + output.err
    if failure is None:
        assert exit_code is None
        assert output.err == ""
        assert json.loads(output.out) == public
        assert events[-1] == "close"
    else:
        assert exit_code == 1
        assert output.out == ""
        assert output.err == "Identity inventory submission failed.\n"
    if failure == "binding":
        assert "submit" not in events
