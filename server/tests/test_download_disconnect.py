import os

import anyio
import pytest
from starlette.requests import ClientDisconnect

from orangespace_node.app import DownloadResponse
from orangespace_node.storage import FileReader


@pytest.mark.parametrize("failure_message", ["http.response.start", "http.response.body"])
def test_download_descriptor_closed_when_client_cannot_receive(tmp_path, failure_message):
    source = tmp_path / "file"
    source.write_bytes(b"file contents")
    reader = FileReader(os.open(source, os.O_RDONLY))
    entered = []

    async def chunks():
        entered.append(True)
        yield reader.read()

    async def receive():
        return {"type": "http.disconnect"}

    async def send(message):
        if message["type"] == failure_message:
            raise OSError("client disconnected")

    async def serve():
        response = DownloadResponse(reader, chunks())
        with pytest.raises(ClientDisconnect):
            await response({"type": "http", "method": "GET", "asgi": {"spec_version": "2.4"}}, receive, send)

    anyio.run(serve)
    assert reader.fd is None
    if failure_message == "http.response.start":
        assert entered == []  # Generator cleanup alone cannot handle this case.
