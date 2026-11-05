import os
import time

from orangespace_node.storage import TEMP_PREFIX


def test_crash_cleanup_skips_live_uploads_and_other_files(client, tokens, config):
    user_id = client.get("/v1/me", headers=tokens["alice"]).json()["user_id"]
    storage = client.app.state.storage
    active = storage.begin_upload(user_id, "active", 64, False)
    active.write(b"still active")
    root = config.data_root / user_id
    orphan = root / (TEMP_PREFIX + "a" * 32)
    orphan.write_bytes(b"abandoned by a crashed process")
    keep = root / "keep"
    keep.write_bytes(b"ordinary user file")
    old = time.time() - 2 * 3600
    os.utime(orphan, (old, old))
    os.utime(root / active.temporary, (old, old))
    os.utime(keep, (old, old))
    try:
        assert storage.cleanup_uploads(3600) == 1
        assert not orphan.exists()
        assert (root / active.temporary).exists()
        assert keep.read_bytes() == b"ordinary user file"
        active.commit()
        assert client.get("/v1/files/active", headers=tokens["alice"]).content == b"still active"
    finally:
        active.close()
