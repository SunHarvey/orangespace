"""Behaviour of wsl/system (install and upgrade support). Ownership cases need root."""
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

loader = importlib.machinery.SourceFileLoader("system", str(Path(__file__).with_name("system")))
spec = importlib.util.spec_from_loader(loader.name, loader)
system = importlib.util.module_from_spec(spec)
loader.exec_module(system)

SANDBOX = "aaaaaaaa-0000-4000-8000-00000000000a"
OWNER = 332072

# Stands in for podman: `load` records the archive it was given and makes the
# desktop tag exist; `ps` lists the containers named in $FAKE_RUNNING.
FAKE_PODMAN = r"""#!/bin/sh
state="$FAKE_STATE"
case "$1" in
  image)
    if [ "$2" = inspect ]; then [ -e "$state/loaded" ] && { echo sha256:feedface; exit 0; }; exit 1; fi
    [ "$2" = prune ] && { echo prune >> "$state/calls"; exit 0; } ;;
  load) cp "$4" "$state/loaded"; echo load >> "$state/calls"; exit 0 ;;
  ps) printf '%s' "$FAKE_RUNNING"; exit 0 ;;
esac
exit 1
"""


class Sandbox(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.state = self.root / "podman-state"
        self.state.mkdir()
        fake = self.root / "podman"
        fake.write_text(FAKE_PODMAN)
        fake.chmod(0o755)
        self.enterContext(patch.object(system, "ROOT", self.root / "lib"))
        self.enterContext(patch.object(system, "PODMAN", (str(fake),)))
        self.enterContext(patch.object(system, "SPOOL", self.root))
        self.enterContext(patch.dict(os.environ, {"FAKE_STATE": str(self.state), "FAKE_RUNNING": ""}))
        # No desktop units on a test machine; only podman decides "running" here.
        self.enterContext(patch.object(system.subprocess, "run", wraps=self.no_units))

    real_run = system.subprocess.run

    def no_units(self, args, **kwargs):
        if args[0] == "systemctl":
            return system.subprocess.CompletedProcess(args, 0, "", "")
        return Sandbox.real_run(args, **kwargs)


class LoadImageTests(Sandbox):
    def test_a_matching_archive_is_loaded_and_the_spool_file_removed(self):
        data = b"oci archive bytes" * 1000
        result = system.load_image(hashlib.sha256(data).hexdigest(), io.BytesIO(data))
        self.assertEqual(result["image"], "sha256:feedface")
        self.assertEqual((self.state / "loaded").read_bytes(), data)
        self.assertEqual((self.state / "calls").read_text().split(), ["load", "prune"])
        self.assertEqual(list(self.root.glob("orangespace-image-*")), [])

    def test_a_mismatched_or_malformed_digest_never_reaches_podman(self):
        data = b"tampered"
        for digest in (hashlib.sha256(b"other").hexdigest(), "abc", "Z" * 64):
            with self.subTest(digest=digest), self.assertRaises(system.SystemError_):
                system.load_image(digest, io.BytesIO(data))
        self.assertFalse((self.state / "calls").exists())
        self.assertEqual(list(self.root.glob("orangespace-image-*")), [])

    def test_an_archive_without_the_desktop_tag_is_refused(self):
        data = b"some other image"
        with patch.object(system, "image_id", return_value=None), self.assertRaises(system.SystemError_):
            system.load_image(hashlib.sha256(data).hexdigest(), io.BytesIO(data))


@unittest.skipUnless(sys.platform == "linux" and os.geteuid() == 0, "needs root to own files as other UIDs")
class DataTests(Sandbox):
    def make_tree(self):
        home = system.ROOT / "desktop" / "instances" / SANDBOX / "home"
        (home / "Downloads").mkdir(parents=True)
        (system.ROOT / "desktop" / "locks").mkdir()
        (system.ROOT / "desktop" / "instances" / SANDBOX / "owner").write_text("user\n")
        (home / "Downloads" / "report.pdf").write_bytes(b"%PDF")
        (home / ".bashrc").write_text("# hi\n")
        (home / "latest").symlink_to("Downloads/report.pdf")
        for path in (home, home / "Downloads", home / "Downloads" / "report.pdf", home / ".bashrc"):
            os.lchown(path, OWNER, OWNER)
        os.lchown(home / "latest", OWNER, OWNER)
        home.chmod(0o700)
        (home / "Downloads" / "report.pdf").chmod(0o600)
        return home

    def snapshot(self):
        result = {}
        for path in sorted((system.ROOT / "desktop").rglob("*")):
            st = path.lstat()
            result[str(path.relative_to(system.ROOT))] = (
                st.st_uid, st.st_gid, stat.S_IMODE(st.st_mode), stat.S_IFMT(st.st_mode),
                path.read_bytes() if path.is_file() and not path.is_symlink() else os.readlink(path) if path.is_symlink() else None)
        return result

    def export(self):
        out = io.BytesIO()
        system.export_data(out)
        out.seek(0)
        return out

    def test_round_trip_keeps_contents_owners_modes_and_links(self):
        self.make_tree()
        before = self.snapshot()
        archive = self.export()
        import shutil
        shutil.rmtree(system.ROOT / "desktop")
        result = system.import_data(archive)
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(result["sandboxes"], 1)
        self.assertEqual([p.name for p in system.ROOT.iterdir()], ["desktop"])  # no staging left

    def test_export_refuses_while_a_desktop_runs(self):
        self.make_tree()
        with patch.dict(os.environ, {"FAKE_RUNNING": "0123abcd\n"}), self.assertRaises(system.SystemError_):
            self.export()

    def test_import_refuses_a_target_that_has_data(self):
        self.make_tree()
        archive = self.export()
        before = self.snapshot()
        with self.assertRaises(system.SystemError_):
            system.import_data(archive)
        self.assertEqual(self.snapshot(), before)

    def test_import_refuses_entries_outside_the_data_directory(self):
        for name in ("etc/passwd", "desktop/../../escape", "/desktop/abs"):
            with self.subTest(name=name):
                out = io.BytesIO()
                with tarfile.open(fileobj=out, mode="w") as archive:
                    info = tarfile.TarInfo(name)
                    info.size = 1
                    archive.addfile(info, io.BytesIO(b"x"))
                out.seek(0)
                with self.assertRaises((system.SystemError_, tarfile.TarError)):
                    system.import_data(out)
                self.assertFalse((system.ROOT / "desktop").exists())
                self.assertEqual(list(system.ROOT.glob(".import-*")), [])
                self.assertFalse((self.root / "escape").exists())


class CommandTests(Sandbox):
    def test_info_reports_revision_image_and_sandbox_count(self):
        revision = self.root / "REVISION"
        revision.write_text("0.1.0+abc1234\ndev-update 2026-11-21T00:00:00Z\n")
        (system.ROOT / "desktop" / "instances" / SANDBOX).mkdir(parents=True)
        with patch.object(system, "REVISION", revision):
            self.assertEqual(system.info(), {"revision": "0.1.0+abc1234", "image": None, "sandboxes": 1})


if __name__ == "__main__":
    unittest.main()
