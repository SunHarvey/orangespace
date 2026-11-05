"""Descriptor-relative personal directories; never resolve an API path against cwd.

The service account owns the whole storage tree. Other OS accounts must not be
allowed to mutate it. API users are not given SSH access as that service account.
"""
from contextlib import contextmanager
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import secrets
import stat
import threading
import time
from collections.abc import Iterator
from uuid import UUID


TEMP_PREFIX = ".orangespace-upload-"
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class StorageError(Exception):
    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail
        super().__init__(detail)


def parts(path: str, *, allow_root: bool = False) -> list[str]:
    if path == "" and allow_root:
        return []
    if not path or len(path.encode("utf-8", errors="surrogatepass")) > 4096:
        raise StorageError(400, "invalid relative path")
    items = path.split("/")
    if len(items) > 64:
        raise StorageError(400, "path is too deeply nested")
    for item in items:
        if (
            item in ("", ".", "..")
            or "\\" in item
            or any(ord(char) < 32 or ord(char) == 127 or 0xD800 <= ord(char) <= 0xDFFF for char in item)
            or item.startswith(TEMP_PREFIX)
            or len(item.encode("utf-8", errors="surrogatepass")) > 255
        ):
            raise StorageError(400, "invalid relative path")
    return items


@contextmanager
def translate_errors():
    try:
        yield
    except OSError as error:
        if error.errno in (errno.ENOENT,):
            raise StorageError(404, "file or directory not found") from error
        if error.errno in (errno.ELOOP, errno.ENOTDIR):
            raise StorageError(400, "symbolic links and non-directory parents are forbidden") from error
        if error.errno in (errno.EEXIST, errno.ENOTEMPTY, errno.EISDIR):
            raise StorageError(409, "destination exists or directory is not empty") from error
        if error.errno in (errno.ENOSPC, errno.EDQUOT):
            raise StorageError(507, "node storage is full") from error
        if error.errno in (errno.EACCES, errno.EPERM):
            raise StorageError(403, "file operation forbidden") from error
        raise StorageError(503, "node storage unavailable") from error


def file_metadata(name: str, info: os.stat_result) -> dict:
    return {
        "name": name,
        "kind": "directory" if stat.S_ISDIR(info.st_mode) else "file",
        "size": info.st_size if stat.S_ISREG(info.st_mode) else None,
        "modified_at_ns": info.st_mtime_ns,
    }


class FileReader:
    def __init__(self, fd: int):
        self.fd: int | None = fd
        self.info = os.fstat(fd)
        self.lock = threading.Lock()

    def read(self, size: int = 256 * 1024) -> bytes:
        with self.lock:
            return os.read(self.fd, size) if self.fd is not None else b""

    def close(self) -> None:
        with self.lock:
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None


class Upload:
    def __init__(self, parent_fd: int, destination: str, max_bytes: int, overwrite: bool):
        self.parent_fd: int | None = parent_fd
        self.destination = destination
        self.temporary = TEMP_PREFIX + secrets.token_hex(16)
        self.fd: int | None = None
        self.size = 0
        self.max_bytes = max_bytes
        self.overwrite = overwrite
        self.sha256 = hashlib.sha256()
        try:
            self.fd = os.open(
                self.temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=parent_fd,
            )
            # The administrator cleanup command skips uploads that still hold
            # this lock, including long-running uploads older than its cutoff.
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            self.close()
            raise

    def write(self, data: bytes) -> None:
        if self.fd is None:
            raise StorageError(409, "upload is already closed")
        if len(data) > self.max_bytes - self.size:
            raise StorageError(413, "file exceeds node upload limit")
        with translate_errors():
            view = memoryview(data)
            while view:
                written = os.write(self.fd, view)
                if written <= 0:
                    raise StorageError(503, "incomplete file write")
                view = view[written:]
        self.sha256.update(data)
        self.size += len(data)

    def commit(self) -> dict:
        if self.fd is None or self.parent_fd is None:
            raise StorageError(409, "upload is already closed")
        with translate_errors():
            os.fsync(self.fd)
            info = os.fstat(self.fd)
            if self.overwrite:
                try:
                    old = os.stat(self.destination, dir_fd=self.parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    old = None
                if old is not None and not stat.S_ISREG(old.st_mode):
                    raise StorageError(409, "only regular files may be replaced")
                # rename replaces a directory entry; it never follows the target symlink.
                os.replace(self.temporary, self.destination, src_dir_fd=self.parent_fd, dst_dir_fd=self.parent_fd)
            else:
                # Atomic create-if-absent: unlike exists()+rename(), racing uploads
                # cannot overwrite the winner's destination.
                os.link(self.temporary, self.destination, src_dir_fd=self.parent_fd, dst_dir_fd=self.parent_fd, follow_symlinks=False)
                os.unlink(self.temporary, dir_fd=self.parent_fd)
            os.fsync(self.parent_fd)
            os.close(self.fd)
            self.fd = None
        return {**file_metadata(self.destination, info), "sha256": self.sha256.hexdigest()}

    def close(self) -> None:
        # Also cleans up canceled, oversized and conflicting uploads.
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        if self.parent_fd is not None:
            try:
                os.unlink(self.temporary, dir_fd=self.parent_fd)
            except FileNotFoundError:
                pass
            finally:
                os.close(self.parent_fd)
                self.parent_fd = None


class PersonalStorage:
    def __init__(self, root: Path):
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            raise RuntimeError("personal storage requires POSIX descriptor-relative filesystem APIs")
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.root_fd = os.open(root, DIRECTORY_FLAGS)
        info = os.fstat(self.root_fd)
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            os.close(self.root_fd)
            raise RuntimeError("data root must be owned by service account with permissions 0700")

    def close(self) -> None:
        os.close(self.root_fd)

    def _user(self, user_id: str) -> int:
        # Identity comes from authentication, never from request path or JSON.
        name = str(UUID(user_id))
        with translate_errors():
            try:
                os.mkdir(name, mode=0o700, dir_fd=self.root_fd)
            except FileExistsError:
                pass
            fd = os.open(name, DIRECTORY_FLAGS, dir_fd=self.root_fd)
            info = os.fstat(fd)
            if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                os.close(fd)
                raise StorageError(503, "personal directory permissions are invalid")
            return fd

    def _directory(self, user_id: str, segments: list[str]) -> int:
        fd = self._user(user_id)
        try:
            with translate_errors():
                for segment in segments:
                    next_fd = os.open(segment, DIRECTORY_FLAGS, dir_fd=fd)
                    os.close(fd)
                    fd = next_fd
            return fd
        except BaseException:
            os.close(fd)
            raise

    def list(self, user_id: str, path: str) -> list[dict]:
        fd = self._directory(user_id, parts(path, allow_root=True))
        try:
            with translate_errors():
                entries = []
                for name in os.listdir(fd):
                    if name.startswith(TEMP_PREFIX):
                        continue
                    try:
                        info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    except FileNotFoundError:
                        continue  # Another request removed it during the listing.
                    if stat.S_ISDIR(info.st_mode) or (stat.S_ISREG(info.st_mode) and info.st_nlink == 1):
                        entries.append(file_metadata(name, info))
                return sorted(entries, key=lambda item: (item["kind"] != "directory", item["name"]))
        finally:
            os.close(fd)

    def mkdir(self, user_id: str, path: str) -> dict:
        segments = parts(path)
        fd = self._directory(user_id, segments[:-1])
        try:
            with translate_errors():
                os.mkdir(segments[-1], mode=0o700, dir_fd=fd)
                os.fsync(fd)
                return file_metadata(segments[-1], os.stat(segments[-1], dir_fd=fd, follow_symlinks=False))
        finally:
            os.close(fd)

    def begin_upload(self, user_id: str, path: str, max_bytes: int, overwrite: bool) -> Upload:
        segments = parts(path)
        fd = self._directory(user_id, segments[:-1])
        with translate_errors():
            return Upload(fd, segments[-1], max_bytes, overwrite)

    def read(self, user_id: str, path: str) -> FileReader:
        segments = parts(path)
        parent_fd = self._directory(user_id, segments[:-1])
        fd = None
        try:
            with translate_errors():
                fd = os.open(segments[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent_fd)
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise StorageError(400, "only regular files without extra hard links may be downloaded")
                reader = FileReader(fd)
                fd = None
                return reader
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent_fd)

    def delete(self, user_id: str, path: str) -> None:
        segments = parts(path)
        fd = self._directory(user_id, segments[:-1])
        try:
            with translate_errors():
                info = os.stat(segments[-1], dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    os.rmdir(segments[-1], dir_fd=fd)  # No recursive deletion.
                elif stat.S_ISREG(info.st_mode):
                    os.unlink(segments[-1], dir_fd=fd)
                else:
                    raise StorageError(400, "symbolic links and special files are forbidden")
                os.fsync(fd)
        finally:
            os.close(fd)

    def cleanup_uploads(self, minimum_age_seconds: int) -> int:
        """Remove old, unlocked staging files after a crash; never follow links."""
        if minimum_age_seconds < 3600:
            raise ValueError("cleanup age must be at least one hour")
        cutoff = time.time() - minimum_age_seconds
        removed = 0
        for user_id in os.listdir(self.root_fd):
            try:
                if str(UUID(user_id)) != user_id:
                    continue
            except ValueError:
                continue
            stack: list[list[str]] = [[]]
            while stack:
                segments = stack.pop()
                directory_fd = self._directory(user_id, segments)
                try:
                    for name in os.listdir(directory_fd):
                        try:
                            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                        except FileNotFoundError:
                            continue
                        if stat.S_ISDIR(info.st_mode) and len(segments) < 64:
                            stack.append([*segments, name])
                            continue
                        suffix = name.removeprefix(TEMP_PREFIX)
                        if not (name.startswith(TEMP_PREFIX) and len(suffix) == 32
                                and all(char in "0123456789abcdef" for char in suffix)
                                and stat.S_ISREG(info.st_mode) and info.st_mtime <= cutoff):
                            continue
                        fd = None
                        try:
                            fd = os.open(name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory_fd)
                            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            opened = os.fstat(fd)
                            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                            if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino) or opened.st_mtime > cutoff:
                                continue
                            os.unlink(name, dir_fd=directory_fd)
                            removed += 1
                        except (FileNotFoundError, BlockingIOError):
                            continue
                        finally:
                            if fd is not None:
                                os.close(fd)
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        return removed
