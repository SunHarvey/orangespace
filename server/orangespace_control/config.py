"""Secret configuration is a protected owner-only regular file, never env."""
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import stat


class ConfigError(ValueError):
    """Intentionally contains no source data."""


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate member')
        result[key] = value
    return result


@dataclass(frozen=True)
class ControlConfig:
    database_url: str = field(repr=False)
    session_ttl_seconds: int = 3600


def load_config(path: str | Path) -> ControlConfig:
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077 or info.st_nlink != 1 or info.st_size > 16384:
            raise ValueError()
        with os.fdopen(fd, 'r', encoding='utf-8') as stream:
            fd = None
            body = json.load(stream, object_pairs_hook=unique_object)
        if not isinstance(body, dict) or set(body) - {'database_url', 'session_ttl_seconds'}:
            raise ValueError()
        url = body.get('database_url')
        ttl = body.get('session_ttl_seconds', 3600)
        if not isinstance(url, str) or not url.startswith('mysql+pymysql://') or type(ttl) is not int or not 1 <= ttl <= 3600:
            raise ValueError()
        return ControlConfig(url, ttl)
    except (OSError, ValueError, TypeError):
        raise ConfigError('invalid protected control configuration') from None
    finally:
        if fd is not None:
            os.close(fd)
