from dataclasses import dataclass
import os
from pathlib import Path
from uuid import UUID


@dataclass(frozen=True)
class Settings:
    node_id: UUID
    data_root: Path
    database_url: str
    token_lifetime_seconds: int = 8 * 60 * 60
    max_upload_bytes: int = 1024 * 1024 * 1024
    login_attempts: int = 10
    login_window_seconds: int = 300

    def __post_init__(self) -> None:
        if self.max_upload_bytes <= 0 or self.token_lifetime_seconds <= 0:
            raise ValueError("upload size and token lifetime must be positive")
        if self.login_attempts <= 0 or self.login_window_seconds <= 0:
            raise ValueError("login limits must be positive")
        if not self.data_root.is_absolute():
            raise ValueError("ORANGESPACE_DATA_ROOT must be absolute")

    @classmethod
    def from_env(cls) -> "Settings":
        # A stable explicit identity prevents accidentally treating two nodes as one.
        return cls(
            node_id=UUID(os.environ["ORANGESPACE_NODE_ID"]),
            data_root=Path(os.environ.get("ORANGESPACE_DATA_ROOT", "/var/lib/orangespace/files")),
            database_url=os.environ["ORANGESPACE_DATABASE_URL"],
            token_lifetime_seconds=int(os.environ.get("ORANGESPACE_TOKEN_TTL", "28800")),
            max_upload_bytes=int(os.environ.get("ORANGESPACE_MAX_UPLOAD_BYTES", "1073741824")),
            login_attempts=int(os.environ.get("ORANGESPACE_LOGIN_ATTEMPTS", "10")),
            login_window_seconds=int(os.environ.get("ORANGESPACE_LOGIN_WINDOW", "300")),
        )
